//! Package scanning — mirrors `detector.py::scan_package`.
//!
//! Sequential for Phase 1-3 (proving the pipeline works); Phase 4 replaces
//! the per-package loop with `rayon` per the port proposal's §4.3/§6.
//!
//! Column normalization, fingerprinting and suppression are each applied
//! once, at the very end, over the combined per-file *and* package-level
//! issue list — matching Python's own structure exactly (`scan_package`
//! extends `result.issues` with every check's output first, then runs
//! `_normalize_columns`, `_assign_fingerprints` and `_apply_suppressions`
//! in that order), since a package-level issue (e.g. `import-cycle`) is
//! attributed to a file that isn't "the current file" in any per-file loop,
//! so it needs the same final passes everything else gets.

use crate::checks::ast_per_file::Check;
use crate::checks::package_level::{self, ParsedFile};
use crate::checks::{ast_per_file, text_per_file};
use crate::models::{Issue, ScanConfig, ScanResult, Severity};
use crate::suppression::is_suppressed;
use regex::Regex;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use walkdir::WalkDir;

pub fn scan_package(package: &str, root: &Path, config: &ScanConfig) -> ScanResult {
    let mut result = ScanResult::default();
    if !root.exists() {
        return result;
    }

    let mut all_issues: Vec<Issue> = Vec::new();
    let mut source_by_file: HashMap<PathBuf, String> = HashMap::new();
    let mut parsed_files: Vec<ParsedFile> = Vec::new();

    // Sorted, matching Python's `sorted(pkg_path.rglob("*.py"))` — the
    // package-level checks' output (`sync-async-duplication`'s cross-file
    // dedup in particular, since its `reported` key doesn't include the
    // file path) depends on which file is processed first, so this can't
    // be arbitrary directory-walk order.
    //
    // `recursive=false` caps depth at 1 (root's direct children only) —
    // used for the synthetic "loose root scripts" package cwd
    // auto-discovery produces alongside real subpackages (mirrors
    // `scan_package(..., recursive=False)` in the Python port), so its own
    // directory's already-registered subdirectories aren't double-scanned.
    let walker = WalkDir::new(root).sort_by_file_name();
    let walker = if config.recursive {
        walker
    } else {
        walker.max_depth(1)
    };
    for entry in walker.into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("py") {
            continue;
        }
        let path_str = path.to_string_lossy();
        if path_str.contains("__pycache__") {
            continue;
        }
        if config
            .exclude
            .iter()
            .any(|pat| path_str.contains(pat.as_str()))
        {
            continue;
        }

        result.files_scanned += 1;
        // Read bytes and decode lossily so invalid UTF-8 reaches the parser
        // and surfaces as `syntax-error`, matching Python's
        // `read_text(errors="replace")`. Only a genuine I/O failure (broken
        // symlink, permission denied, ...) becomes `unreadable-file`.
        let source = match std::fs::read(path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => {
                all_issues.push(Issue::new(
                    path,
                    1,
                    Severity::Error,
                    "unreadable-file",
                    package,
                    format!("Failed to read file — {e}"),
                ));
                continue;
            }
        };
        result.total_lines += source.lines().count();

        all_issues.extend(text_per_file::check_long_file(&source, path, package));
        all_issues.extend(text_per_file::check_todo_markers(&source, path, package));

        match rustpython_parser::parse(&source, rustpython_parser::Mode::Module, &path_str) {
            Ok(module) => {
                result.functions_scanned += ast_per_file::count_functions(&module);
                for check in ast_per_file::ALL_CHECKS {
                    all_issues.extend(match check {
                        Check::PerFile(f) => f(&module, &source, path, package),
                        Check::WithPkgRoot(f) => f(&module, &source, path, package, root),
                    });
                }
                parsed_files.push(ParsedFile {
                    path: path.to_path_buf(),
                    source: source.clone(),
                    module,
                });
            }
            Err(e) => {
                all_issues.push(Issue::new(
                    path,
                    1,
                    Severity::Error,
                    "syntax-error",
                    package,
                    format!("Failed to parse file — syntax error: {e}"),
                ));
            }
        }

        source_by_file.insert(path.to_path_buf(), source);
    }

    all_issues.extend(package_level::check_import_cycles_pkg(
        package,
        &parsed_files,
        root,
    ));
    all_issues.extend(package_level::check_module_coupling_pkg(
        package,
        &parsed_files,
        root,
    ));
    all_issues.extend(package_level::check_duplicate_functions_pkg(
        package,
        &parsed_files,
        config.min_duplicate_lines,
    ));
    all_issues.extend(package_level::check_sync_async_twins_pkg(
        package,
        &parsed_files,
        config.twin_similarity,
    ));

    let lines_by_file: HashMap<&Path, Vec<&str>> = source_by_file
        .iter()
        .map(|(p, s)| (p.as_path(), s.lines().collect()))
        .collect();

    for issue in &mut all_issues {
        normalize_columns(issue, lines_by_file.get(issue.file.as_path()));
    }
    assign_fingerprints(&mut all_issues, root);

    for mut issue in all_issues {
        let suppression = lines_by_file
            .get(issue.file.as_path())
            .and_then(|lines| is_suppressed(&issue, lines));
        match suppression {
            Some(sup) => {
                result.suppressed += 1;
                issue.reason = sup.reason;
                result.ignored.push(issue);
            }
            None => result.issues.push(issue),
        }
    }

    result
}

/// Convert a 0-based UTF-8 byte offset (what the parser reports) into a
/// 1-based character column (what editors and SARIF expect) — mirrors
/// `detector._char_column`: `len(line.encode()[:byte_offset].decode(
/// "utf-8", errors="replace")) + 1`.
fn char_column(line_text: &str, byte_offset: usize) -> usize {
    let bytes = line_text.as_bytes();
    let head = &bytes[..byte_offset.min(bytes.len())];
    String::from_utf8_lossy(head).chars().count() + 1
}

/// Checks record raw byte columns; rewrite them to character columns —
/// mirrors `detector._normalize_columns`.
fn normalize_columns(issue: &mut Issue, lines: Option<&Vec<&str>>) {
    let Some(lines) = lines else {
        return;
    };
    if let Some(column) = issue.column
        && issue.line > 0
        && issue.line <= lines.len()
    {
        issue.column = Some(char_column(lines[issue.line - 1], column - 1));
    }
    if let (Some(end_column), Some(end_line)) = (issue.end_column, issue.end_line)
        && end_line > 0
        && end_line <= lines.len()
    {
        issue.end_column = Some(char_column(lines[end_line - 1], end_column - 1));
    }
}

/// Python's `\d` on a `str` pattern matches any Unicode decimal digit
/// (category Nd); the regex crate's Unicode-mode `\d` is the same class.
static DIGITS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d+").unwrap());

/// Stable identity for a finding across line shifts and re-runs — mirrors
/// `detector._assign_fingerprints`.
///
/// Hashes rule + package-relative path + message with digits stripped (so
/// "is 65 lines" and "is 66 lines" stay the same finding). Identical keys
/// within one run are disambiguated by order of appearance so a baseline
/// can hold two genuinely separate occurrences.
fn assign_fingerprints(issues: &mut [Issue], pkg_root: &Path) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for issue in issues {
        let rel = match issue.file.strip_prefix(pkg_root) {
            Ok(rel) => rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/"),
            Err(_) => issue
                .file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        };
        let key = format!(
            "{}\0{rel}\0{}",
            issue.rule,
            DIGITS_RE.replace_all(&issue.message, "")
        );
        let n = seen.entry(key.clone()).or_insert(0);
        let digest = Sha1::digest(format!("{key}\0{n}").as_bytes());
        *n += 1;
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        issue.fingerprint = hex[..16].to_string();
    }
}

#[cfg(test)]
mod recursive_flag_tests {
    use super::scan_package;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn non_recursive_ignores_subdirectories() {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "spaghetti_rs_scan_non_recursive_{}_{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(
            root.join("loose.py"),
            "def f():\n    try:\n        pass\n    except:\n        pass\n",
        )
        .unwrap();
        std::fs::write(
            root.join("sub/mod.py"),
            "def g():\n    try:\n        pass\n    except:\n        pass\n",
        )
        .unwrap();

        let config = crate::models::ScanConfig {
            exclude: vec![],
            min_duplicate_lines: 5,
            twin_similarity: 0.6,
            recursive: false,
        };
        let result = scan_package("root", &root, &config);

        std::fs::remove_dir_all(&root).ok();
        assert_eq!(result.files_scanned, 1);
        assert!(
            result
                .issues
                .iter()
                .filter(|i| i.rule == "bare-except")
                .all(|i| i.file == root.join("loose.py"))
        );
    }
}

#[cfg(test)]
mod unreadable_file_tests {
    use super::scan_package;
    use crate::models::{ScanConfig, Severity};

    fn config() -> ScanConfig {
        ScanConfig {
            exclude: vec![],
            min_duplicate_lines: 5,
            twin_similarity: 0.6,
            recursive: true,
        }
    }

    fn fresh_root(tag: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("spaghetti_rs_scan_{tag}_{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[cfg(unix)]
    #[test]
    fn broken_symlink_is_reported_not_swallowed() {
        // Regression: `read_to_string(..).unwrap_or_default()` used to treat
        // an unreadable file as empty, counting it as scanned with no
        // finding — indistinguishable from a genuinely clean file.
        let root = fresh_root("broken_symlink");
        std::fs::write(root.join("ok.py"), "X = 1\n").unwrap();
        std::os::unix::fs::symlink(root.join("does-not-exist.py"), root.join("dangling.py"))
            .unwrap();

        let result = scan_package("pkg", &root, &config());
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(result.files_scanned, 2);
        let unreadable: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.rule == "unreadable-file")
            .collect();
        assert_eq!(unreadable.len(), 1);
        assert_eq!(unreadable[0].file, root.join("dangling.py"));
        assert_eq!(unreadable[0].severity, Severity::Error);
        assert_eq!(unreadable[0].line, 1);
    }

    #[test]
    fn invalid_utf8_is_a_syntax_error_like_python() {
        let root = fresh_root("invalid_utf8");
        std::fs::write(root.join("latin.py"), b"\xff\xfe\x00garbage\n").unwrap();

        let result = scan_package("pkg", &root, &config());
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(result.files_scanned, 1);
        assert!(result.issues.iter().any(|i| i.rule == "syntax-error"));
        assert!(result.issues.iter().all(|i| i.rule != "unreadable-file"));
    }
}

#[cfg(test)]
mod location_and_fingerprint_tests {
    use super::{char_column, scan_package};
    use crate::models::ScanConfig;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn config() -> ScanConfig {
        ScanConfig {
            exclude: vec![],
            min_duplicate_lines: 5,
            twin_similarity: 0.6,
            recursive: true,
        }
    }

    fn fresh_pkg(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "spaghetti_rs_scan_{tag}_{}_{n}",
            std::process::id()
        ));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(root.join("pkg")).unwrap();
        root.join("pkg")
    }

    #[test]
    fn char_column_counts_characters_not_bytes() {
        // `é` is two bytes; byte offset 3 ("é ") is character column 3.
        assert_eq!(char_column("é = 1", 0), 1);
        assert_eq!(char_column("é = 1", 2), 2);
        assert_eq!(char_column("é = 1", 3), 3);
        // Past the end of the line clamps rather than panics.
        assert_eq!(char_column("ab", 10), 3);
    }

    #[test]
    fn columns_are_one_based_character_columns_with_exclusive_end() {
        // Mirrors the Python fixture: a two-byte `é` before the flagged
        // `def` must not shift its columns.
        let pkg = fresh_pkg("columns");
        std::fs::write(pkg.join("m.py"), "é = 1\ndef f(x):\n    return x\n").unwrap();
        let result = scan_package("pkg", &pkg, &config());
        std::fs::remove_dir_all(pkg.parent().unwrap()).ok();

        let issue = result
            .issues
            .iter()
            .find(|i| i.rule == "missing-return-type")
            .expect("missing-return-type is reported");
        assert_eq!(issue.line, 2);
        assert_eq!(issue.column, Some(1));
        assert_eq!(issue.end_line, Some(3));
        assert_eq!(issue.end_column, Some(13));
        assert_eq!(issue.fingerprint.len(), 16);
    }

    #[test]
    fn unlocated_rules_leave_columns_none() {
        let pkg = fresh_pkg("unlocated");
        std::fs::write(pkg.join("m.py"), "import os  # TODO: drop\n").unwrap();
        let result = scan_package("pkg", &pkg, &config());
        std::fs::remove_dir_all(pkg.parent().unwrap()).ok();

        for rule in ["todo-marker", "unused-import"] {
            let issue = result
                .issues
                .iter()
                .find(|i| i.rule == rule)
                .unwrap_or_else(|| panic!("{rule} is reported"));
            assert_eq!(issue.column, None, "{rule}");
            assert_eq!(issue.end_line, None, "{rule}");
            assert_eq!(issue.end_column, None, "{rule}");
            assert_eq!(issue.fingerprint.len(), 16, "{rule}");
        }
    }

    #[test]
    fn fingerprints_are_stable_across_line_shifts_and_distinct_per_occurrence() {
        // Mirrors tests/test_detector.py::
        // test_fingerprints_are_stable_across_line_shifts_and_distinct_per_occurrence
        let pkg = fresh_pkg("fingerprints");
        let body = "def f(x):\n    return x\n\ndef g(x):\n    return x\n";
        std::fs::write(pkg.join("m.py"), body).unwrap();
        let first: HashMap<String, String> = scan_package("pkg", &pkg, &config())
            .issues
            .into_iter()
            .map(|i| (i.message, i.fingerprint))
            .collect();

        std::fs::write(pkg.join("m.py"), format!("# shifted down\n\n{body}")).unwrap();
        let second: HashMap<String, String> = scan_package("pkg", &pkg, &config())
            .issues
            .into_iter()
            .map(|i| (i.message, i.fingerprint))
            .collect();
        std::fs::remove_dir_all(pkg.parent().unwrap()).ok();

        assert!(!first.is_empty());
        assert_eq!(first, second);
        let distinct: std::collections::HashSet<&String> = first.values().collect();
        assert_eq!(distinct.len(), first.len());
        assert!(first.values().all(|fp| fp.len() == 16));
    }

    #[test]
    fn fingerprint_matches_python_reference_value() {
        // sha1("missing-return-type\0m.py\0f() missing return type annotation\0" + "0")[:16]
        // as computed by the Python original for the fixture above.
        let pkg = fresh_pkg("reference");
        std::fs::write(pkg.join("m.py"), "def f(x):\n    return x\n").unwrap();
        let result = scan_package("pkg", &pkg, &config());
        std::fs::remove_dir_all(pkg.parent().unwrap()).ok();
        let issue = result
            .issues
            .iter()
            .find(|i| i.rule == "missing-return-type")
            .unwrap();
        assert_eq!(issue.fingerprint, "87723ab8afbf36e7");
    }
}
