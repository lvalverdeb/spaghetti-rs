//! Package scanning — mirrors `detector.py::scan_package`.
//!
//! The per-file pass runs on rayon's pool. Each worker finishes its own
//! file completely: the per-file checks, then rule overrides, column
//! normalisation, fingerprints and inline suppressions for that file's
//! findings (fingerprint occurrence counts are per file and rule, so a file
//! can be finalized the moment it is scanned), and the compact `FileFacts`
//! the package-level checks need. The tree and the source text are dropped
//! in the worker. The sequential tail combines facts across files, runs the
//! three package checks over them and finalizes those findings with the
//! source of just the files they name — it never re-walks a tree or
//! re-parses a file.

use crate::ast_helpers::LineIndex;
use crate::cache::{FileCache, FileEntry};
use crate::checks::ast_per_file::Check;
use crate::checks::package_level::{self, FileFacts};
use crate::checks::workspace_level::{
    PackageImports, build_import_graph, check_contracts_ws, check_duplicate_code_ws,
    check_import_cycles_ws, check_module_coupling_ws, collect_raw_imports, dependency_edges,
};
use crate::checks::{ast_per_file, text_per_file};
use crate::clones::{TokenStream, token_stream};
use crate::config::{RuleSetting, rule_overrides};
use crate::metrics::maintainability_index;
use crate::models::{Issue, ScanConfig, ScanResult, Severity};
use crate::rules::{is_enabled_by_default, is_known_rule, rule_meta};
use crate::suppression::is_suppressed;
use indexmap::IndexMap;
use rayon::prelude::*;
use regex::Regex;
use rustpython_ast::{Mod, Stmt};
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use walkdir::WalkDir;

pub fn scan_package(package: &str, root: &Path, config: &ScanConfig) -> ScanResult {
    let mut result = ScanResult::default();
    if !root.exists() {
        return result;
    }

    let cache = config
        .cache_dir
        .as_ref()
        .map(|dir| FileCache::new(dir, &config.cache_key));
    let overrides = rule_overrides();

    // Sorted, matching Python's `sorted(pkg_path.rglob("*.py"))` — the
    // package-level checks' output (`duplicate-function-body`'s first
    // location, which file a same-named `orphan-interface` is reported in)
    // depends on file order, so this can't be arbitrary directory-walk order.
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
    let files: Vec<PathBuf> = walker
        .into_iter()
        .filter_map(Result::ok)
        .map(|entry| entry.into_path())
        .filter(|path| {
            if path.extension().and_then(|e| e.to_str()) != Some("py") {
                return false;
            }
            let path_str = path.to_string_lossy();
            !path_str.contains("__pycache__")
                && !config
                    .exclude
                    .iter()
                    .any(|pat| path_str.contains(pat.as_str()))
        })
        .collect();

    // Files are independent until the package-level checks, so they are
    // scanned in parallel and folded back in sorted order — the result is
    // identical to a sequential scan.
    let scanned: Vec<FileScan> = files
        .par_iter()
        .map(|path| {
            let mut file = FileScan::default();
            scan_one_file(path, package, root, &overrides, cache.as_ref(), &mut file);
            file
        })
        .collect();
    let mut facts: Vec<(PathBuf, FileFacts)> = Vec::new();
    for (path, file) in files.iter().zip(scanned) {
        let FileScan {
            result: part,
            facts: file_facts,
        } = file;
        result.issues.extend(part.issues);
        result.files_scanned += part.files_scanned;
        result.functions_scanned += part.functions_scanned;
        result.total_lines += part.total_lines;
        result.suppressed += part.suppressed;
        result.ignored.extend(part.ignored);
        result.file_mi.extend(part.file_mi);
        result.cache_hits += part.cache_hits;
        result.cache_misses += part.cache_misses;
        result.raw_imports.extend(part.raw_imports);
        result.token_streams.extend(part.token_streams);
        if let Some(file_facts) = file_facts {
            facts.push((path.clone(), file_facts));
        }
    }

    // The package-level half: the cross-file checks over the per-file facts,
    // finalized with the source of just the files they name — mirrors
    // `detector._assemble_package`.
    let mut found = package_level::check_orphan_interfaces_pkg(package, &facts);
    found.extend(package_level::check_duplicate_functions_pkg(
        package,
        &facts,
        config.min_duplicate_lines,
    ));
    found.extend(package_level::check_sync_async_twins_pkg(
        package,
        &facts,
        config.twin_similarity,
    ));
    drop(facts);
    finalize_from_disk(found, root, &overrides, &mut result);
    result
}

/// One file's share of a package scan, before it is folded in: its
/// finalized findings and counts, plus the facts the package checks combine.
#[derive(Default)]
struct FileScan {
    result: ScanResult,
    facts: Option<FileFacts>,
}

/// A finding about the file itself (`syntax-error`, `unreadable-file`,
/// `scan-limit`), at line 1 with the catalog's severity — mirrors
/// `detector._infra_issue`.
fn infra_issue(path: &Path, package: &str, rule: &'static str, message: String) -> Issue {
    let severity = rule_meta(rule).map_or(Severity::Error, |m| m.default_severity);
    Issue::new(path, 1, severity, rule, package, message)
}

/// `OSError.strerror`: the OS message without Rust's " (os error N)".
fn strerror(e: &std::io::Error) -> String {
    let text = e.to_string();
    match text.rfind(" (os error ") {
        Some(at) if text.ends_with(')') => text[..at].to_string(),
        _ => text,
    }
}

/// `Path.read_text(encoding="utf-8", errors="replace")`: lossy UTF-8 and
/// universal newlines (`\r\n` and `\r` become `\n`).
fn read_python_text(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes);
    Ok(if text.contains('\r') {
        text.replace("\r\n", "\n").replace('\r', "\n")
    } else {
        text.into_owned()
    })
}

/// Run every per-file check on `path` and finalize its findings into
/// `file.result` — mirrors `detector._scan_one_file`.
fn scan_one_file(
    path: &Path,
    package: &str,
    root: &Path,
    overrides: &BTreeMap<String, RuleSetting>,
    cache: Option<&FileCache>,
    file: &mut FileScan,
) {
    file.result.files_scanned += 1;
    let mut issues = Vec::new();
    let source = match read_python_text(path) {
        Ok(source) => source,
        Err(e) => {
            issues.push(infra_issue(
                path,
                package,
                "unreadable-file",
                format!("Failed to read file — {}", strerror(&e)),
            ));
            finalize(issues, root, |_| None, overrides, &mut file.result);
            return;
        }
    };
    let lines = crate::pyast::py_splitlines(&source);
    file.result.total_lines += lines.len();
    scan_source(&source, path, package, root, cache, file, &mut issues);
    finalize(issues, root, |_| Some(&lines), overrides, &mut file.result);
}

/// Size limit, cache lookup, then the per-file checks (or the cached
/// result) — mirrors `detector._scan_source`.
fn scan_source(
    source: &str,
    path: &Path,
    package: &str,
    root: &Path,
    cache: Option<&FileCache>,
    file: &mut FileScan,
    issues: &mut Vec<Issue>,
) {
    let max_file_bytes = crate::config::thresholds().max_file_bytes;
    if source.len() > max_file_bytes {
        issues.push(infra_issue(
            path,
            package,
            "scan-limit",
            format!(
                "File skipped — {} bytes exceeds max-file-bytes ({max_file_bytes}); exclude it \
                 if generated, or raise the limit",
                source.len()
            ),
        ));
        return;
    }

    if let Some(cache) = cache {
        if let Some(entry) = cache.load(source, path, package) {
            file.result.cache_hits += 1;
            apply_cached(path, file, issues, entry);
            return;
        }
        file.result.cache_misses += 1;
    }

    let functions_before = file.result.functions_scanned;
    let Ok(parsed) = check_one_file(source, path, package, root, file, issues) else {
        issues.clear();
        file.result.functions_scanned = functions_before;
        file.result.file_mi.shift_remove(path);
        file.result.raw_imports.shift_remove(path);
        file.result.token_streams.shift_remove(path);
        file.facts = None;
        issues.push(infra_issue(
            path,
            package,
            "scan-limit",
            "File skipped — nesting deeper than the analysis limit; exclude it if generated"
                .to_string(),
        ));
        return;
    };
    if let Some(cache) = cache {
        cache.store(
            source,
            path,
            package,
            &FileEntry {
                issues: issues.clone(),
                parsed,
                functions: file.result.functions_scanned - functions_before,
                mi: file.result.file_mi.get(path).copied(),
                raw_imports: file.result.raw_imports.get(path).cloned(),
                tokens: file.result.token_streams.get(path).cloned(),
                facts: file.facts.clone(),
            },
        );
    }
}

/// The analysis gave up on a file nested past Python's recursion limit.
struct NestingLimit;

/// Every per-file check, uncached — mirrors `detector._check_one_file`.
/// `Ok(false)` on a syntax error.
fn check_one_file(
    source: &str,
    path: &Path,
    package: &str,
    root: &Path,
    file: &mut FileScan,
    issues: &mut Vec<Issue>,
) -> Result<bool, NestingLimit> {
    issues.extend(text_per_file::check_long_file(source, path, package));
    issues.extend(text_per_file::check_todo_markers(source, path, package));

    let path_str = path.to_string_lossy();
    let parsed = if crate::limits::cpython_rejects(source) {
        None
    } else {
        rustpython_parser::parse(source, rustpython_parser::Mode::Module, &path_str).ok()
    };
    // The parser's own message is dropped: Python reports the bare
    // "syntax error" too, so the fingerprint and message match.
    let Some(module) = parsed else {
        issues.push(infra_issue(
            path,
            package,
            "syntax-error",
            "Failed to parse file — syntax error".to_string(),
        ));
        return Ok(false);
    };
    let body: &[Stmt] = match &module {
        Mod::Module(m) => &m.body,
        _ => &[],
    };
    if crate::limits::exceeds_nesting_limit(body) {
        return Err(NestingLimit);
    }

    let result = &mut file.result;
    result.functions_scanned += ast_per_file::count_functions(&module);
    for check in ast_per_file::ALL_CHECKS {
        issues.extend(match check {
            Check::PerFile(f) => f(&module, source, path, package),
            Check::WithPkgRoot(f) => f(&module, source, path, package, root),
        });
    }
    let mi = maintainability_index(body, source);
    result.file_mi.insert(path.to_path_buf(), mi);
    issues.extend(ast_per_file::low_maintainability_issue(mi, path, package));
    let line_index = LineIndex::new(source);
    result
        .raw_imports
        .insert(path.to_path_buf(), collect_raw_imports(body, &line_index));
    result
        .token_streams
        .insert(path.to_path_buf(), token_stream(body, source, &line_index));
    file.facts = Some(package_level::collect_facts(body, source, &line_index));
    Ok(true)
}

/// Fold a cache hit into `file` — mirrors `detector._apply_cached`.
fn apply_cached(path: &Path, file: &mut FileScan, issues: &mut Vec<Issue>, entry: FileEntry) {
    issues.extend(entry.issues);
    file.result.functions_scanned += entry.functions;
    if let Some(mi) = entry.mi {
        file.result.file_mi.insert(path.to_path_buf(), mi);
    }
    if let Some(raw) = entry.raw_imports {
        file.result.raw_imports.insert(path.to_path_buf(), raw);
    }
    if let Some(tokens) = entry.tokens {
        file.result.token_streams.insert(path.to_path_buf(), tokens);
    }
    if let Some(facts) = entry.facts {
        file.facts = Some(facts);
    }
}

/// Rule overrides, character columns, fingerprints, inline suppressions —
/// in that order, for every issue — then into `result` (mirrors
/// `detector._finalize_issues`). `lines_of` gives a file's source lines, or
/// `None` for a file that could not be read: its findings are left as they
/// are, like a file that was never read.
fn finalize<'a>(
    issues: Vec<Issue>,
    root: &Path,
    mut lines_of: impl FnMut(&Path) -> Option<&'a Vec<&'a str>>,
    overrides: &BTreeMap<String, RuleSetting>,
    result: &mut ScanResult,
) {
    let mut issues = apply_rule_overrides(issues, overrides);
    for issue in &mut issues {
        normalize_columns(issue, lines_of(&issue.file));
    }
    assign_fingerprints(&mut issues, root);
    for mut issue in issues {
        let suppression = lines_of(&issue.file).and_then(|lines| is_suppressed(&issue, lines));
        match suppression {
            Some(sup) => {
                result.suppressed += 1;
                issue.reason = sup.reason;
                result.ignored.push(issue);
            }
            None => result.issues.push(issue),
        }
    }
}

/// Finalize findings that arrive after the per-file pass has let go of the
/// text, reading each named file at most once — mirrors `_finalize_issues`
/// with `_SourceLines`.
fn finalize_from_disk(
    issues: Vec<Issue>,
    root: &Path,
    overrides: &BTreeMap<String, RuleSetting>,
    result: &mut ScanResult,
) {
    if issues.is_empty() {
        return;
    }
    let mut sources: HashMap<PathBuf, Option<String>> = HashMap::new();
    for issue in &issues {
        if !sources.contains_key(&issue.file) {
            sources.insert(issue.file.clone(), read_python_text(&issue.file).ok());
        }
    }
    let lines_by_file: HashMap<&Path, Vec<&str>> = sources
        .iter()
        .filter_map(|(p, s)| Some((p.as_path(), crate::pyast::py_splitlines(s.as_deref()?))))
        .collect();
    finalize(
        issues,
        root,
        |path| lines_by_file.get(path),
        overrides,
        result,
    );
}

/// Run the checks that need every package at once — import cycles and
/// coupling over the union graph, token-based clones — and fold their
/// findings into each owning package's result, after that package's own
/// findings. Consumes the per-file transport data the workers collected.
/// Mirrors `detector.scan_workspace`.
pub fn scan_workspace(
    per_package: &mut IndexMap<String, ScanResult>,
    registry: &IndexMap<String, PathBuf>,
    config: &ScanConfig,
    workspace_root: Option<&Path>,
) {
    scan_workspace_with(
        per_package,
        registry,
        config,
        workspace_root,
        &rule_overrides(),
    );
}

fn scan_workspace_with(
    per_package: &mut IndexMap<String, ScanResult>,
    registry: &IndexMap<String, PathBuf>,
    config: &ScanConfig,
    workspace_root: Option<&Path>,
    overrides: &BTreeMap<String, RuleSetting>,
) {
    let found: Vec<Issue> = {
        let packages: Vec<PackageImports<'_>> = per_package
            .iter()
            .map(|(name, result)| PackageImports {
                name,
                root: &registry[name.as_str()],
                files: &result.raw_imports,
            })
            .collect();
        let streams: Vec<(&str, &IndexMap<PathBuf, TokenStream>)> = per_package
            .iter()
            .map(|(name, result)| (name.as_str(), &result.token_streams))
            .collect();
        let (graph, index) = build_import_graph(&packages);
        let mut found = check_import_cycles_ws(&graph, &index);
        found.extend(check_module_coupling_ws(&graph, &index));
        found.extend(check_duplicate_code_ws(
            &streams,
            config.min_clone_tokens,
            workspace_root,
        ));
        let contracts = crate::config::contracts();
        if !contracts.is_empty() {
            let (edges, index) = dependency_edges(&packages);
            found.extend(check_contracts_ws(&edges, &index, &contracts));
        }
        found
    };

    for (name, result) in per_package.iter_mut() {
        let own: Vec<Issue> = found
            .iter()
            .filter(|i| i.package == *name)
            .cloned()
            .collect();
        result.raw_imports = IndexMap::new();
        result.token_streams = IndexMap::new();
        finalize_from_disk(own, &registry[name.as_str()], overrides, result);
    }
}

/// Honour the catalog's `enabled_by_default` and `[tool.spaghetti.rules]`:
/// drop rules that ship off unless opted in, drop rules set to `off`,
/// rewrite the severity of the rest — mirrors `detector._apply_rule_overrides`.
/// Runs before fingerprinting so a severity change doesn't alter a finding's
/// identity (the fingerprint ignores severity). A rule not in the catalog
/// is never dropped silently.
fn apply_rule_overrides(
    issues: Vec<Issue>,
    overrides: &BTreeMap<String, RuleSetting>,
) -> Vec<Issue> {
    issues
        .into_iter()
        .filter_map(|mut issue| match overrides.get(issue.rule) {
            Some(RuleSetting::Off) => None,
            Some(RuleSetting::Severity(severity)) => {
                issue.severity = *severity;
                Some(issue)
            }
            None if is_known_rule(issue.rule) && !is_enabled_by_default(issue.rule) => None,
            None => Some(issue),
        })
        .collect()
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
            min_clone_tokens: 50,
            cache_dir: None,
            cache_key: String::new(),
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
mod pool_size_tests {
    //! Mirrors tests/test_detector.py::test_chunked_parallel_scan_matches_the_sequential_scan:
    //! however the files are spread over workers, the result is what one
    //! worker would produce.
    use super::scan_package;
    use crate::models::ScanConfig;

    #[test]
    fn parallel_scan_matches_the_single_threaded_scan() {
        let root = std::env::temp_dir().join(format!(
            "spaghetti_rs_scan_pool_size_{}",
            std::process::id()
        ));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let body = "import os\n\
                    class Base:\n\
                    \x20   def run(self, x):\n\
                    \x20       if x:\n\
                    \x20           return os.getcwd()\n\
                    \x20       if x is None:\n\
                    \x20           raise ValueError(x)\n\
                    \x20       for part in os.listdir('.'):\n\
                    \x20           if part.startswith('.'):\n\
                    \x20               continue\n\
                    \x20       return None\n\
                    def helper(a, b):\n\
                    \x20   return a if a else b\n\
                    def get(key):\n    value = store.read(key)\n    if value is None:\n        raise KeyError(key)\n    return decode(value)\n\
                    async def aget(key):\n    value = await store.aread(key)\n    if value is None:\n        raise KeyError(key)\n    return decode(value)\n";
        for i in 0..10 {
            std::fs::write(
                root.join(format!("m{i}.py")),
                body.replace("Base", &format!("Base{i}")),
            )
            .unwrap();
            std::fs::write(
                root.join("sub").join(format!("n{i}.py")),
                body.replace("helper", &format!("helper{i}")),
            )
            .unwrap();
        }
        std::fs::write(root.join("broken.py"), "def (:\n").unwrap();
        std::fs::write(root.join("huge.py"), "x = 1\n".repeat(400)).unwrap();
        let config = ScanConfig {
            exclude: vec![],
            min_duplicate_lines: 5,
            twin_similarity: 0.6,
            recursive: true,
            min_clone_tokens: 50,
            cache_dir: None,
            cache_key: String::new(),
        };
        let scan_with = |threads: usize| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| scan_package("big", &root, &config))
        };
        let sequential = scan_with(1);
        let parallel = scan_with(3);
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(parallel.issues, sequential.issues);
        assert_eq!(parallel.files_scanned, 22);
        assert_eq!(sequential.files_scanned, 22);
        assert_eq!(parallel.total_lines, sequential.total_lines);
        assert_eq!(parallel.functions_scanned, sequential.functions_scanned);
        assert_eq!(parallel.file_mi, sequential.file_mi);
        assert_eq!(parallel.suppressed, sequential.suppressed);
        let rules: std::collections::HashSet<&str> =
            parallel.issues.iter().map(|i| i.rule).collect();
        for rule in [
            "syntax-error",
            "duplicate-function-body",
            "sync-async-duplication",
        ] {
            assert!(rules.contains(rule), "{rule} missing from {rules:?}");
        }
        // Twins are reported per file: each of the 20 modules has its own.
        assert_eq!(
            parallel
                .issues
                .iter()
                .filter(|i| i.rule == "sync-async-duplication")
                .count(),
            20
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
            min_clone_tokens: 50,
            cache_dir: None,
            cache_key: String::new(),
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
            min_clone_tokens: 50,
            cache_dir: None,
            cache_key: String::new(),
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
        std::fs::write(
            pkg.join("m.py"),
            "# TODO: drop\ndef f() -> int:\n    return 1\n    x = 2\n",
        )
        .unwrap();
        let result = scan_package("pkg", &pkg, &config());
        std::fs::remove_dir_all(pkg.parent().unwrap()).ok();

        for rule in ["todo-marker", "dead-code"] {
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

#[cfg(test)]
mod rule_override_tests {
    // Mirrors tests/test_calibration.py's enabled_by_default plumbing tests.
    use super::apply_rule_overrides;
    use crate::config::RuleSetting;
    use crate::models::{Issue, Severity};
    use std::collections::BTreeMap;
    use std::path::Path;

    fn issue(rule: &'static str) -> Issue {
        Issue::new(
            Path::new("f.py"),
            1,
            Severity::Info,
            rule,
            "pkg",
            "m".into(),
        )
    }

    #[test]
    fn rules_off_by_default_are_dropped_unless_opted_in() {
        let issues = vec![
            issue("magic-number"),
            issue("missing-else"),
            issue("dead-code"),
        ];
        let kept: Vec<&str> = apply_rule_overrides(issues.clone(), &BTreeMap::new())
            .iter()
            .map(|i| i.rule)
            .collect();
        assert_eq!(kept, ["dead-code"]);

        let overrides = BTreeMap::from([(
            "magic-number".to_string(),
            RuleSetting::Severity(Severity::Warning),
        )]);
        let kept = apply_rule_overrides(issues, &overrides);
        let magic: Vec<&Issue> = kept.iter().filter(|i| i.rule == "magic-number").collect();
        assert!(!magic.is_empty());
        assert!(magic.iter().all(|i| i.severity == Severity::Warning));
        assert!(!kept.iter().any(|i| i.rule == "missing-else"));
    }

    #[test]
    fn apply_rule_overrides_keeps_unknown_rules() {
        // A rule not in the catalog (e.g. a future experimental one) is never
        // dropped silently.
        let kept = apply_rule_overrides(vec![issue("future-rule")], &BTreeMap::new());
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].rule, "future-rule");
    }
}

#[cfg(test)]
mod workspace_tests {
    //! Mirrors tests/test_workspace.py: cross-package cycles, coupling and
    //! clones folded into each owning package's result.
    use super::{scan_package, scan_workspace_with};
    use crate::config::RuleSetting;
    use crate::models::{ScanConfig, ScanResult};
    use indexmap::IndexMap;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    const CLONE: &str = "\ndef {name}(items, limit):\n    total = 0\n    seen = set()\n    for item in items:\n        if item in seen:\n            continue\n        seen.add(item)\n        if item.value > limit:\n            total += item.value * 2\n        else:\n            total -= 1\n    return total, len(seen)\n";

    fn clone_body(name: &str) -> String {
        CLONE.replace("{name}", name)
    }

    fn config() -> ScanConfig {
        ScanConfig {
            exclude: vec![],
            min_duplicate_lines: 5,
            twin_similarity: 0.6,
            recursive: true,
            min_clone_tokens: 30,
            cache_dir: None,
            cache_key: String::new(),
        }
    }

    struct Workspace {
        root: PathBuf,
        registry: IndexMap<String, PathBuf>,
        per_package: IndexMap<String, ScanResult>,
    }

    impl Drop for Workspace {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).ok();
        }
    }

    fn workspace(
        tag: &str,
        packages: &[(&str, &[(&str, &str)])],
        overrides: &BTreeMap<String, RuleSetting>,
    ) -> Workspace {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("spaghetti_rs_ws_{tag}_{}_{n}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        let mut registry = IndexMap::new();
        for (pkg, files) in packages {
            let dir = root.join(pkg);
            std::fs::create_dir_all(&dir).unwrap();
            for (name, src) in *files {
                std::fs::write(dir.join(name), src).unwrap();
            }
            registry.insert(pkg.to_string(), dir);
        }
        let config = config();
        let mut per_package: IndexMap<String, ScanResult> = registry
            .iter()
            .map(|(pkg, dir)| (pkg.clone(), scan_package(pkg, dir, &config)))
            .collect();
        scan_workspace_with(&mut per_package, &registry, &config, None, overrides);
        Workspace {
            root,
            registry,
            per_package,
        }
    }

    #[test]
    fn cycle_spanning_two_packages_is_reported_once() {
        let ws = workspace(
            "cycle",
            &[
                (
                    "alpha",
                    &[("__init__.py", ""), ("a.py", "from beta.b import B\n")],
                ),
                (
                    "beta",
                    &[("__init__.py", ""), ("b.py", "from alpha.a import A\n")],
                ),
            ],
            &BTreeMap::new(),
        );
        let cycles: Vec<_> = ws
            .per_package
            .values()
            .flat_map(|r| r.issues.iter())
            .filter(|i| i.rule == "import-cycle")
            .collect();
        assert_eq!(cycles.len(), 1);
        assert!(cycles[0].message.contains("alpha.a → beta.b → alpha.a"));
        assert_eq!(cycles[0].package, "alpha");
        assert!(!cycles[0].fingerprint.is_empty());
        assert_eq!(cycles[0].file, ws.registry["alpha"].join("a.py"));
    }

    #[test]
    fn clone_across_packages_reported_on_both_sides() {
        let f = clone_body("f");
        let g = clone_body("g").replace("item", "row");
        let ws = workspace(
            "clone",
            &[
                ("alpha", &[("__init__.py", ""), ("a.py", f.as_str())]),
                ("beta", &[("__init__.py", ""), ("b.py", g.as_str())]),
            ],
            &BTreeMap::new(),
        );
        let clones: Vec<_> = ws
            .per_package
            .values()
            .flat_map(|r| r.issues.iter())
            .filter(|i| i.rule == "duplicate-code")
            .collect();
        let packages: Vec<&str> = clones.iter().map(|i| i.package.as_str()).collect();
        assert_eq!(packages, ["alpha", "beta"]); // both sides are told
        assert!(
            clones[0]
                .message
                .contains("Lines 2-13 are duplicated in 1 other place(s)")
        );
        assert!(clones[0].message.contains("b.py:2-13"));
        assert!(clones[1].message.contains("a.py:2-13"));
        assert_eq!(clones[0].line, 2);
        assert_eq!(clones[0].end_line, Some(13));
    }

    #[test]
    fn workspace_findings_honour_suppressions_and_overrides() {
        let overrides = BTreeMap::from([("duplicate-code".to_string(), RuleSetting::Off)]);
        let b = format!("from alpha.a import A\n{}", clone_body("f"));
        let c = clone_body("g");
        let ws = workspace(
            "overrides",
            &[(
                "alpha",
                &[
                    ("__init__.py", ""),
                    (
                        "a.py",
                        "# spaghetti-ignore[import-cycle]: legacy\nfrom alpha.b import B\n",
                    ),
                    ("b.py", b.as_str()),
                    ("c.py", c.as_str()),
                ],
            )],
            &overrides,
        );
        let result = &ws.per_package["alpha"];
        assert!(
            result
                .issues
                .iter()
                .all(|i| i.rule != "import-cycle" && i.rule != "duplicate-code")
        );
        let ignored: Vec<&str> = result.ignored.iter().map(|i| i.rule).collect();
        assert_eq!(ignored, ["import-cycle"]);
        assert_eq!(result.suppressed, 1);
        assert!(result.raw_imports.is_empty() && result.token_streams.is_empty());
    }

    #[test]
    fn maintainability_index_is_recorded_per_file() {
        let ws = workspace(
            "mi",
            &[("alpha", &[("__init__.py", ""), ("a.py", "x = 1\n")])],
            &BTreeMap::new(),
        );
        let result = &ws.per_package["alpha"];
        let files: Vec<&PathBuf> = result.file_mi.keys().collect();
        assert_eq!(
            files,
            [
                &ws.registry["alpha"].join("__init__.py"),
                &ws.registry["alpha"].join("a.py")
            ]
        );
        assert_eq!(result.maintainability_index(), Some(100.0));
    }
}
