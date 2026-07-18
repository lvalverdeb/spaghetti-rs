//! Package scanning — mirrors `detector.py::scan_package`.
//!
//! Sequential for Phase 1-3 (proving the pipeline works); Phase 4 replaces
//! the per-package loop with `rayon` per the port proposal's §4.3/§6.
//!
//! Suppression is applied once, at the very end, over the combined
//! per-file *and* package-level issue list — matching Python's own
//! structure exactly (`scan_package` extends `result.issues` with every
//! check's output first, then runs the suppression pass once), since a
//! package-level issue (e.g. `import-cycle`) is attributed to a file that
//! isn't "the current file" in any per-file loop, so it needs the same
//! final pass everything else gets, not a per-file-immediate one.

use crate::checks::package_level::{self, ParsedFile};
use crate::checks::{ast_per_file, text_per_file};
use crate::models::{Issue, ScanResult, Severity};
use crate::suppression::is_suppressed;
use std::path::Path;
use walkdir::WalkDir;

pub fn scan_package(
    package: &str,
    root: &Path,
    exclude: &[String],
    min_duplicate_lines: usize,
    twin_similarity: f64,
) -> ScanResult {
    let mut result = ScanResult::default();
    if !root.exists() {
        return result;
    }

    let mut all_issues: Vec<Issue> = Vec::new();
    let mut source_by_file: Vec<(std::path::PathBuf, String)> = Vec::new();
    let mut parsed_files: Vec<ParsedFile> = Vec::new();

    // Sorted, matching Python's `sorted(pkg_path.rglob("*.py"))` — the
    // package-level checks' output (`sync-async-duplication`'s cross-file
    // dedup in particular, since its `reported` key doesn't include the
    // file path) depends on which file is processed first, so this can't
    // be arbitrary directory-walk order.
    for entry in WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("py") {
            continue;
        }
        let path_str = path.to_string_lossy();
        if path_str.contains("__pycache__") {
            continue;
        }
        if exclude.iter().any(|pat| path_str.contains(pat.as_str())) {
            continue;
        }

        let source = std::fs::read_to_string(path).unwrap_or_default();
        result.files_scanned += 1;
        result.total_lines += source.lines().count();

        all_issues.extend(text_per_file::check_long_file(&source, path, package));
        all_issues.extend(text_per_file::check_todo_markers(&source, path, package));

        match rustpython_parser::parse(&source, rustpython_parser::Mode::Module, &path_str) {
            Ok(module) => {
                result.functions_scanned += ast_per_file::count_functions(&module);
                for check in ast_per_file::ALL_CHECKS {
                    all_issues.extend(check(&module, &source, path, package));
                }
                for check in ast_per_file::PKG_ROOT_CHECKS {
                    all_issues.extend(check(&module, &source, path, package, root));
                }
                parsed_files.push(ParsedFile {
                    path: path.to_path_buf(),
                    source: source.clone(),
                    module,
                });
            }
            Err(e) => {
                all_issues.push(Issue {
                    file: path.to_path_buf(),
                    line: 1,
                    severity: Severity::Error,
                    rule: "syntax-error",
                    message: format!("Failed to parse file — syntax error: {e}"),
                    package: package.to_string(),
                });
            }
        }

        source_by_file.push((path.to_path_buf(), source));
    }

    all_issues.extend(package_level::check_import_cycles_pkg(
        package,
        &parsed_files,
        root,
    ));
    all_issues.extend(package_level::check_duplicate_functions_pkg(
        package,
        &parsed_files,
        min_duplicate_lines,
    ));
    all_issues.extend(package_level::check_sync_async_twins_pkg(
        package,
        &parsed_files,
        twin_similarity,
    ));

    for issue in all_issues {
        let lines: Option<Vec<&str>> = source_by_file
            .iter()
            .find(|(p, _)| p == &issue.file)
            .map(|(_, s)| s.lines().collect());
        match lines {
            Some(lines) if is_suppressed(&issue, &lines) => result.suppressed += 1,
            _ => result.issues.push(issue),
        }
    }

    result
}
