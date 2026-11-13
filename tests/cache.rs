//! Incremental cache: entries round-trip, hits skip the checks, keys
//! invalidate — mirrors the Python repo's tests/test_cache.py — plus the
//! scan limits and the `--cache` CLI surface.

use indexmap::IndexMap;
use spaghetti::cache::FileCache;
use spaghetti::models::{ScanConfig, ScanResult};
use spaghetti::scanner::{scan_package, scan_workspace};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const SOURCE: &str = "import os\n\
def f(a, b, c, d, e, f, g, h):\n    return a\n\
class K:\n    def m(self):\n        return 1\n";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn tmp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "spaghetti_rs_cache_{tag}_{}_{n}",
        std::process::id()
    ));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A package with one ordinary file and one that does not parse.
fn pkg(tmp: &Path) -> PathBuf {
    let root = tmp.join("pkg");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("m.py"), SOURCE).unwrap();
    std::fs::write(root.join("bad.py"), "def (:\n").unwrap();
    root
}

fn config(cache_dir: Option<PathBuf>, key: &str) -> ScanConfig {
    ScanConfig {
        exclude: vec![],
        min_duplicate_lines: 5,
        twin_similarity: 0.6,
        recursive: true,
        min_clone_tokens: 50,
        cache_dir,
        cache_key: key.to_string(),
    }
}

fn scan(root: &Path, config: &ScanConfig) -> ScanResult {
    let mut per: IndexMap<String, ScanResult> = IndexMap::new();
    per.insert("pkg".to_string(), scan_package("pkg", root, config));
    let registry: IndexMap<String, PathBuf> = [("pkg".to_string(), root.to_path_buf())]
        .into_iter()
        .collect();
    scan_workspace(&mut per, &registry, config, None);
    per.shift_remove("pkg").unwrap()
}

/// Everything a report shows about a finding.
fn findings(result: &ScanResult) -> Vec<String> {
    result
        .issues
        .iter()
        .map(|i| {
            format!(
                "{}|{}|{}|{:?}|{:?}|{:?}|{}|{}|{}",
                i.file.display(),
                i.line,
                i.rule,
                i.column,
                i.end_line,
                i.end_column,
                i.severity.as_str(),
                i.message,
                i.fingerprint
            )
        })
        .collect()
}

fn entries(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|it| {
            it.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "json"))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn cache_hit_reproduces_the_uncached_result_exactly() {
    let tmp = tmp_dir("hit");
    let root = pkg(&tmp);
    let plain = scan(&root, &config(None, ""));
    let cold = scan(&root, &config(Some(tmp.join("cache")), "k"));
    let warm = scan(&root, &config(Some(tmp.join("cache")), "k"));
    assert_eq!((cold.cache_hits, cold.cache_misses), (0, 2));
    assert_eq!((warm.cache_hits, warm.cache_misses), (2, 0));
    for result in [&cold, &warm] {
        assert_eq!(findings(result), findings(&plain));
        assert_eq!(result.file_mi, plain.file_mi);
        assert_eq!(result.functions_scanned, plain.functions_scanned);
        assert_eq!(result.total_lines, plain.total_lines);
    }
    assert!(!plain.issues.is_empty());
    let stored = entries(&tmp.join("cache").join("k"));
    assert_eq!(stored.len(), 2);
    let data: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&stored[0]).unwrap()).unwrap();
    assert_eq!(data["schema_version"], 1);
    for key in [
        "issues",
        "parsed",
        "functions",
        "mi",
        "raw_imports",
        "tokens",
    ] {
        assert!(data.get(key).is_some(), "{key}");
    }
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn edited_file_misses_and_changed_key_invalidates() {
    let tmp = tmp_dir("edit");
    let root = pkg(&tmp);
    scan(&root, &config(Some(tmp.join("cache")), "k"));
    std::fs::write(root.join("m.py"), format!("{SOURCE}x = 1\n")).unwrap();
    let result = scan(&root, &config(Some(tmp.join("cache")), "k"));
    assert_eq!((result.cache_hits, result.cache_misses), (1, 1));
    let result = scan(&root, &config(Some(tmp.join("cache")), "other"));
    assert_eq!((result.cache_hits, result.cache_misses), (0, 2));
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn identical_files_at_different_paths_do_not_share_an_entry() {
    // A test file is exempt from missing-type checks; a library file with
    // the same text is not. A content-only key would hand one the other's
    // findings.
    let tmp = tmp_dir("paths");
    let root = tmp.join("pkg");
    std::fs::create_dir_all(root.join("tests")).unwrap();
    let text = "def f(x):\n    return x\n";
    std::fs::write(root.join("a.py"), text).unwrap();
    std::fs::write(root.join("tests").join("test_a.py"), text).unwrap();
    let plain = scan(&root, &config(None, ""));
    let cold = scan(&root, &config(Some(tmp.join("cache")), "k"));
    let warm = scan(&root, &config(Some(tmp.join("cache")), "k"));
    assert_eq!(cold.cache_misses, 2);
    assert_eq!(findings(&cold), findings(&plain));
    assert_eq!(findings(&warm), findings(&plain));
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn corrupt_or_foreign_entries_are_misses() {
    let tmp = tmp_dir("corrupt");
    let root = pkg(&tmp);
    let cache = tmp.join("cache");
    scan(&root, &config(Some(cache.clone()), "k"));
    for entry in entries(&cache.join("k")) {
        std::fs::write(entry, "{not json").unwrap();
    }
    let result = scan(&root, &config(Some(cache.clone()), "k"));
    assert_eq!((result.cache_hits, result.cache_misses), (0, 2));
    for entry in entries(&cache.join("k")) {
        std::fs::write(entry, r#"{"schema_version": 99}"#).unwrap();
    }
    assert_eq!(scan(&root, &config(Some(cache), "k")).cache_hits, 0);
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn unwritable_cache_dir_is_silent() {
    let tmp = tmp_dir("unwritable");
    let root = pkg(&tmp);
    let blocker = tmp.join("cache");
    std::fs::write(&blocker, "not a directory").unwrap();
    let result = scan(&root, &config(Some(blocker.clone()), "k"));
    assert_eq!((result.cache_hits, result.cache_misses), (0, 2));
    assert!(
        FileCache::new(&blocker, "k")
            .load(SOURCE, &root.join("m.py"), "pkg")
            .is_none()
    );
    std::fs::remove_dir_all(&tmp).ok();
}

fn run_cli(cwd: &Path, args: &[&str]) -> (serde_json::Value, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_spaghetti"))
        .args(["--no-pyproject", "--fail-on", "never", "--json", "--quiet"])
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("failed to run spaghetti binary");
    let report = serde_json::from_slice(&output.stdout).expect("a JSON report");
    (report, String::from_utf8_lossy(&output.stderr).into_owned())
}

#[test]
fn scan_limits_emit_an_info_finding_and_skip_the_file() {
    let tmp = tmp_dir("limits");
    let root = tmp.join("pkg");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("big.py"), "x = 1\n".repeat(2000)).unwrap();
    std::fs::write(
        root.join("deep.py"),
        format!("x = a{}\n", ".b".repeat(3000)),
    )
    .unwrap();
    std::fs::write(
        tmp.join("settings.yaml"),
        "thresholds:\n  max-file-bytes: 7000\n",
    )
    .unwrap();
    let (report, _) = run_cli(&tmp, &["--config", "settings.yaml", "--package", "pkg=pkg"]);
    let issues = report["issues"].as_array().unwrap();
    assert_eq!(issues.len(), 2, "{issues:?}");
    let by_file = |name: &str| {
        issues
            .iter()
            .find(|i| i["file"].as_str().unwrap().ends_with(name))
            .unwrap()
            .clone()
    };
    for issue in issues {
        assert_eq!(issue["rule"], "scan-limit");
        assert_eq!(issue["severity"], "info");
    }
    assert!(
        by_file("big.py")["message"]
            .as_str()
            .unwrap()
            .contains("12000 bytes exceeds max-file-bytes (7000)")
    );
    assert!(
        by_file("deep.py")["message"]
            .as_str()
            .unwrap()
            .contains("nesting deeper")
    );
    assert_eq!(report["summary"]["files"], 2);
    assert_eq!(report["summary"]["lines"], 2001);
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn cache_flags_report_hits_and_misses_on_stderr() {
    let tmp = tmp_dir("cli");
    pkg(&tmp);
    let (cold, stderr) = run_cli(&tmp, &["--cache-dir", "store", "--package", "pkg=pkg"]);
    assert!(
        stderr.contains("Cache: 0 hit(s), 2 miss(es) in store/"),
        "{stderr}"
    );
    let (warm, stderr) = run_cli(&tmp, &["--cache-dir", "store", "--package", "pkg=pkg"]);
    assert!(
        stderr.contains("Cache: 2 hit(s), 0 miss(es) in store/"),
        "{stderr}"
    );
    assert_eq!(cold["issues"], warm["issues"]);
    // --cache uses .spaghetti/cache under the cwd.
    let (_, stderr) = run_cli(&tmp, &["--cache", "--package", "pkg=pkg"]);
    assert!(
        stderr.contains("Cache: 0 hit(s), 2 miss(es) in "),
        "{stderr}"
    );
    assert!(tmp.join(".spaghetti").join("cache").is_dir());
    // `cache = true` in the settings turns it on; --no-cache overrides that.
    std::fs::write(tmp.join("on.yaml"), "cache: true\ncache-dir: kept\n").unwrap();
    let (_, stderr) = run_cli(&tmp, &["--config", "on.yaml", "--package", "pkg=pkg"]);
    assert!(stderr.contains("2 miss(es) in "), "{stderr}");
    assert!(tmp.join("kept").is_dir());
    let (_, stderr) = run_cli(
        &tmp,
        &["--config", "on.yaml", "--no-cache", "--package", "pkg=pkg"],
    );
    assert!(!stderr.contains("Cache:"), "{stderr}");
    std::fs::remove_dir_all(&tmp).ok();
}
