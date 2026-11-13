//! CLI entry point — mirrors `spaghetti/cli.py`. Phase 4: full flag parity
//! (`--plan`, `rayon`-based concurrency across packages, matching Python's
//! `review_packages_concurrently` — no process-pool/agent machinery needed
//! here since Rust has no GIL to work around, per the port proposal's §4.3).

use crate::config;
use crate::models::{Issue, ScanConfig, ScanResult, Severity, display_path};
use crate::scanner::scan_package;
use clap::Parser;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "spaghetti",
    about = "Spaghetti Code Detector (Rust port)",
    version
)]
pub struct Args {
    /// Suppress the report banner (text-report mode only; --json is unaffected)
    #[arg(long, short = 'q')]
    pub quiet: bool,

    #[arg(long)]
    pub config: Option<PathBuf>,

    #[arg(long = "package", value_name = "NAME=PATH")]
    pub package_args: Vec<String>,

    #[arg(long, num_args = 0..)]
    pub packages: Option<Vec<String>>,

    #[arg(long, default_value = "info", value_parser = ["info", "warning", "error"])]
    pub severity: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value_t = config::DEFAULT_TOP_FILES)]
    pub top: usize,

    #[arg(long, num_args = 0..)]
    pub exclude: Vec<String>,

    #[arg(long, default_value_t = config::DEFAULT_MIN_DUPLICATE_LINES)]
    pub min_duplicate_lines: usize,

    #[arg(long, default_value_t = config::DEFAULT_TWIN_SIMILARITY)]
    pub twin_similarity: f64,

    #[arg(long)]
    pub plan: bool,
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "info" => 0,
        "warning" => 1,
        _ => 2,
    }
}

/// Shape of a `--config` YAML file: a top-level `packages` mapping of
/// `{name: path}`. Mirrors the Python original's `yaml.safe_load` + shape
/// check in `spaghetti/src/spaghetti/cli.py`; other top-level keys are ignored.
#[derive(serde::Deserialize)]
struct ConfigFile {
    packages: Option<BTreeMap<String, String>>,
}

fn load_packages_from_config(config_path: &Path) -> BTreeMap<String, PathBuf> {
    let text = std::fs::read_to_string(config_path).unwrap_or_else(|e| {
        panic!(
            "error: could not read --config {}: {e}",
            config_path.display()
        )
    });
    let config: ConfigFile = serde_saphyr::from_str(&text).unwrap_or_else(|e| {
        panic!(
            "error: could not parse --config {}: {e}",
            config_path.display()
        )
    });

    let packages = config.packages.unwrap_or_else(|| {
        panic!(
            "error: {} must define a top-level 'packages' mapping of {{name: path}}",
            config_path.display()
        )
    });

    let base_dir = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf())
        .parent()
        .unwrap()
        .to_path_buf();

    packages
        .into_iter()
        .map(|(name, rel)| (name, base_dir.join(rel)))
        .collect()
}

fn parse_package_args(entries: &[String], cwd: &Path) -> BTreeMap<String, PathBuf> {
    entries
        .iter()
        .map(|entry| {
            let (name, raw_path) = entry
                .split_once('=')
                .unwrap_or_else(|| panic!("error: --package expects NAME=PATH, got {entry:?}"));
            (name.trim().to_string(), cwd.join(raw_path.trim()))
        })
        .collect()
}

pub fn resolve_packages(
    config_path: Option<&Path>,
    package_args: &[String],
    defaults: &BTreeMap<String, PathBuf>,
    cwd: &Path,
) -> BTreeMap<String, PathBuf> {
    if config_path.is_none() && package_args.is_empty() {
        return defaults.clone();
    }
    let mut packages = config_path
        .map(load_packages_from_config)
        .unwrap_or_default();
    packages.extend(parse_package_args(package_args, cwd));
    packages
}

const NOISE_DIR_NAMES: &[&str] = &[
    "__pycache__",
    "node_modules",
    "build",
    "dist",
    "site-packages",
];

pub const DEFAULT_CWD_EXCLUDES: &[&str] = &[
    "/.venv/",
    "/venv/",
    "/.git/",
    "/__pycache__/",
    "/node_modules/",
    "/build/",
    "/dist/",
    ".egg-info",
    "/.mypy_cache/",
    "/.pytest_cache/",
    "/.ruff_cache/",
    "/.tox/",
    "/site-packages/",
];

fn is_noise_dir(name: &str) -> bool {
    name.starts_with('.') || NOISE_DIR_NAMES.contains(&name) || name.ends_with(".egg-info")
}

/// Auto-discover a `{name: path}` registry from `cwd` for a bare `spaghetti`
/// invocation (no --config/--package given) — mirrors
/// `cli.py::discover_cwd_packages`. This is what keeps a no-args run from
/// silently defaulting to the workspace's boti/boti-data/boti-dask registry:
/// it scans whatever's actually under the current directory instead.
///
/// Each immediate, non-noise subdirectory of `cwd` containing at least one
/// `.py` file anywhere in its subtree becomes its own named package. `.py`
/// files sitting directly in `cwd` (outside any subdirectory) are grouped
/// into one additional package named after `cwd` itself — the second return
/// value is that package's name (`None` if there were no such loose files),
/// so callers can scan it non-recursively and avoid double-scanning the
/// subdirectories already registered on their own.
pub fn discover_cwd_packages(cwd: &Path) -> (BTreeMap<String, PathBuf>, Option<String>) {
    let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(cwd)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(|e| e.file_name());

    let mut packages: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut has_loose_py = false;
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if is_noise_dir(&name) {
                continue;
            }
            let has_python = walkdir::WalkDir::new(&path)
                .into_iter()
                .filter_map(Result::ok)
                .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("py"));
            if has_python {
                packages.insert(name, path);
            }
        } else if path.extension().and_then(|x| x.to_str()) == Some("py") {
            has_loose_py = true;
        }
    }

    let loose_root_name = if has_loose_py {
        let base = cwd
            .canonicalize()
            .unwrap_or_else(|_| cwd.to_path_buf())
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| cwd.display().to_string());
        let name = if packages.contains_key(&base) {
            format!("{base} (root)")
        } else {
            base
        };
        packages.insert(name.clone(), cwd.to_path_buf());
        Some(name)
    } else {
        None
    };

    (packages, loose_root_name)
}

/// Bumped only on a breaking change to the `--json` shape; additive fields
/// keep it. The matching schema is committed in the Python repo at
/// `schema/report.v1.json` — mirrors `cli.py::JSON_SCHEMA_VERSION`.
pub const JSON_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct JsonIssue {
    file: String,
    line: usize,
    column: Option<usize>,
    end_line: Option<usize>,
    end_column: Option<usize>,
    severity: &'static str,
    rule: &'static str,
    message: String,
    package: String,
    fingerprint: String,
}

impl JsonIssue {
    fn from_issue(i: &Issue, workspace_root: Option<&Path>) -> Self {
        JsonIssue {
            file: display_path(&i.file, workspace_root),
            line: i.line,
            column: i.column,
            end_line: i.end_line,
            end_column: i.end_column,
            severity: i.severity.as_str(),
            rule: i.rule,
            message: i.message.clone(),
            package: i.package.clone(),
            fingerprint: i.fingerprint.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonIgnoredIssue {
    #[serde(flatten)]
    issue: JsonIssue,
    reason: Option<String>,
}

/// Per-package (and whole-run) stats — mirrors `cli.py::_package_json`.
#[derive(Serialize)]
struct JsonPackageStats {
    grade: &'static str,
    score: f64,
    files: usize,
    lines: usize,
    functions: usize,
    issues: usize,
    errors: usize,
    warnings: usize,
    infos: usize,
}

impl JsonPackageStats {
    fn from_result(result: &ScanResult) -> Self {
        let (score, grade) = crate::scoring::compute_score(result);
        JsonPackageStats {
            grade,
            score: round_half_even_1dp(score),
            files: result.files_scanned,
            lines: result.total_lines,
            functions: result.functions_scanned,
            issues: result.issues.len(),
            errors: result.error_count(),
            warnings: result.warning_count(),
            infos: result.info_count(),
        }
    }
}

/// Python's `round(x, 1)`: the double nearest the correctly-rounded
/// (half-to-even) one-decimal value. Rust's `{:.1}` formatting is the same
/// correctly-rounded conversion, so parsing it back yields the identical
/// double — and `serde_json` then prints the same shortest repr Python does
/// (`100.0`, `89.8`).
fn round_half_even_1dp(x: f64) -> f64 {
    format!("{x:.1}").parse().unwrap_or(x)
}

/// `{name: stats}` in scan order — serialized as a JSON object whose key
/// order is the package order, like Python's insertion-ordered dict.
struct JsonPackages(Vec<(String, JsonPackageStats)>);

impl Serialize for JsonPackages {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, stats) in &self.0 {
            map.serialize_entry(name, stats)?;
        }
        map.end()
    }
}

/// Schema v1 — mirrors `cli.py::_json_report` key for key, in order.
#[derive(Serialize)]
struct JsonOutput {
    schema_version: u32,
    summary: JsonPackageStats,
    packages: JsonPackages,
    issues: Vec<JsonIssue>,
    suppressed: usize,
    suppression_help: &'static str,
    ignored: Vec<JsonIgnoredIssue>,
}

const SUPPRESSION_HELP: &str = "Silence a confirmed non-issue by adding \
'# spaghetti-ignore[rule-name]: reason' on the flagged line (or the line above).";

/// `json.dumps(..., indent=2)` byte for byte: serde_json's pretty printer
/// already matches the indentation and separators; what it doesn't do is
/// `ensure_ascii`, so every non-ASCII character (and DEL, which Python's
/// `[^\ -~]` escape class also catches) is rewritten to `\uXXXX` — as a
/// UTF-16 surrogate pair above the BMP, lowercase hex, exactly like Python.
/// Safe to do over the whole document: outside string literals serde_json
/// only ever emits ASCII.
fn to_json_ensure_ascii<T: Serialize>(value: &T) -> String {
    let pretty = serde_json::to_string_pretty(value).expect("report is serializable");
    let mut out = String::with_capacity(pretty.len());
    for c in pretty.chars() {
        if (c as u32) < 0x7f {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

pub fn run(args: Args) -> i32 {
    let cwd = std::env::current_dir().expect("cwd");
    let workspace_root = config::find_workspace_root(&cwd);

    // A bare invocation (no --config, no --package) must never silently
    // fall back to a hardcoded workspace-specific registry — instead it
    // auto-discovers whatever's actually under the current directory.
    // --config/--package (in any combination) opt back into the explicit
    // registry-resolution path below, unchanged. There's no built-in
    // default registry to fall back to in that path either (empty
    // defaults) — a generic tool shouldn't assume it's running inside this
    // particular monorepo. Mirrors `cli.py::main`'s equivalent branch.
    let mut run_exclude = args.exclude.clone();
    let mut non_recursive: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let registry = if args.config.is_none() && args.package_args.is_empty() {
        let (discovered, loose_root_name) = discover_cwd_packages(&cwd);
        run_exclude.extend(DEFAULT_CWD_EXCLUDES.iter().map(|s| s.to_string()));
        if let Some(name) = loose_root_name {
            non_recursive.insert(name);
        }
        discovered
    } else {
        resolve_packages(
            args.config.as_deref(),
            &args.package_args,
            &BTreeMap::new(),
            &cwd,
        )
    };
    if registry.is_empty() {
        eprintln!("error: no packages to scan — the resolved package registry is empty");
        return 2;
    }

    let selected: Vec<String> = args
        .packages
        .clone()
        .unwrap_or_else(|| registry.keys().cloned().collect());
    let unknown: Vec<&String> = selected
        .iter()
        .filter(|p| !registry.contains_key(*p))
        .collect();
    if !unknown.is_empty() {
        eprintln!(
            "error: unknown package(s): {}. Available: {}",
            unknown
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            registry.keys().cloned().collect::<Vec<_>>().join(", ")
        );
        return 2;
    }

    // A resolved-but-nonexistent path (e.g. a --package NAME=PATH typo, or a
    // relative PATH resolved against the wrong cwd — the real case that
    // surfaced this, in the Python original: `--package
    // boti-dask=src/boti_dask` run from the workspace root instead of from
    // inside boti-dask/) must not be confused with "scanned and found
    // nothing wrong": scan_package() silently returns an empty ScanResult
    // for a missing path (`!root.exists()`), which without this check
    // reports a perfect A/100.0 grade — indistinguishable from a genuinely
    // clean package that actually got scanned. Same fix as the Python port.
    let missing: Vec<String> = selected
        .iter()
        .filter(|name| !registry[*name].exists())
        .map(|name| format!("{name}={}", registry[name].display()))
        .collect();
    if !missing.is_empty() {
        eprintln!(
            "error: package path(s) do not exist: {}",
            missing.join(", ")
        );
        return 2;
    }

    // Every package scanned concurrently — mirrors Python's
    // `review_packages_concurrently`, minus the `ProcessPoolExecutor`/
    // `boti.core.Agent` machinery that exists there only to get real
    // parallelism past the GIL. Rust has no GIL, so `rayon`'s thread pool is
    // the whole story.
    let scanned: Vec<(String, ScanResult)> = selected
        .par_iter()
        .map(|name| {
            let root = &registry[name];
            let config = ScanConfig {
                exclude: run_exclude.clone(),
                min_duplicate_lines: args.min_duplicate_lines,
                twin_similarity: args.twin_similarity,
                recursive: !non_recursive.contains(name),
            };
            let result = scan_package(name, root, &config);
            (name.clone(), result)
        })
        .collect();
    let per_package: BTreeMap<String, ScanResult> = scanned.into_iter().collect();

    let mut total = ScanResult::default();
    for name in &selected {
        total.extend(&per_package[name]);
    }

    let min_severity = severity_rank(&args.severity);
    let filtered: Vec<&Issue> = total
        .issues
        .iter()
        .filter(|i| severity_rank(i.severity.as_str()) >= min_severity)
        .collect();

    if args.plan {
        print!(
            "{}",
            crate::scoring::plan_report(&filtered, args.top, workspace_root.as_deref())
        );
    } else if args.json {
        let output = JsonOutput {
            schema_version: JSON_SCHEMA_VERSION,
            summary: JsonPackageStats::from_result(&total),
            packages: JsonPackages(
                selected
                    .iter()
                    .map(|name| {
                        (
                            name.clone(),
                            JsonPackageStats::from_result(&per_package[name]),
                        )
                    })
                    .collect(),
            ),
            issues: filtered
                .iter()
                .map(|i| JsonIssue::from_issue(i, workspace_root.as_deref()))
                .collect(),
            suppressed: total.suppressed,
            suppression_help: SUPPRESSION_HELP,
            ignored: total
                .ignored
                .iter()
                .map(|i| JsonIgnoredIssue {
                    issue: JsonIssue::from_issue(i, workspace_root.as_deref()),
                    reason: i.reason.clone(),
                })
                .collect(),
        };
        println!("{}", to_json_ensure_ascii(&output));
    } else {
        render_text_report(&filtered, &total, workspace_root.as_deref(), args.quiet);
    }

    if total.issues.iter().any(|i| i.severity == Severity::Error) {
        2
    } else if total.issues.iter().any(|i| i.severity == Severity::Warning) {
        1
    } else {
        0
    }
}

/// (errors, warnings, infos) — the report renders this same tally for
/// several different issue slices.
fn severity_counts(issues: &[&Issue]) -> (usize, usize, usize) {
    let errors = issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .count();
    let warnings = issues
        .iter()
        .filter(|i| i.severity == Severity::Warning)
        .count();
    let infos = issues
        .iter()
        .filter(|i| i.severity == Severity::Info)
        .count();
    (errors, warnings, infos)
}

fn render_text_report(
    filtered: &[&Issue],
    total: &ScanResult,
    workspace_root: Option<&Path>,
    quiet: bool,
) {
    if !quiet {
        println!("{}", "=".repeat(config::BANNER_WIDTH));
        println!(
            "  SPAGHETTI CODE DETECTION REPORT (v{})",
            env!("CARGO_PKG_VERSION")
        );
        println!("{}", "=".repeat(config::BANNER_WIDTH));
        println!();
    }
    println!("  Files scanned:     {}", total.files_scanned);
    println!("  Lines scanned:     {}", total.total_lines);
    println!("  Functions scanned: {}", total.functions_scanned);
    println!("  Total issues:      {}", filtered.len());
    let (errors, warnings, infos) = severity_counts(filtered);
    println!("    Errors:          {errors}");
    println!("    Warnings:        {warnings}");
    println!("    Info:            {infos}");
    if total.suppressed > 0 {
        println!(
            "  Suppressed:        {} (inline spaghetti-ignore markers)",
            total.suppressed
        );
    }
    if !filtered.is_empty() {
        println!(
            "  Silence a confirmed non-issue: add \
             '# spaghetti-ignore[rule-name]: reason' on the flagged line (or the line above)."
        );
    }
    println!();

    let (score, grade) = crate::scoring::compute_score(total);
    println!("  Overall score: {score:.1} ({grade})");
    println!();

    if !total.ignored.is_empty() {
        println!("{}", "=".repeat(config::BANNER_WIDTH));
        println!("  SPAGHETTI-IGNORED (inline spaghetti-ignore markers)");
        println!("{}", "=".repeat(config::BANNER_WIDTH));
        println!();
        let mut sorted_ignored: Vec<&Issue> = total.ignored.iter().collect();
        sorted_ignored.sort_by(|a, b| {
            display_path(&a.file, workspace_root)
                .cmp(&display_path(&b.file, workspace_root))
                .then(a.line.cmp(&b.line))
        });
        for issue in sorted_ignored {
            let icon = match issue.severity {
                Severity::Error => "✖",
                Severity::Warning => "⚠",
                Severity::Info => "ℹ",
            };
            let reason = issue.reason.as_deref().unwrap_or("no reason given");
            println!(
                "  {icon} {}:{} [{}] {reason}",
                display_path(&issue.file, workspace_root),
                issue.line,
                issue.rule
            );
        }
        println!();
    }

    for issue in filtered {
        println!(
            "  {} L{:<5} [{}] {}",
            display_path(&issue.file, workspace_root),
            issue.line,
            issue.rule,
            issue.message
        );
    }
}

#[cfg(test)]
mod discover_cwd_packages_tests {
    use super::discover_cwd_packages;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// A fresh, empty temp directory, unique per call (tests run in
    /// parallel threads within the same process, so `process::id()` alone
    /// isn't enough).
    fn temp_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "spaghetti_rs_discover_{}_{}_{}",
            std::process::id(),
            tag,
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn finds_subdirectories_with_python() {
        let cwd = temp_dir("finds_subdirs");
        std::fs::create_dir(cwd.join("alpha")).unwrap();
        std::fs::write(cwd.join("alpha/mod.py"), "x = 1\n").unwrap();
        std::fs::create_dir_all(cwd.join("beta/nested")).unwrap();
        std::fs::write(cwd.join("beta/nested/mod.py"), "x = 1\n").unwrap();

        let (packages, loose_root_name) = discover_cwd_packages(&cwd);

        std::fs::remove_dir_all(&cwd).ok();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages["alpha"], cwd.join("alpha"));
        assert_eq!(packages["beta"], cwd.join("beta"));
        assert!(loose_root_name.is_none());
    }

    #[test]
    fn skips_dirs_with_no_python() {
        let cwd = temp_dir("skips_no_python");
        std::fs::create_dir(cwd.join("docs")).unwrap();
        std::fs::write(cwd.join("docs/readme.txt"), "no python here\n").unwrap();
        std::fs::create_dir(cwd.join("alpha")).unwrap();
        std::fs::write(cwd.join("alpha/mod.py"), "x = 1\n").unwrap();

        let (packages, _) = discover_cwd_packages(&cwd);

        std::fs::remove_dir_all(&cwd).ok();
        assert_eq!(packages.len(), 1);
        assert!(packages.contains_key("alpha"));
    }

    #[test]
    fn skips_noise_directories() {
        let cwd = temp_dir("skips_noise");
        for noisy in [
            ".venv",
            "__pycache__",
            "node_modules",
            ".git",
            "build",
            "dist",
            "foo.egg-info",
        ] {
            let d = cwd.join(noisy);
            std::fs::create_dir(&d).unwrap();
            std::fs::write(d.join("mod.py"), "x = 1\n").unwrap();
        }
        std::fs::create_dir(cwd.join("alpha")).unwrap();
        std::fs::write(cwd.join("alpha/mod.py"), "x = 1\n").unwrap();

        let (packages, _) = discover_cwd_packages(&cwd);

        std::fs::remove_dir_all(&cwd).ok();
        assert_eq!(packages.len(), 1);
        assert!(packages.contains_key("alpha"));
    }

    #[test]
    fn bundles_loose_root_files() {
        let cwd = temp_dir("loose_root");
        std::fs::write(cwd.join("main.py"), "x = 1\n").unwrap();
        std::fs::create_dir(cwd.join("alpha")).unwrap();
        std::fs::write(cwd.join("alpha/mod.py"), "x = 1\n").unwrap();

        let (packages, loose_root_name) = discover_cwd_packages(&cwd);

        let expected_name = cwd
            .canonicalize()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        std::fs::remove_dir_all(&cwd).ok();
        assert_eq!(loose_root_name, Some(expected_name.clone()));
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[&expected_name], cwd);
    }

    #[test]
    fn empty_cwd_returns_empty_registry() {
        let cwd = temp_dir("empty");

        let (packages, loose_root_name) = discover_cwd_packages(&cwd);

        std::fs::remove_dir_all(&cwd).ok();
        assert!(packages.is_empty());
        assert!(loose_root_name.is_none());
    }

    #[test]
    fn does_not_special_case_boti_names() {
        // No hardcoded skip list — a directory literally named 'boti' found
        // under cwd is discovered like any other, since the guarantee is
        // "never silently default to the workspace registry", not "never
        // scan a directory that happens to be named boti".
        let cwd = temp_dir("boti_name");
        std::fs::create_dir(cwd.join("boti")).unwrap();
        std::fs::write(cwd.join("boti/mod.py"), "x = 1\n").unwrap();

        let (packages, _) = discover_cwd_packages(&cwd);

        std::fs::remove_dir_all(&cwd).ok();
        assert_eq!(packages.len(), 1);
        assert!(packages.contains_key("boti"));
    }
}
