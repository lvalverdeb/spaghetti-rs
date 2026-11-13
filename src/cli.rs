//! CLI entry point — mirrors `spaghetti/cli.py`: flag parity, settings from
//! `pyproject.toml`/`--config`, baseline and changed-lines gating, the
//! `--fail-on` exit-code policy, and text/JSON/SARIF output. Packages scan
//! concurrently on `rayon` (Python needs a process pool to get past the GIL;
//! Rust doesn't, per the port proposal's §4.3).

use crate::baseline::{self, BaselineEntry};
use crate::churn::{Hotspot, churn_factor, file_churn, rank_hotspots};
use crate::config;
use crate::diff_filter;
use crate::json::dumps_pretty;
use crate::models::{Issue, ScanConfig, ScanResult, Severity, display_path};
use crate::sarif;
use crate::scanner::{scan_package, scan_workspace};
use crate::scoring::file_penalties;
use crate::settings::{self, Settings, SettingsError, resolve_lenient};
use crate::snapshots::{
    Comparison, Snapshot, append_snapshot, compare, find_snapshot, git_head_sha, load_snapshots,
    take_snapshot,
};
use clap::Parser;
use indexmap::IndexMap;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "spaghetti",
    about = "Spaghetti Code Detector (Rust port)",
    version,
    after_help = "Subcommand: 'spaghetti mcp' serves the scan, plan, explain_rule, compare and \
                  baseline tools over the Model Context Protocol (stdio) for coding agents."
)]
pub struct Args {
    /// Suppress the report banner (text-report mode only; --json is unaffected)
    #[arg(long, short = 'q')]
    pub quiet: bool,

    /// YAML settings file; its 'packages: {name: path}' mapping replaces the
    /// pyproject one. Paths resolve relative to the config file.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Add or override one package as NAME=PATH (repeatable). Applied on top
    /// of --config/pyproject; PATH resolves relative to the current directory.
    #[arg(long = "package", value_name = "NAME=PATH")]
    pub package_args: Vec<String>,

    /// Names to scan from the resolved registry (default: all)
    #[arg(long, num_args = 0..)]
    pub packages: Option<Vec<String>>,

    /// Minimum severity to display (default: info)
    #[arg(long, default_value = "info", value_parser = ["info", "warning", "error"])]
    pub severity: String,

    /// Report format (default: text). 'sarif' emits SARIF 2.1.0 for code-scanning tools;
    /// 'html' a self-contained page with scorecard, trend, hotspots and findings.
    #[arg(long, value_parser = ["text", "json", "sarif", "html"])]
    pub format: Option<String>,

    /// Shorthand for --format json
    #[arg(long)]
    pub json: bool,

    /// Lowest severity that makes the exit code non-zero (default: warning,
    /// i.e. exit 2 on errors, 1 on warnings). 'never' always exits 0.
    #[arg(long, value_parser = ["error", "warning", "info", "never"])]
    pub fail_on: Option<String>,

    /// Baseline file of accepted findings (by fingerprint). Findings in it are
    /// hidden and don't affect the exit code. Can also be set in [tool.spaghetti].
    #[arg(long, value_name = "PATH")]
    pub baseline: Option<PathBuf>,

    /// Write every current finding to the baseline file and exit 0
    #[arg(long)]
    pub update_baseline: bool,

    /// Report only findings on lines added or modified since git REF (e.g.
    /// origin/main). Requires the scanned paths to be inside a git repo.
    #[arg(long, value_name = "REF")]
    pub diff_base: Option<String>,

    /// Append this run (git SHA, scores, per-file penalties, finding fingerprints) to
    /// the snapshot store so later runs can --compare against it and draw trends
    #[arg(long)]
    pub snapshot: bool,

    /// JSONL snapshot store (default: .spaghetti/snapshots.jsonl, or [tool.spaghetti] snapshot-store)
    #[arg(long, value_name = "PATH")]
    pub snapshot_store: Option<PathBuf>,

    /// Report the delta against a stored snapshot: 'latest', '~N' (N runs back), a git
    /// SHA prefix or a timestamp prefix. Shows score change, findings introduced and
    /// fixed, files that got worse.
    #[arg(long, value_name = "REF")]
    pub compare: Option<String>,

    /// Rank files by health penalty × git change frequency (CodeScene-style hotspots)
    /// and weight the --plan by it. Needs the scanned paths inside a git repository.
    #[arg(long)]
    pub hotspots: bool,

    /// History window for --hotspots (default: 6 months)
    #[arg(long, value_name = "N", allow_negative_numbers = true)]
    pub churn_months: Option<i64>,

    /// Reuse per-file results for files whose content and configuration have not
    /// changed (store: .spaghetti/cache, or --cache-dir / [tool.spaghetti] cache-dir)
    #[arg(long)]
    pub cache: bool,

    /// Ignore `cache = true` from the settings for this run
    #[arg(long)]
    pub no_cache: bool,

    /// Where --cache stores its entries (implies --cache)
    #[arg(long, value_name = "PATH")]
    pub cache_dir: Option<PathBuf>,

    /// Ignore any [tool.spaghetti] table found in a pyproject.toml above the cwd
    #[arg(long)]
    pub no_pyproject: bool,

    /// Number of worst files to list
    #[arg(long, default_value_t = config::DEFAULT_TOP_FILES)]
    pub top: usize,

    /// Path substrings to exclude from scanning (default: none)
    #[arg(long, num_args = 0..)]
    pub exclude: Vec<String>,

    /// Minimum function length to consider for duplicate-body detection
    #[arg(long, default_value_t = config::DEFAULT_MIN_DUPLICATE_LINES)]
    pub min_duplicate_lines: usize,

    /// Minimum text-similarity ratio (0-1) to flag a sync/async twin pair
    #[arg(long, default_value_t = config::DEFAULT_TWIN_SIMILARITY)]
    pub twin_similarity: f64,

    /// Output a prioritized remediation plan instead of the standard report
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

/// `{name: path}` in insertion order — a Python dict, so the scan order and
/// every per-package listing follow the order packages were registered.
pub type Registry = IndexMap<String, PathBuf>;

/// Shape of a `--config` YAML file's `packages:` mapping, as the pre-settings
/// `resolve_packages` API still reads it; `run()` goes through `settings`
/// instead, which validates the whole file.
#[derive(serde::Deserialize)]
struct ConfigFile {
    /// Order-preserving (serde_json's `preserve_order`), like the Python dict.
    packages: Option<serde_json::Map<String, serde_json::Value>>,
}

fn load_packages_from_config(config_path: &Path) -> Registry {
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
        .map(|(name, rel)| {
            let rel = rel.as_str().unwrap_or_else(|| {
                panic!(
                    "error: {} must define a top-level 'packages' mapping of {{name: path}}",
                    config_path.display()
                )
            });
            (name, base_dir.join(rel))
        })
        .collect()
}

fn parse_package_args(entries: &[String], cwd: &Path) -> Result<Registry, String> {
    let mut resolved = Registry::new();
    for entry in entries {
        let (name, raw_path) = entry
            .split_once('=')
            .map(|(n, p)| (n.trim(), p.trim()))
            .filter(|(n, p)| !n.is_empty() && !p.is_empty())
            .ok_or_else(|| format!("--package expects NAME=PATH, got {entry:?}"))?;
        resolved.insert(name.to_string(), resolve_lenient(&cwd.join(raw_path)));
    }
    Ok(resolved)
}

/// Build the effective `{name: path}` package registry for one run —
/// mirrors `cli.py::resolve_packages`.
pub fn resolve_packages(
    config_path: Option<&Path>,
    package_args: &[String],
    defaults: &Registry,
    cwd: &Path,
) -> Result<Registry, String> {
    if config_path.is_none() && package_args.is_empty() {
        return Ok(defaults.clone());
    }
    let mut packages = config_path
        .map(load_packages_from_config)
        .unwrap_or_default();
    packages.extend(parse_package_args(package_args, cwd)?);
    Ok(packages)
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
/// silently defaulting to a hardcoded registry: it scans whatever's actually
/// under the current directory instead.
///
/// Each immediate, non-noise subdirectory of `cwd` containing at least one
/// `.py` file anywhere in its subtree becomes its own named package. `.py`
/// files sitting directly in `cwd` (outside any subdirectory) are grouped
/// into one additional package named after `cwd` itself — the second return
/// value is that package's name (`None` if there were no such loose files),
/// so callers can scan it non-recursively and avoid double-scanning the
/// subdirectories already registered on their own.
pub fn discover_cwd_packages(cwd: &Path) -> (Registry, Option<String>) {
    let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(cwd)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(|e| e.file_name());

    let mut packages = Registry::new();
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
    /// Mean SEI/Radon Maintainability Index over parsed files (2.0); `null`
    /// when no file parsed.
    maintainability_index: Option<f64>,
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
            maintainability_index: result.maintainability_index().map(round_half_even_1dp),
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

/// `_Gating.json()["diff_base"]`.
#[derive(Serialize)]
struct JsonDiffBase {
    #[serde(rename = "ref")]
    base_ref: String,
    hidden: usize,
}

/// One entry of `_Gating.json()["baseline"]["fixed"]`.
#[derive(Serialize)]
struct JsonFixed<'a> {
    fingerprint: &'a str,
    rule: &'a str,
    file: &'a str,
    message: &'a str,
}

/// `_Gating.json()["baseline"]`.
#[derive(Serialize)]
struct JsonBaseline<'a> {
    path: String,
    known: usize,
    fixed: Vec<JsonFixed<'a>>,
}

/// Schema v1 — mirrors `cli.py::_json_report` key for key, in order, plus the
/// additive `diff_base`/`baseline` objects `_Gating.json()` appends.
#[derive(Serialize)]
struct JsonOutput<'a> {
    schema_version: u32,
    summary: JsonPackageStats,
    packages: JsonPackages,
    issues: Vec<JsonIssue>,
    suppressed: usize,
    suppression_help: &'static str,
    ignored: Vec<JsonIgnoredIssue>,
    diff_base: Option<JsonDiffBase>,
    baseline: Option<JsonBaseline<'a>>,
    /// `_History.json()` — present only when comparing.
    #[serde(skip_serializing_if = "Option::is_none")]
    compare: Option<crate::snapshots::ComparisonJson<'a>>,
    /// `_History.json()` — present only with `--hotspots`.
    #[serde(skip_serializing_if = "Option::is_none")]
    hotspots: Option<JsonHotspots<'a>>,
    /// `_plan_json` — present only with `--plan --json`.
    #[serde(skip_serializing_if = "Option::is_none")]
    plan: Option<Vec<JsonPlanStep>>,
}

#[derive(Serialize)]
struct JsonHotspot<'a> {
    file: &'a str,
    penalty: f64,
    commits: usize,
    authors: usize,
    score: f64,
}

#[derive(Serialize)]
struct JsonHotspots<'a> {
    months: i64,
    files: Vec<JsonHotspot<'a>>,
}

/// One step of `cli.py::_plan_json`.
#[derive(Serialize)]
struct JsonPlanStep {
    priority: &'static str,
    rule: &'static str,
    severity: &'static str,
    effort: &'static str,
    count: usize,
    score: f64,
    files: Vec<String>,
    description: String,
    fix: Option<&'static str>,
}

/// Phase 3 context: the snapshot store, the comparison and the hotspots,
/// each optional, all surfaced in every output format — mirrors
/// `cli.py::_History`.
struct History {
    store: PathBuf,
    snapshots: Vec<Snapshot>,
    current: Option<Snapshot>,
    /// Whether `current` was appended to `snapshots` (`--snapshot`).
    appended: bool,
    comparison: Option<Comparison>,
    hotspots: Option<Vec<Hotspot>>,
    /// Issue file -> churn factor (absent: 1.0).
    weights: HashMap<PathBuf, f64>,
    months: i64,
}

impl History {
    fn notes(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(comparison) = &self.comparison {
            out.extend(comparison.notes());
        }
        if let Some(spots) = &self.hotspots {
            out.push(format!(
                "Hotspots: {} file(s) with findings ranked by penalty \u{d7} change frequency \
                 over {} months; --plan is churn-weighted",
                spots.len(),
                self.months
            ));
        }
        out
    }

    fn weight(&self, path: &Path) -> f64 {
        self.weights.get(path).copied().unwrap_or(1.0)
    }

    fn json_hotspots(&self) -> Option<JsonHotspots<'_>> {
        self.hotspots.as_ref().map(|spots| JsonHotspots {
            months: self.months,
            files: spots
                .iter()
                .map(|h| JsonHotspot {
                    file: &h.file,
                    penalty: h.penalty,
                    commits: h.commits,
                    authors: h.authors,
                    score: h.score,
                })
                .collect(),
        })
    }

    /// Stored snapshots other than the current run — the trend history.
    fn past(&self) -> Vec<&Snapshot> {
        let n = self.snapshots.len() - usize::from(self.appended);
        self.snapshots[..n].iter().collect()
    }
}

/// `None` when the cache is off: it is opt-in by flag or by `cache = true` —
/// mirrors `_resolve_cache_dir`.
fn resolve_cache_dir(args: &Args, settings: &Settings, cwd: &Path) -> Option<PathBuf> {
    if let Some(dir) = &args.cache_dir {
        return Some(dir.clone());
    }
    let enabled = args.cache || (settings.cache == Some(true) && !args.no_cache);
    if !enabled {
        return None;
    }
    Some(
        settings
            .cache_dir
            .clone()
            .unwrap_or_else(|| cwd.join(crate::cache::DEFAULT_CACHE_DIR)),
    )
}

fn resolve_store(args: &Args, settings: &Settings, cwd: &Path) -> PathBuf {
    args.snapshot_store
        .clone()
        .or_else(|| settings.snapshot_store.clone())
        .unwrap_or_else(|| cwd.join(crate::snapshots::DEFAULT_STORE))
}

/// Everything `build_history` needs from the run.
struct RunContext<'a> {
    args: &'a Args,
    cwd: &'a Path,
    workspace_root: Option<&'a Path>,
    registry: &'a Registry,
    selected: &'a [String],
    per_package: &'a IndexMap<String, ScanResult>,
    total: &'a ScanResult,
}

/// Take, store and compare snapshots; compute hotspots. Each only when asked
/// — mirrors `cli.py::_build_history`. `Err` is a usage error.
fn build_history(ctx: &RunContext<'_>, settings: &Settings) -> Result<History, String> {
    let args = ctx.args;
    let mut history = History {
        store: resolve_store(args, settings, ctx.cwd),
        snapshots: Vec::new(),
        current: None,
        appended: false,
        comparison: None,
        hotspots: None,
        weights: HashMap::new(),
        months: 0,
    };
    if args.snapshot || args.compare.is_some() || output_format(args) == "html" {
        take_and_compare(ctx, &mut history)?;
    }
    if args.hotspots {
        compute_hotspots(ctx, &mut history)?;
    }
    Ok(history)
}

fn take_and_compare(ctx: &RunContext<'_>, history: &mut History) -> Result<(), String> {
    history.snapshots = load_snapshots(&history.store).map_err(|e| e.to_string())?;
    let current = take_snapshot(
        ctx.per_package,
        ctx.total,
        env!("CARGO_PKG_VERSION"),
        git_head_sha(ctx.cwd),
        crate::snapshots::utc_now_iso(),
        ctx.workspace_root,
    );
    if let Some(reference) = &ctx.args.compare {
        let against = find_snapshot(&history.snapshots, reference).map_err(|e| e.to_string())?;
        history.comparison = Some(compare(
            against,
            &current,
            &ctx.total.issues,
            ctx.workspace_root,
        ));
    }
    if ctx.args.snapshot {
        append_snapshot(&history.store, &current)
            .map_err(|e| format!("{}: {e}", history.store.display()))?;
        eprintln!(
            "Snapshot {} appended to {}",
            current.label(),
            history.store.display()
        );
        history.snapshots.push(current.clone());
        history.appended = true;
    }
    history.current = Some(current);
    Ok(())
}

fn compute_hotspots(ctx: &RunContext<'_>, history: &mut History) -> Result<(), String> {
    history.months = match ctx.args.churn_months {
        Some(n) if n != 0 => n,
        _ => config::thresholds().hotspot_window_months as i64,
    };
    let roots: Vec<PathBuf> = ctx
        .selected
        .iter()
        .map(|name| ctx.registry[name.as_str()].clone())
        .collect();
    let churn = file_churn(&roots, history.months).map_err(|e| format!("--hotspots: {e}"))?;
    let penalties = file_penalties(&ctx.total.issues);
    let mut resolved: IndexMap<PathBuf, f64> = IndexMap::new();
    let mut display: HashMap<PathBuf, String> = HashMap::new();
    let mut resolved_of: HashMap<&PathBuf, PathBuf> = HashMap::new();
    for (path, penalty) in &penalties {
        let real = resolve_lenient(path);
        resolved.insert(real.clone(), *penalty);
        display.insert(real.clone(), display_path(path, ctx.workspace_root));
        resolved_of.insert(path, real);
    }
    history.hotspots = Some(rank_hotspots(&resolved, &churn, &display));
    let max_commits = churn.values().map(|c| c.commits).max().unwrap_or(0);
    for (path, real) in resolved_of {
        if let Some(c) = churn.get(&real) {
            history
                .weights
                .insert(path.clone(), churn_factor(Some(c), max_commits));
        }
    }
    Ok(())
}

fn render_hotspots(history: &History, top: usize) {
    let Some(spots) = &history.hotspots else {
        return;
    };
    println!("{}", "=".repeat(config::BANNER_WIDTH));
    println!(
        "  HOTSPOTS \u{2014} health penalty \u{d7} change frequency (last {} months)",
        history.months
    );
    println!("{}", "=".repeat(config::BANNER_WIDTH));
    println!();
    if spots.is_empty() {
        println!("  No file with findings was touched in the window.");
        println!();
        return;
    }
    println!(
        "  {:<58} {:>5} {:>4} {:>4} {:>6}",
        "File", "Pen", "Cmt", "Auth", "Hot"
    );
    println!(
        "  {} {} {} {} {}",
        "\u{2500}".repeat(58),
        "\u{2500}".repeat(5),
        "\u{2500}".repeat(4),
        "\u{2500}".repeat(4),
        "\u{2500}".repeat(6)
    );
    for h in spots.iter().take(top) {
        let chars: Vec<char> = h.file.chars().collect();
        let name = if chars.len() <= 58 {
            h.file.clone()
        } else {
            format!(
                "\u{2026}{}",
                chars[chars.len() - 57..].iter().collect::<String>()
            )
        };
        println!(
            "  {name:<58} {:>5.1} {:>4} {:>4} {:>6.1}",
            h.penalty, h.commits, h.authors, h.score
        );
    }
    println!();
}

const SUPPRESSION_HELP: &str = "Silence a confirmed non-issue by adding \
'# spaghetti-ignore[rule-name]: reason' on the flagged line (or the line above).";

/// What the run hid from the report and why — surfaced in every format.
/// Mirrors `cli.py::_Gating`.
#[derive(Default)]
struct Gating {
    diff_base: Option<String>,
    diff_hidden: usize,
    baseline_path: Option<PathBuf>,
    baseline_used: bool,
    known: Vec<Issue>,
    fixed: Vec<BaselineEntry>,
}

impl Gating {
    fn notes(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(base) = &self.diff_base {
            out.push(format!(
                "Changed lines only (vs {base}): {} finding(s) outside the diff hidden",
                self.diff_hidden
            ));
        }
        if self.baseline_used {
            out.push(format!(
                "Baseline {}: {} known finding(s) hidden, {} fixed since the baseline was written",
                self.baseline_path
                    .as_deref()
                    .unwrap_or(Path::new(""))
                    .display(),
                self.known.len(),
                self.fixed.len()
            ));
        }
        out
    }

    fn json_diff_base(&self) -> Option<JsonDiffBase> {
        self.diff_base.as_ref().map(|base| JsonDiffBase {
            base_ref: base.clone(),
            hidden: self.diff_hidden,
        })
    }

    fn json_baseline(&self) -> Option<JsonBaseline<'_>> {
        self.baseline_used.then(|| JsonBaseline {
            path: self
                .baseline_path
                .as_deref()
                .unwrap_or(Path::new(""))
                .display()
                .to_string(),
            known: self.known.len(),
            fixed: self
                .fixed
                .iter()
                .map(|e| JsonFixed {
                    fingerprint: &e.fingerprint,
                    rule: &e.rule,
                    file: &e.file,
                    message: &e.message,
                })
                .collect(),
        })
    }
}

const DEFAULT_FAIL_ON: &str = "warning";

// Process exit codes: the worst issue severity that trips the --fail-on
// policy, or 0 if the run was clean.
const EXIT_CLEAN: i32 = 0;
const EXIT_WARNING: i32 = 1;
const EXIT_ERROR: i32 = 2;
/// Usage/configuration errors — what argparse's `parser.error` exits with.
const EXIT_USAGE: i32 = 2;

/// Worst severity among `issues` at or above `fail_on` decides the code:
/// errors → 2, anything else that trips the policy → 1, clean → 0 —
/// mirrors `cli.py::_exit_code`.
fn exit_code(issues: &[Issue], fail_on: &str) -> i32 {
    if fail_on == "never" {
        return EXIT_CLEAN;
    }
    let threshold = severity_rank(fail_on);
    let tripping: Vec<&Issue> = issues
        .iter()
        .filter(|i| severity_rank(i.severity.as_str()) >= threshold)
        .collect();
    if tripping.is_empty() {
        EXIT_CLEAN
    } else if tripping.iter().any(|i| i.severity == Severity::Error) {
        EXIT_ERROR
    } else {
        EXIT_WARNING
    }
}

/// `parser.error(...)`: message on stderr, exit 2, nothing on stdout.
fn usage_error(message: &str) -> i32 {
    eprintln!("error: {message}");
    EXIT_USAGE
}

fn load_run_settings(args: &Args, cwd: &Path) -> Result<Settings, SettingsError> {
    let pyproject = if args.no_pyproject {
        None
    } else {
        settings::find_pyproject(cwd)?
    };
    settings::load_settings(pyproject.as_deref(), args.config.as_deref())
}

/// The output format: `--format` wins, then `--json`, then text.
fn output_format(args: &Args) -> &str {
    match &args.format {
        Some(fmt) => fmt.as_str(),
        None if args.json => "json",
        None => "text",
    }
}

/// Populate the registry from the CLI flags, settings or cwd discovery, and
/// return it with the effective exclude list plus the names to scan
/// non-recursively — mirrors `cli.py::_resolve_registry`.
fn resolve_registry(
    args: &Args,
    settings: &Settings,
    cwd: &Path,
) -> Result<(Registry, Vec<String>, BTreeSet<String>), String> {
    // A bare invocation (no --config, no --package, no configured packages)
    // must never silently fall back to a hardcoded registry — instead it
    // auto-discovers whatever's actually under the current directory.
    let mut run_exclude: Vec<String> = settings.exclude.clone();
    run_exclude.extend(args.exclude.iter().cloned());
    let mut non_recursive = BTreeSet::new();
    let registry =
        if args.config.is_none() && args.package_args.is_empty() && settings.packages.is_empty() {
            let (discovered, loose_root_name) = discover_cwd_packages(cwd);
            run_exclude.extend(DEFAULT_CWD_EXCLUDES.iter().map(|s| s.to_string()));
            if let Some(name) = loose_root_name {
                non_recursive.insert(name);
            }
            discovered
        } else {
            // `settings.packages` already reflects --config's `packages:` (which
            // replaces any pyproject mapping), so only --package overlays remain.
            resolve_packages(None, &args.package_args, &settings.packages, cwd)?
        };
    if registry.is_empty() {
        return Err("no packages to scan — the resolved package registry is empty".to_string());
    }
    Ok((registry, run_exclude, non_recursive))
}

pub fn run(args: Args) -> i32 {
    let cwd = std::env::current_dir().expect("cwd");
    let workspace_root = config::find_workspace_root(&cwd);

    let settings = match load_run_settings(&args, &cwd) {
        Ok(settings) => settings,
        Err(e) => return usage_error(&e.to_string()),
    };
    settings::apply_settings(&settings);

    let (registry, run_exclude, non_recursive) = match resolve_registry(&args, &settings, &cwd) {
        Ok(resolved) => resolved,
        Err(message) => return usage_error(&message),
    };

    let selected: Vec<String> = args
        .packages
        .clone()
        .unwrap_or_else(|| registry.keys().cloned().collect());
    let unknown: Vec<&str> = selected
        .iter()
        .map(String::as_str)
        .filter(|p| !registry.contains_key(*p))
        .collect();
    if !unknown.is_empty() {
        let mut available: Vec<&str> = registry.keys().map(String::as_str).collect();
        available.sort_unstable();
        return usage_error(&format!(
            "unknown package(s): {}. Available: {}",
            unknown.join(", "),
            available.join(", ")
        ));
    }

    // A resolved-but-nonexistent path (e.g. a --package NAME=PATH typo, or a
    // relative PATH resolved against the wrong cwd) must not be confused
    // with "scanned and found nothing wrong": scan_package() silently
    // returns an empty ScanResult for a missing path, which without this
    // check reports a perfect A/100.0 grade — indistinguishable from a
    // genuinely clean package that actually got scanned.
    let missing: Vec<String> = selected
        .iter()
        .filter(|name| !registry[name.as_str()].exists())
        .map(|name| format!("{name}={}", registry[name.as_str()].display()))
        .collect();
    if !missing.is_empty() {
        return usage_error(&format!(
            "package path(s) do not exist: {}",
            missing.join(", ")
        ));
    }

    // Every package scanned concurrently — mirrors Python's
    // `review_packages_concurrently`, minus the `ProcessPoolExecutor`
    // machinery that exists there only to get real parallelism past the GIL.
    // Rust has no GIL, so `rayon`'s thread pool is the whole story; the
    // settings installed above are process-global, so every worker sees them.
    let cache_dir = resolve_cache_dir(&args, &settings, &cwd);
    let base_config = ScanConfig {
        exclude: run_exclude.clone(),
        min_duplicate_lines: args.min_duplicate_lines,
        twin_similarity: args.twin_similarity,
        recursive: true,
        min_clone_tokens: config::thresholds().min_clone_tokens,
        cache_key: match &cache_dir {
            Some(_) => crate::cache::cache_key(
                &crate::cache::overrides_json(&settings),
                env!("CARGO_PKG_VERSION"),
            ),
            None => String::new(),
        },
        cache_dir: cache_dir.clone(),
    };
    let scanned: Vec<(String, ScanResult)> = selected
        .par_iter()
        .map(|name| {
            let root = &registry[name.as_str()];
            let config = ScanConfig {
                recursive: !non_recursive.contains(name),
                ..base_config.clone()
            };
            let result = scan_package(name, root, &config);
            (name.clone(), result)
        })
        .collect();
    let mut per_package: IndexMap<String, ScanResult> = scanned.into_iter().collect();
    // Import cycles, coupling and clones run once over every package, so a
    // cycle or clone that spans two packages is found.
    scan_workspace(
        &mut per_package,
        &registry,
        &base_config,
        workspace_root.as_deref(),
    );

    let mut total = ScanResult::default();
    for name in &selected {
        total.extend(&per_package[name.as_str()]);
    }
    if let Some(dir) = &cache_dir {
        eprintln!(
            "Cache: {} hit(s), {} miss(es) in {}",
            total.cache_hits,
            total.cache_misses,
            dir.join(&base_config.cache_key).display()
        );
    }

    // ── Gating: baseline, then changed lines ────────────────────────────────
    let mut gating = Gating::default();
    let mut gated: Vec<Issue> = total.issues.clone();
    let baseline_path = args.baseline.clone().or_else(|| settings.baseline.clone());
    match baseline_path {
        None if args.update_baseline => {
            return usage_error("--update-baseline needs --baseline PATH or a 'baseline' setting");
        }
        None => {}
        Some(path) => {
            gating.baseline_path = Some(path.clone());
            if args.update_baseline {
                if let Err(e) = baseline::save_baseline(
                    &path,
                    &total.issues,
                    &format!("spaghetti {}", env!("CARGO_PKG_VERSION")),
                    workspace_root.as_deref(),
                ) {
                    return usage_error(&format!(
                        "{}: cannot write baseline — {e}",
                        path.display()
                    ));
                }
                eprintln!(
                    "Wrote {} finding(s) to {}",
                    total.issues.len(),
                    path.display()
                );
                return EXIT_CLEAN;
            }
            let known = match baseline::load_baseline(&path) {
                Ok(known) => known,
                Err(e) => return usage_error(&e.to_string()),
            };
            if path.exists() {
                let split = baseline::split_against_baseline(gated, &known);
                gating.baseline_used = true;
                gating.known = split.known;
                gating.fixed = split.fixed;
                gated = split.new;
            }
        }
    }
    if let Some(base_ref) = &args.diff_base {
        let changed = match diff_filter::changed_lines(base_ref, &cwd) {
            Ok(changed) => changed,
            Err(e) => return usage_error(&format!("--diff-base: {e}")),
        };
        let split = diff_filter::restrict_to_changed(gated, &changed);
        gating.diff_base = Some(base_ref.clone());
        gating.diff_hidden = split.hidden;
        gated = split.kept;
    }

    let min_severity = severity_rank(&args.severity);
    let filtered: Vec<&Issue> = gated
        .iter()
        .filter(|i| severity_rank(i.severity.as_str()) >= min_severity)
        .collect();

    let ctx = RunContext {
        args: &args,
        cwd: &cwd,
        workspace_root: workspace_root.as_deref(),
        registry: &registry,
        selected: &selected,
        per_package: &per_package,
        total: &total,
    };
    let history = match build_history(&ctx, &settings) {
        Ok(history) => history,
        Err(message) => return usage_error(&message),
    };
    emit_report(&ctx, &filtered, &gating, &history);

    let fail_on = args
        .fail_on
        .as_deref()
        .or(settings.fail_on.as_deref())
        .unwrap_or(DEFAULT_FAIL_ON);
    exit_code(&gated, fail_on)
}

/// Mirrors `cli.py::_emit_report`.
fn emit_report(ctx: &RunContext<'_>, filtered: &[&Issue], gating: &Gating, history: &History) {
    let args = ctx.args;
    let workspace_root = ctx.workspace_root;
    let total = ctx.total;
    let fmt = output_format(args);
    let mut notes = gating.notes();
    notes.extend(history.notes());
    let weight = |path: &Path| history.weight(path);
    if args.plan && fmt != "json" {
        let note = history.hotspots.as_ref().map(|_| {
            format!(
                "Weighted by git change frequency over the last {} months",
                history.months
            )
        });
        print!(
            "{}",
            crate::scoring::plan_report(
                filtered,
                args.top,
                workspace_root,
                Some(&weight),
                note.as_deref()
            )
        );
    } else {
        match fmt {
            "json" => {
                let plan = args.plan.then(|| {
                    crate::scoring::build_remediation_plan(filtered, workspace_root, Some(&weight))
                        .into_iter()
                        .take(args.top)
                        .map(|step| JsonPlanStep {
                            priority: step.priority,
                            rule: step.rule,
                            severity: step.severity.as_str(),
                            effort: step.effort,
                            count: step.count,
                            score: step.score,
                            files: step.files,
                            description: step.description,
                            fix: crate::rule_docs::rule_doc(step.rule).map(|d| d.fix),
                        })
                        .collect()
                });
                let output = JsonOutput {
                    schema_version: JSON_SCHEMA_VERSION,
                    summary: JsonPackageStats::from_result(total),
                    packages: JsonPackages(
                        ctx.selected
                            .iter()
                            .map(|name| {
                                (
                                    name.clone(),
                                    JsonPackageStats::from_result(&ctx.per_package[name.as_str()]),
                                )
                            })
                            .collect(),
                    ),
                    issues: filtered
                        .iter()
                        .map(|i| JsonIssue::from_issue(i, workspace_root))
                        .collect(),
                    suppressed: total.suppressed,
                    suppression_help: SUPPRESSION_HELP,
                    ignored: total
                        .ignored
                        .iter()
                        .map(|i| JsonIgnoredIssue {
                            issue: JsonIssue::from_issue(i, workspace_root),
                            reason: i.reason.clone(),
                        })
                        .collect(),
                    diff_base: gating.json_diff_base(),
                    baseline: gating.json_baseline(),
                    compare: history.comparison.as_ref().map(Comparison::to_json),
                    hotspots: history.json_hotspots(),
                    plan,
                };
                println!("{}", dumps_pretty(&output));
            }
            "html" => {
                let current = history.current.as_ref();
                let past = history.past();
                print!(
                    "{}",
                    crate::html_report::build_html(&crate::html_report::HtmlInput {
                        packages: ctx.selected,
                        per_package: ctx.per_package,
                        total,
                        issues: filtered,
                        tool_version: env!("CARGO_PKG_VERSION"),
                        sha: current.and_then(|c| c.sha.as_deref()),
                        generated_at: current.map_or("", |c| c.timestamp.as_str()),
                        notes: &notes,
                        history: &past,
                        comparison: history.comparison.as_ref(),
                        hotspots: history.hotspots.as_deref(),
                        hotspot_months: history.months,
                        top: args.top,
                        workspace_root,
                    })
                );
            }
            "sarif" => {
                let document = sarif::build_sarif(
                    filtered,
                    &gating.known,
                    &total.ignored,
                    env!("CARGO_PKG_VERSION"),
                    ctx.cwd,
                    gating.baseline_used,
                );
                println!("{}", dumps_pretty(&document));
            }
            _ => {
                render_text_report(filtered, total, workspace_root, args.quiet, &notes);
                render_hotspots(history, args.top);
            }
        }
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
    notes: &[String],
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
    for note in notes {
        println!("  {note}");
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

    #[test]
    fn registry_keeps_insertion_order_like_a_python_dict() {
        let cwd = temp_dir("order");
        for name in ["zeta", "alpha"] {
            std::fs::create_dir(cwd.join(name)).unwrap();
            std::fs::write(cwd.join(name).join("mod.py"), "x = 1\n").unwrap();
        }
        std::fs::write(cwd.join("main.py"), "x = 1\n").unwrap();
        let (packages, loose) = discover_cwd_packages(&cwd);
        std::fs::remove_dir_all(&cwd).ok();
        // Sorted subdirectories first, the loose-root package appended last
        // (a BTreeMap would have slotted it alphabetically between them).
        let names: Vec<&String> = packages.keys().collect();
        assert_eq!(names[0], "alpha");
        assert_eq!(names[1], "zeta");
        assert_eq!(Some(names[2]), loose.as_ref());
    }
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
