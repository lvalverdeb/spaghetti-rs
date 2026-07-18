//! CLI entry point — mirrors `spaghetti/cli.py`. Phase 4: full flag parity
//! (`--plan`, `rayon`-based concurrency across packages, matching Python's
//! `review_packages_concurrently` — no process-pool/agent machinery needed
//! here since Rust has no GIL to work around, per the port proposal's §4.3).

use crate::config;
use crate::models::{Issue, ScanResult, display_path};
use crate::scanner::scan_package;
use clap::Parser;
use rayon::prelude::*;
use serde::Serialize;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "spaghetti", about = "Spaghetti Code Detector (Rust port)")]
pub struct Args {
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

    #[arg(long, default_value_t = 5)]
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

fn load_packages_from_config(config_path: &Path) -> BTreeMap<String, PathBuf> {
    let text = std::fs::read_to_string(config_path).unwrap_or_else(|e| {
        panic!(
            "error: could not read --config {}: {e}",
            config_path.display()
        )
    });
    let raw: YamlValue = serde_yaml::from_str(&text).unwrap_or_else(|e| {
        panic!(
            "error: could not parse --config {}: {e}",
            config_path.display()
        )
    });

    let packages = raw
        .get("packages")
        .and_then(|p| p.as_mapping())
        .unwrap_or_else(|| {
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
        .iter()
        .map(|(k, v)| {
            let name = k.as_str().unwrap_or_default().to_string();
            let rel = v.as_str().unwrap_or_default();
            (name, base_dir.join(rel))
        })
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

#[derive(Serialize)]
struct JsonIssue {
    file: String,
    line: usize,
    severity: &'static str,
    rule: &'static str,
    message: String,
    package: String,
}

#[derive(Serialize)]
struct JsonOutput {
    issues: Vec<JsonIssue>,
    suppressed: usize,
}

pub fn run(args: Args) -> i32 {
    let cwd = std::env::current_dir().expect("cwd");
    let workspace_root = config::find_workspace_root(&cwd);
    let defaults = config::default_packages(workspace_root.as_deref());

    let registry = resolve_packages(args.config.as_deref(), &args.package_args, &defaults, &cwd);
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

    // Every package scanned concurrently — mirrors Python's
    // `review_packages_concurrently`, minus the `ProcessPoolExecutor`/
    // `boti.core.Agent` machinery that exists there only to get real
    // parallelism past the GIL. Rust has no GIL, so `rayon`'s thread pool is
    // the whole story.
    let scanned: Vec<(String, ScanResult)> = selected
        .par_iter()
        .map(|name| {
            let root = &registry[name];
            let result = scan_package(
                name,
                root,
                &args.exclude,
                args.min_duplicate_lines,
                args.twin_similarity,
            );
            (name.clone(), result)
        })
        .collect();
    let mut per_package: BTreeMap<String, ScanResult> = scanned.into_iter().collect();

    let mut total = ScanResult::default();
    for name in &selected {
        total.extend(std::mem::take(per_package.get_mut(name).unwrap()));
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
            issues: filtered
                .iter()
                .map(|i| JsonIssue {
                    file: display_path(&i.file, workspace_root.as_deref()),
                    line: i.line,
                    severity: i.severity.as_str(),
                    rule: i.rule,
                    message: i.message.clone(),
                    package: i.package.clone(),
                })
                .collect(),
            suppressed: total.suppressed,
        };
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        render_text_report(&filtered, &total, workspace_root.as_deref());
    }

    if total.issues.iter().any(|i| i.severity.as_str() == "error") {
        2
    } else if total
        .issues
        .iter()
        .any(|i| i.severity.as_str() == "warning")
    {
        1
    } else {
        0
    }
}

fn render_text_report(filtered: &[&Issue], total: &ScanResult, workspace_root: Option<&Path>) {
    println!("{}", "=".repeat(72));
    println!("  SPAGHETTI CODE DETECTION REPORT (Rust port, Phase 1)");
    println!("{}", "=".repeat(72));
    println!();
    println!("  Files scanned:     {}", total.files_scanned);
    println!("  Lines scanned:     {}", total.total_lines);
    println!("  Functions scanned: {}", total.functions_scanned);
    println!("  Total issues:      {}", filtered.len());
    println!(
        "    Errors:          {}",
        filtered
            .iter()
            .filter(|i| i.severity.as_str() == "error")
            .count()
    );
    println!(
        "    Warnings:        {}",
        filtered
            .iter()
            .filter(|i| i.severity.as_str() == "warning")
            .count()
    );
    println!(
        "    Info:            {}",
        filtered
            .iter()
            .filter(|i| i.severity.as_str() == "info")
            .count()
    );
    if total.suppressed > 0 {
        println!(
            "  Suppressed:        {} (inline spaghetti-ignore markers)",
            total.suppressed
        );
    }
    println!();

    let (score, grade) = crate::scoring::compute_score(total);
    println!("  Overall score: {score:.1} ({grade})");
    println!();

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
