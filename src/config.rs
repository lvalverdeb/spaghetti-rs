//! Package-wide configuration: workspace root, thresholds, package registry —
//! mirrors `spaghetti/config.py`.

use regex::Regex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Walk upward from `start` for the `pyproject.toml` declaring the uv
/// workspace. Returns `None` rather than erroring when no such ancestor
/// exists — mirrors `config.py::_find_workspace_root`'s tolerance of
/// unreadable/malformed files along the way (§7.4 of the port proposal).
pub fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    let mut candidate = Some(start.to_path_buf());
    while let Some(dir) = candidate {
        let pyproject = dir.join("pyproject.toml");
        if pyproject.is_file()
            && let Ok(text) = std::fs::read_to_string(&pyproject)
            && let Ok(value) = text.parse::<toml::Table>()
        {
            let has_workspace = value
                .get("tool")
                .and_then(|t| t.get("uv"))
                .and_then(|uv| uv.get("workspace"))
                .is_some();
            if has_workspace {
                return Some(dir);
            }
        }
        candidate = dir.parent().map(PathBuf::from);
    }
    None
}

pub fn default_packages(workspace_root: Option<&Path>) -> BTreeMap<String, PathBuf> {
    let Some(root) = workspace_root else {
        return BTreeMap::new();
    };
    [
        ("boti", "boti/src/boti"),
        ("boti-data", "boti-data/src/boti_data"),
        ("boti-dask", "boti-dask/src/boti_dask"),
        ("spaghetti", "spaghetti/src/spaghetti"),
    ]
    .into_iter()
    .map(|(name, rel)| (name.to_string(), root.join(rel)))
    .collect()
}

/// The first allowed import prefix for `pkg` — mirrors
/// `config.py::ALLOWED_IMPORT_PREFIXES`, used by `import-cycle` to restrict
/// the intra-package import graph to the package's own dotted-module stem.
pub fn allowed_import_prefix(pkg: &str) -> Option<&'static str> {
    match pkg {
        "etl-core" => Some("etl_core."),
        "etl-demo" => Some("etl_demo."),
        "boti-data" => Some("boti_data."),
        "boti-dask" => Some("boti_dask."),
        "boti" => Some("boti."),
        _ => None,
    }
}

// ── Thresholds — must stay numerically identical to config.py ───────────────

pub const MAX_FUNCTION_LINES: usize = 50;
pub const MAX_FILE_LINES: usize = 400;
pub const MAX_FUNC_PARAMS: usize = 6;
pub const MAX_RETURNS: usize = 3;
pub const MAX_NESTING_DEPTH: usize = 5;
pub const COMPLEXITY_THRESHOLD: usize = 10;
pub const MIN_BOOLEAN_FLAGS: usize = 3;
pub const MAX_DECORATORS: usize = 3;
pub const MAX_CLASS_METHODS: usize = 25;
pub const MAX_CLASS_ATTRS: usize = 20;
pub const MAX_INHERITANCE_DEPTH: usize = 4;
pub const MAX_MESSAGE_CHAIN_DEPTH: i64 = 3;
pub const DEFAULT_TWIN_SIMILARITY: f64 = 0.6;
pub const DEFAULT_MIN_DUPLICATE_LINES: usize = 5;
pub const DEFAULT_TOP_FILES: usize = 5;
pub const DEFAULT_PLAN_TOP: usize = 20;
pub const MIN_TWIN_FUNCTION_LINES: usize = 4;
pub const MAX_PUBLIC_SYMBOLS: usize = 15;
pub const MIN_CLASS_METHODS: usize = 2;

// Weighted Methods per Class: sum of each method's own cyclomatic
// complexity. A class can stay under MAX_CLASS_METHODS/MAX_CLASS_ATTRS yet
// still be a god class if its few methods are individually complex enough.
pub const MAX_CLASS_WMC: i64 = 50;

// A module is only flagged as an overloaded "hub" when it's both heavily
// depended-on (fan-in) and heavily dependent (fan-out) — either alone is
// often just a legitimately central util or a legitimately thin orchestrator.
pub const MAX_MODULE_FAN_IN: usize = 8;
pub const MAX_MODULE_FAN_OUT: usize = 8;

/// By how much a warning-level threshold is multiplied to decide when a rule
/// escalates its own finding to "error" instead (e.g. high-complexity,
/// god-class) — one shared factor instead of each rule picking its own.
pub const ERROR_ESCALATION_MULTIPLIER: f64 = 1.5;

// ── Units & display ──────────────────────────────────────────────────────────

pub const LINES_PER_KLOC: f64 = 1000.0;
pub const BANNER_WIDTH: usize = 72;

// ── Layer rules (pkg -> {path-prefix: [forbidden import prefixes]}) ─────────
//
// Only exercised for `etl-demo`/`etl-core`, which aren't part of this port's
// default package set — ported faithfully anyway since `layer-violation`'s
// logic doesn't depend on which packages happen to be scanned by default.

pub fn layer_rules(pkg: &str) -> &'static [(&'static str, &'static [&'static str])] {
    match pkg {
        "etl-demo" => &[("routes/", &["boti_data.", "boti.", "boti_dask."])],
        "etl-core" => &[("", &["fastapi", "starlette", "httpx"])],
        _ => &[],
    }
}

// ── Compiled regexes ──────────────────────────────────────────────────────────

pub static TODO_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"#.*\b(TODO|FIXME|XXX|HACK)\b").unwrap());

pub static SUPPRESS_MARKER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"#\s*spaghetti-ignore(?:\[([^\]]*)\])?(?:\s*:\s*(.*))?").unwrap());

/// Mirrors `config.py::DUNDER_RE` (`^__.*__$`). Guards the length so a
/// 2-3 char name like `__`/`___` isn't misidentified as dunder by a naive
/// starts_with/ends_with check (the regex requires ≥4 chars to match both
/// anchors without overlap).
pub fn is_dunder(name: &str) -> bool {
    name.len() >= 4 && name.starts_with("__") && name.ends_with("__")
}
