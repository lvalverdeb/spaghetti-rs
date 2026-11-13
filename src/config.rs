//! Package-wide configuration: workspace root, thresholds (built-in defaults
//! plus the runtime-settable live values), layer rules, library packages and
//! rule overrides — mirrors `spaghetti/config.py`.

use indexmap::IndexMap;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, RwLock};

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

// ── Default thresholds — must stay numerically identical to config.py ───────

pub const MAX_FUNCTION_LINES: usize = 50;
pub const MAX_FILE_LINES: usize = 400;
pub const MAX_FUNC_PARAMS: usize = 6;
pub const MAX_RETURNS: usize = 3;
pub const MAX_NESTING_DEPTH: usize = 5;
// A long function whose nesting stays this shallow or shallower (a couple of
// single-level guard clauses) reads as a flat, linear sequence, not something
// Extract Method reliably improves — distinct from MAX_NESTING_DEPTH, which
// is deep-nesting's own, much higher threshold for a different rule.
pub const LONG_FUNCTION_FLAT_NESTING_MAX: usize = 2;
pub const COMPLEXITY_THRESHOLD: usize = 10;
/// Sonar's default for its cognitive-complexity rule.
pub const COGNITIVE_COMPLEXITY_THRESHOLD: usize = 15;
/// Smallest normalised-token window reported as a clone (see `clones`).
pub const MIN_CLONE_TOKENS: usize = 50;
/// Files whose Maintainability Index is below this are flagged; 10 is the
/// Radon rank-C boundary ("low maintainability").
pub const MIN_MAINTAINABILITY_INDEX: usize = 10;
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

// ── Runtime-settable configuration ───────────────────────────────────────────
//
// Python's checks read every threshold from `spaghetti.config` at call time,
// and `spaghetti.settings.apply_settings` mutates that module in place. The
// `pub const`s above are the built-in defaults; `Thresholds` is the live set
// the checks actually read (through `thresholds()`), installed once per run by
// `settings::apply_settings` before any package is scanned. rayon workers all
// read the same `RwLock`, so they see identical values.

/// Every tunable numeric constant in `spaghetti.config` — field names are the
/// Python constant names in snake_case, so the kebab-case keys in
/// `[tool.spaghetti.thresholds]` map 1:1. Fields the Rust checks don't read
/// yet (`max_cross_layer_imports`, the LCOM4 trio) are accepted so a settings
/// file valid for the Python original is valid here too.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    pub max_function_lines: usize,
    pub max_file_lines: usize,
    pub max_func_params: usize,
    pub max_returns: usize,
    pub max_nesting_depth: usize,
    pub long_function_flat_nesting_max: usize,
    pub max_cross_layer_imports: usize,
    pub complexity_threshold: usize,
    pub cognitive_complexity_threshold: usize,
    pub min_clone_tokens: usize,
    pub min_maintainability_index: usize,
    pub max_class_methods: usize,
    pub max_class_attrs: usize,
    pub min_boolean_flags: usize,
    pub default_min_duplicate_lines: usize,
    pub default_twin_similarity: f64,
    pub default_top_files: usize,
    pub default_plan_top: usize,
    pub min_twin_function_lines: usize,
    pub max_public_symbols: usize,
    pub min_class_methods: usize,
    pub max_class_wmc: i64,
    pub max_class_lcom4: usize,
    pub min_methods_for_cohesion: usize,
    pub min_stateful_method_fraction: f64,
    pub max_module_fan_in: usize,
    pub max_module_fan_out: usize,
    pub error_escalation_multiplier: f64,
    pub max_message_chain_depth: i64,
    pub max_decorators: usize,
    pub max_inheritance_depth: usize,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            max_function_lines: MAX_FUNCTION_LINES,
            max_file_lines: MAX_FILE_LINES,
            max_func_params: MAX_FUNC_PARAMS,
            max_returns: MAX_RETURNS,
            max_nesting_depth: MAX_NESTING_DEPTH,
            long_function_flat_nesting_max: LONG_FUNCTION_FLAT_NESTING_MAX,
            max_cross_layer_imports: 0,
            complexity_threshold: COMPLEXITY_THRESHOLD,
            cognitive_complexity_threshold: COGNITIVE_COMPLEXITY_THRESHOLD,
            min_clone_tokens: MIN_CLONE_TOKENS,
            min_maintainability_index: MIN_MAINTAINABILITY_INDEX,
            max_class_methods: MAX_CLASS_METHODS,
            max_class_attrs: MAX_CLASS_ATTRS,
            min_boolean_flags: MIN_BOOLEAN_FLAGS,
            default_min_duplicate_lines: DEFAULT_MIN_DUPLICATE_LINES,
            default_twin_similarity: DEFAULT_TWIN_SIMILARITY,
            default_top_files: DEFAULT_TOP_FILES,
            default_plan_top: DEFAULT_PLAN_TOP,
            min_twin_function_lines: MIN_TWIN_FUNCTION_LINES,
            max_public_symbols: MAX_PUBLIC_SYMBOLS,
            min_class_methods: MIN_CLASS_METHODS,
            max_class_wmc: MAX_CLASS_WMC,
            max_class_lcom4: 1,
            min_methods_for_cohesion: 3,
            min_stateful_method_fraction: 0.2,
            max_module_fan_in: MAX_MODULE_FAN_IN,
            max_module_fan_out: MAX_MODULE_FAN_OUT,
            error_escalation_multiplier: ERROR_ESCALATION_MULTIPLIER,
            max_message_chain_depth: MAX_MESSAGE_CHAIN_DEPTH,
            max_decorators: MAX_DECORATORS,
            max_inheritance_depth: MAX_INHERITANCE_DEPTH,
        }
    }
}

/// Whether a threshold is an integer or a float in `spaghetti.config` —
/// `settings` rejects a float for an integer threshold, like Python does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdKind {
    Int,
    Float,
}

/// A parsed threshold value, before it is stored into `Thresholds`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThresholdValue {
    Int(i64),
    Float(f64),
}

/// `(PYTHON_CONSTANT_NAME, kind)` for every field of `Thresholds`, in
/// `config.py` order — the vocabulary `[tool.spaghetti.thresholds]` accepts.
pub const THRESHOLD_NAMES: &[(&str, ThresholdKind)] = &[
    ("MAX_FUNCTION_LINES", ThresholdKind::Int),
    ("MAX_FILE_LINES", ThresholdKind::Int),
    ("MAX_FUNC_PARAMS", ThresholdKind::Int),
    ("MAX_RETURNS", ThresholdKind::Int),
    ("MAX_NESTING_DEPTH", ThresholdKind::Int),
    ("LONG_FUNCTION_FLAT_NESTING_MAX", ThresholdKind::Int),
    ("MAX_CROSS_LAYER_IMPORTS", ThresholdKind::Int),
    ("COMPLEXITY_THRESHOLD", ThresholdKind::Int),
    ("COGNITIVE_COMPLEXITY_THRESHOLD", ThresholdKind::Int),
    ("MIN_CLONE_TOKENS", ThresholdKind::Int),
    ("MIN_MAINTAINABILITY_INDEX", ThresholdKind::Int),
    ("MAX_CLASS_METHODS", ThresholdKind::Int),
    ("MAX_CLASS_ATTRS", ThresholdKind::Int),
    ("MIN_BOOLEAN_FLAGS", ThresholdKind::Int),
    ("DEFAULT_MIN_DUPLICATE_LINES", ThresholdKind::Int),
    ("DEFAULT_TWIN_SIMILARITY", ThresholdKind::Float),
    ("DEFAULT_TOP_FILES", ThresholdKind::Int),
    ("DEFAULT_PLAN_TOP", ThresholdKind::Int),
    ("MIN_TWIN_FUNCTION_LINES", ThresholdKind::Int),
    ("MAX_PUBLIC_SYMBOLS", ThresholdKind::Int),
    ("MIN_CLASS_METHODS", ThresholdKind::Int),
    ("MAX_CLASS_WMC", ThresholdKind::Int),
    ("MAX_CLASS_LCOM4", ThresholdKind::Int),
    ("MIN_METHODS_FOR_COHESION", ThresholdKind::Int),
    ("MIN_STATEFUL_METHOD_FRACTION", ThresholdKind::Float),
    ("MAX_MODULE_FAN_IN", ThresholdKind::Int),
    ("MAX_MODULE_FAN_OUT", ThresholdKind::Int),
    ("ERROR_ESCALATION_MULTIPLIER", ThresholdKind::Float),
    ("MAX_MESSAGE_CHAIN_DEPTH", ThresholdKind::Int),
    ("MAX_DECORATORS", ThresholdKind::Int),
    ("MAX_INHERITANCE_DEPTH", ThresholdKind::Int),
];

pub fn threshold_kind(name: &str) -> Option<ThresholdKind> {
    THRESHOLD_NAMES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, kind)| *kind)
}

impl Thresholds {
    /// Store `value` under the Python constant `name`. The caller (`settings`)
    /// has already validated the name and int-vs-float kind; an integer into a
    /// float slot is widened like Python's `setattr` would leave an `int` in a
    /// float's place (comparisons behave identically). Returns `false` for a
    /// negative value in an unsigned slot, which Rust cannot represent.
    pub fn set(&mut self, name: &str, value: ThresholdValue) -> bool {
        let as_f64 = match value {
            ThresholdValue::Int(i) => i as f64,
            ThresholdValue::Float(f) => f,
        };
        let as_i64 = match value {
            ThresholdValue::Int(i) => i,
            ThresholdValue::Float(f) => f as i64,
        };
        let unsigned = |slot: &mut usize| match usize::try_from(as_i64) {
            Ok(v) => {
                *slot = v;
                true
            }
            Err(_) => false,
        };
        match name {
            "MAX_FUNCTION_LINES" => unsigned(&mut self.max_function_lines),
            "MAX_FILE_LINES" => unsigned(&mut self.max_file_lines),
            "MAX_FUNC_PARAMS" => unsigned(&mut self.max_func_params),
            "MAX_RETURNS" => unsigned(&mut self.max_returns),
            "MAX_NESTING_DEPTH" => unsigned(&mut self.max_nesting_depth),
            "LONG_FUNCTION_FLAT_NESTING_MAX" => unsigned(&mut self.long_function_flat_nesting_max),
            "MAX_CROSS_LAYER_IMPORTS" => unsigned(&mut self.max_cross_layer_imports),
            "COMPLEXITY_THRESHOLD" => unsigned(&mut self.complexity_threshold),
            "COGNITIVE_COMPLEXITY_THRESHOLD" => unsigned(&mut self.cognitive_complexity_threshold),
            "MIN_CLONE_TOKENS" => unsigned(&mut self.min_clone_tokens),
            "MIN_MAINTAINABILITY_INDEX" => unsigned(&mut self.min_maintainability_index),
            "MAX_CLASS_METHODS" => unsigned(&mut self.max_class_methods),
            "MAX_CLASS_ATTRS" => unsigned(&mut self.max_class_attrs),
            "MIN_BOOLEAN_FLAGS" => unsigned(&mut self.min_boolean_flags),
            "DEFAULT_MIN_DUPLICATE_LINES" => unsigned(&mut self.default_min_duplicate_lines),
            "DEFAULT_TOP_FILES" => unsigned(&mut self.default_top_files),
            "DEFAULT_PLAN_TOP" => unsigned(&mut self.default_plan_top),
            "MIN_TWIN_FUNCTION_LINES" => unsigned(&mut self.min_twin_function_lines),
            "MAX_PUBLIC_SYMBOLS" => unsigned(&mut self.max_public_symbols),
            "MIN_CLASS_METHODS" => unsigned(&mut self.min_class_methods),
            "MAX_CLASS_LCOM4" => unsigned(&mut self.max_class_lcom4),
            "MIN_METHODS_FOR_COHESION" => unsigned(&mut self.min_methods_for_cohesion),
            "MAX_MODULE_FAN_IN" => unsigned(&mut self.max_module_fan_in),
            "MAX_MODULE_FAN_OUT" => unsigned(&mut self.max_module_fan_out),
            "MAX_DECORATORS" => unsigned(&mut self.max_decorators),
            "MAX_INHERITANCE_DEPTH" => unsigned(&mut self.max_inheritance_depth),
            "MAX_CLASS_WMC" => {
                self.max_class_wmc = as_i64;
                true
            }
            "MAX_MESSAGE_CHAIN_DEPTH" => {
                self.max_message_chain_depth = as_i64;
                true
            }
            "DEFAULT_TWIN_SIMILARITY" => {
                self.default_twin_similarity = as_f64;
                true
            }
            "MIN_STATEFUL_METHOD_FRACTION" => {
                self.min_stateful_method_fraction = as_f64;
                true
            }
            "ERROR_ESCALATION_MULTIPLIER" => {
                self.error_escalation_multiplier = as_f64;
                true
            }
            _ => false,
        }
    }
}

/// `{rule-id: "off" | severity}` from `[tool.spaghetti.rules]` — mirrors
/// `config.py::RULE_OVERRIDES`; applied by `scanner::scan_package` after the
/// checks run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetting {
    Off,
    Severity(crate::models::Severity),
}

/// `{path-prefix-within-package: [forbidden import prefixes]}` for one
/// package, in file order — mirrors one value of `config.py::LAYER_RULES`.
pub type LayerRules = IndexMap<String, Vec<String>>;

/// The mutable part of `spaghetti.config`: what `settings.apply_settings`
/// writes and the checks read.
#[derive(Debug, Clone, Default)]
pub struct Runtime {
    pub thresholds: Thresholds,
    /// `config.py::LAYER_RULES` — empty by default: no built-in architectural
    /// opinions about any particular codebase; `layer-violation` is inert
    /// until `[tool.spaghetti.layers]` fills this in.
    pub layer_rules: IndexMap<String, LayerRules>,
    /// `config.py::LIBRARY_PACKAGES` — the packages `transport-in-library`
    /// applies to; empty by default, set via `library-packages`.
    pub library_packages: BTreeSet<String>,
    pub rule_overrides: BTreeMap<String, RuleSetting>,
}

/// Mirrors `config.py::TRANSPORT_MODULES`.
pub const TRANSPORT_MODULES: &[&str] = &["fastapi", "starlette", "httpx", "flask", "django"];

static RUNTIME: LazyLock<RwLock<Runtime>> = LazyLock::new(|| RwLock::new(Runtime::default()));

fn runtime() -> std::sync::RwLockReadGuard<'static, Runtime> {
    RUNTIME
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Replace the live configuration — called once per run, before scanning.
pub fn install_runtime(new: Runtime) {
    *RUNTIME
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = new;
}

/// The live thresholds (a cheap copy) — what every check reads, mirroring
/// Python's `_cfg.MAX_FUNCTION_LINES` reads at call time.
pub fn thresholds() -> Thresholds {
    runtime().thresholds
}

/// `config.py::LAYER_RULES.get(pkg, {})`.
pub fn layer_rules(pkg: &str) -> LayerRules {
    runtime().layer_rules.get(pkg).cloned().unwrap_or_default()
}

/// `pkg in config.py::LIBRARY_PACKAGES`.
pub fn is_library_package(pkg: &str) -> bool {
    runtime().library_packages.contains(pkg)
}

/// `config.py::RULE_OVERRIDES`.
pub fn rule_overrides() -> BTreeMap<String, RuleSetting> {
    runtime().rule_overrides.clone()
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
