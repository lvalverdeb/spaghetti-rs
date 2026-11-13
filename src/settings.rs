//! Project settings: `[tool.spaghetti]` in `pyproject.toml` and/or the
//! `--config` YAML file — mirrors `spaghetti/settings.py`.
//!
//! Precedence, lowest to highest: built-in defaults in `config`,
//! `pyproject.toml` found by walking up from the working directory, the
//! `--config` YAML, explicit CLI flags.
//!
//! Recognised keys (kebab-case in the file):
//!
//! ```toml
//! [tool.spaghetti]
//! exclude = ["tests/", "migrations/"]
//! fail-on = "error"                       # error | warning | info | never
//! baseline = ".spaghetti-baseline.json"   # relative to the settings file
//! library-packages = ["my-lib"]           # packages transport-in-library applies to
//!
//! [tool.spaghetti.packages]
//! my-lib = "src/my_lib"                   # same mapping --config's `packages:` takes
//!
//! [tool.spaghetti.thresholds]             # any numeric constant in spaghetti.config
//! max-function-lines = 60
//! complexity-threshold = 12
//!
//! [tool.spaghetti.rules]                  # off, or a severity override
//! magic-number = "off"
//! missing-return-type = "info"
//!
//! [tool.spaghetti.layers.my-lib]          # path prefix -> forbidden import prefixes
//! "routes/" = ["my_lib.db."]
//! ```
//!
//! Both file formats are read into one generic `serde_json::Value` tree (with
//! `preserve_order`, so mapping order survives like a Python dict's) and
//! validated by the same `parse_mapping`, so the error wording is identical
//! whichever file a key came from.

use crate::config::{
    LayerRules, RuleSetting, Runtime, THRESHOLD_NAMES, ThresholdKind, ThresholdValue, Thresholds,
    threshold_kind,
};
use crate::models::Severity;
use crate::rules::is_known_rule;
use indexmap::IndexMap;
use serde_json::{Map, Value};
use std::fmt;
use std::path::{Component, Path, PathBuf};

pub const FAIL_ON_CHOICES: &[&str] = &["error", "warning", "info", "never"];
pub const RULE_SETTING_CHOICES: &[&str] = &["off", "info", "warning", "error"];

/// A settings file is malformed; the message names the file and key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsError(pub String);

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SettingsError {}

fn err<T>(msg: String) -> Result<T, SettingsError> {
    Err(SettingsError(msg))
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Settings {
    /// `PYTHON_CONSTANT_NAME -> value`, validated against `config::THRESHOLD_NAMES`.
    pub thresholds: IndexMap<String, ThresholdValue>,
    pub rules: IndexMap<String, RuleSetting>,
    pub layers: IndexMap<String, LayerRules>,
    pub library_packages: Vec<String>,
    pub exclude: Vec<String>,
    pub fail_on: Option<String>,
    pub baseline: Option<PathBuf>,
    pub packages: IndexMap<String, PathBuf>,
    pub sources: Vec<PathBuf>,
}

impl Settings {
    /// `other` wins on scalar conflicts; mappings and lists combine (a
    /// mapping key already present keeps its position, like `{**a, **b}`).
    pub fn merged_with(&self, other: &Settings) -> Settings {
        fn merge<V: Clone>(
            a: &IndexMap<String, V>,
            b: &IndexMap<String, V>,
        ) -> IndexMap<String, V> {
            let mut out = a.clone();
            for (k, v) in b {
                out.insert(k.clone(), v.clone());
            }
            out
        }
        Settings {
            thresholds: merge(&self.thresholds, &other.thresholds),
            rules: merge(&self.rules, &other.rules),
            layers: merge(&self.layers, &other.layers),
            library_packages: [&self.library_packages[..], &other.library_packages[..]].concat(),
            exclude: [&self.exclude[..], &other.exclude[..]].concat(),
            fail_on: other.fail_on.clone().or_else(|| self.fail_on.clone()),
            baseline: other.baseline.clone().or_else(|| self.baseline.clone()),
            packages: merge(&self.packages, &other.packages),
            sources: [&self.sources[..], &other.sources[..]].concat(),
        }
    }
}

// ── Discovery & loading ───────────────────────────────────────────────────────

fn read_toml(pyproject: &Path) -> Result<Option<toml::Table>, SettingsError> {
    let Ok(text) = std::fs::read_to_string(pyproject) else {
        return Ok(None);
    };
    match text.parse::<toml::Table>() {
        Ok(table) => Ok(Some(table)),
        Err(e) => err(format!("{}: invalid TOML — {e}", pyproject.display())),
    }
}

fn tool_spaghetti(table: &toml::Table) -> Option<&toml::Table> {
    table
        .get("tool")
        .and_then(|t| t.as_table())
        .and_then(|t| t.get("spaghetti"))
        .and_then(|s| s.as_table())
}

/// Nearest `pyproject.toml` at or above `start` with a `[tool.spaghetti]`
/// table — mirrors `settings.py::find_pyproject`.
///
/// A `pyproject.toml` that fails to parse is an error rather than being
/// skipped: silently falling back to defaults would turn a typo in the
/// settings into a run that ignores every setting.
pub fn find_pyproject(start: &Path) -> Result<Option<PathBuf>, SettingsError> {
    for candidate in start.ancestors() {
        let pyproject = candidate.join("pyproject.toml");
        if !pyproject.is_file() {
            continue;
        }
        let Some(table) = read_toml(&pyproject)? else {
            continue;
        };
        if tool_spaghetti(&table).is_some() {
            return Ok(Some(pyproject));
        }
    }
    Ok(None)
}

/// `settings.py::load_settings`: pyproject first, then the `--config` YAML on
/// top; the YAML's `packages:` (if any) is the whole registry, not an overlay.
pub fn load_settings(
    pyproject: Option<&Path>,
    yaml_path: Option<&Path>,
) -> Result<Settings, SettingsError> {
    let mut settings = Settings::default();
    if let Some(pyproject) = pyproject {
        let table = read_toml(pyproject)?.unwrap_or_else(|| {
            // Unreadable here but readable during discovery: treat as empty,
            // like `tomllib.loads("")` would.
            toml::Table::new()
        });
        let data = tool_spaghetti(&table)
            .map(|t| toml_table_to_json(t.clone()))
            .unwrap_or_default();
        settings = settings.merged_with(&parse_mapping(&data, pyproject)?);
    }
    if let Some(yaml_path) = yaml_path {
        let text = std::fs::read_to_string(yaml_path).map_err(|e| {
            SettingsError(format!(
                "could not read --config {}: {e}",
                yaml_path.display()
            ))
        })?;
        let raw: Value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_saphyr::from_str(&text).map_err(|e| {
                SettingsError(format!(
                    "could not parse --config {}: {e}",
                    yaml_path.display()
                ))
            })?
        };
        let data = match raw {
            Value::Null => Map::new(), // `yaml.safe_load(...) or {}`
            Value::Object(map) => map,
            _ => {
                return err(format!(
                    "{}: top level must be a mapping",
                    yaml_path.display()
                ));
            }
        };
        let from_yaml = parse_mapping(&data, yaml_path)?;
        settings = settings.merged_with(&from_yaml);
        if !from_yaml.packages.is_empty() {
            settings.packages = from_yaml.packages.clone();
        }
    }
    Ok(settings)
}

/// `toml::Value` → `serde_json::Value`, keeping table order and the
/// integer/float distinction (`Datetime` becomes its string form).
fn toml_to_json(value: toml::Value) -> Value {
    match value {
        toml::Value::String(s) => Value::String(s),
        toml::Value::Integer(i) => Value::Number(i.into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        toml::Value::Boolean(b) => Value::Bool(b),
        toml::Value::Datetime(d) => Value::String(d.to_string()),
        toml::Value::Array(items) => Value::Array(items.into_iter().map(toml_to_json).collect()),
        toml::Value::Table(table) => Value::Object(toml_table_to_json(table)),
    }
}

fn toml_table_to_json(table: toml::Table) -> Map<String, Value> {
    table
        .into_iter()
        .map(|(k, v)| (k, toml_to_json(v)))
        .collect()
}

const SCALAR_KEYS: &[&str] = &[
    "exclude",
    "fail-on",
    "baseline",
    "library-packages",
    "packages",
];
const TABLE_KEYS: &[&str] = &["thresholds", "rules", "layers"];

/// Validate one settings mapping — mirrors `settings.py::parse_mapping`.
/// Relative paths resolve against `origin`'s directory.
pub fn parse_mapping(data: &Map<String, Value>, origin: &Path) -> Result<Settings, SettingsError> {
    let base_dir = origin.parent().unwrap_or_else(|| Path::new(""));
    let mut unknown: Vec<&str> = data
        .keys()
        .map(String::as_str)
        .filter(|k| !SCALAR_KEYS.contains(k) && !TABLE_KEYS.contains(k))
        .collect();
    if !unknown.is_empty() {
        unknown.sort_unstable();
        let mut known: Vec<&str> = SCALAR_KEYS.iter().chain(TABLE_KEYS).copied().collect();
        known.sort_unstable();
        return err(format!(
            "{}: unknown setting(s): {}. Known: {}",
            origin.display(),
            unknown.join(", "),
            known.join(", ")
        ));
    }
    let o = origin.display();
    let mut s = Settings {
        sources: vec![origin.to_path_buf()],
        ..Settings::default()
    };
    let empty_list = Value::Array(Vec::new());
    let empty_table = Value::Object(Map::new());
    s.exclude = str_list(
        data.get("exclude").unwrap_or(&empty_list),
        origin,
        "exclude",
    )?;
    s.library_packages = str_list(
        data.get("library-packages").unwrap_or(&empty_list),
        origin,
        "library-packages",
    )?;
    if let Some(fail_on) = data.get("fail-on").filter(|v| !v.is_null()) {
        match fail_on.as_str() {
            Some(choice) if FAIL_ON_CHOICES.contains(&choice) => {
                s.fail_on = Some(choice.to_string())
            }
            _ => {
                return err(format!(
                    "{o}: fail-on must be one of {}",
                    FAIL_ON_CHOICES.join(", ")
                ));
            }
        }
    }
    if let Some(baseline) = data.get("baseline").filter(|v| !v.is_null()) {
        let Some(path) = baseline.as_str() else {
            return err(format!("{o}: baseline must be a path string"));
        };
        s.baseline = Some(resolve_lenient(&base_dir.join(path)));
    }
    let packages = data.get("packages").unwrap_or(&empty_table);
    match packages.as_object() {
        Some(map) if map.values().all(Value::is_string) => {
            s.packages = map
                .iter()
                .map(|(name, path)| {
                    let path = path.as_str().unwrap_or_default();
                    (name.clone(), resolve_lenient(&base_dir.join(path)))
                })
                .collect();
        }
        _ => return err(format!("{o}: packages must map names to path strings")),
    }
    s.thresholds = parse_thresholds(data.get("thresholds").unwrap_or(&empty_table), origin)?;
    s.rules = parse_rules(data.get("rules").unwrap_or(&empty_table), origin)?;
    s.layers = parse_layers(data.get("layers").unwrap_or(&empty_table), origin)?;
    Ok(s)
}

fn str_list(value: &Value, origin: &Path, key: &str) -> Result<Vec<String>, SettingsError> {
    match value.as_array() {
        Some(items) if items.iter().all(Value::is_string) => Ok(items
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .collect()),
        _ => err(format!(
            "{}: {key} must be a list of strings",
            origin.display()
        )),
    }
}

/// Kebab-case spelling of a Python constant name (`MAX_FUNCTION_LINES` →
/// `max-function-lines`).
pub fn kebab(name: &str) -> String {
    name.to_lowercase().replace('_', "-")
}

fn parse_thresholds(
    table: &Value,
    origin: &Path,
) -> Result<IndexMap<String, ThresholdValue>, SettingsError> {
    let o = origin.display();
    let Some(table) = table.as_object() else {
        return err(format!("{o}: thresholds must be a table"));
    };
    let mut out = IndexMap::new();
    for (key, value) in table {
        let name = key.to_uppercase().replace('-', "_");
        let Some(kind) = threshold_kind(&name) else {
            let mut known: Vec<String> = THRESHOLD_NAMES.iter().map(|(n, _)| kebab(n)).collect();
            known.sort_unstable();
            return err(format!(
                "{o}: unknown threshold '{key}'. Known: {}",
                known.join(", ")
            ));
        };
        let parsed = match value {
            Value::Number(n) if n.is_i64() || n.is_u64() => {
                ThresholdValue::Int(n.as_i64().unwrap_or(i64::MAX))
            }
            Value::Number(n) => ThresholdValue::Float(n.as_f64().unwrap_or_default()),
            _ => return err(format!("{o}: threshold '{key}' must be a number")),
        };
        if kind == ThresholdKind::Int && matches!(parsed, ThresholdValue::Float(_)) {
            return err(format!("{o}: threshold '{key}' must be an integer"));
        }
        if matches!(parsed, ThresholdValue::Int(i) if i < 0) && kind == ThresholdKind::Int {
            // Rust-only limit: the integer thresholds are unsigned here.
            return err(format!(
                "{o}: threshold '{key}' must be a non-negative integer"
            ));
        }
        out.insert(name, parsed);
    }
    Ok(out)
}

fn parse_rules(
    table: &Value,
    origin: &Path,
) -> Result<IndexMap<String, RuleSetting>, SettingsError> {
    let o = origin.display();
    let Some(table) = table.as_object() else {
        return err(format!("{o}: rules must be a table"));
    };
    let mut out = IndexMap::new();
    for (rule, value) in table {
        if !is_known_rule(rule) {
            return err(format!("{o}: unknown rule '{rule}'"));
        }
        let setting = match value.as_str() {
            Some("off") => RuleSetting::Off,
            Some("info") => RuleSetting::Severity(Severity::Info),
            Some("warning") => RuleSetting::Severity(Severity::Warning),
            Some("error") => RuleSetting::Severity(Severity::Error),
            _ => {
                return err(format!(
                    "{o}: rule '{rule}' must be one of {}",
                    RULE_SETTING_CHOICES.join(", ")
                ));
            }
        };
        out.insert(rule.clone(), setting);
    }
    Ok(out)
}

fn parse_layers(
    table: &Value,
    origin: &Path,
) -> Result<IndexMap<String, LayerRules>, SettingsError> {
    let o = origin.display();
    let Some(table) = table.as_object() else {
        return err(format!("{o}: layers must be a table"));
    };
    let mut out = IndexMap::new();
    for (pkg, rules) in table {
        let Some(rules) = rules.as_object() else {
            return err(format!("{o}: layers.{pkg} must map path prefixes to lists"));
        };
        let mut per_pkg = LayerRules::new();
        for (prefix, forbidden) in rules {
            per_pkg.insert(
                prefix.clone(),
                str_list(forbidden, origin, &format!("layers.{pkg}.{prefix}"))?,
            );
        }
        out.insert(pkg.clone(), per_pkg);
    }
    Ok(out)
}

/// Python's `Path.resolve()` (non-strict): absolute, symlinks in the existing
/// prefix resolved, `.`/`..` collapsed, and a non-existent tail appended
/// as-is. `canonicalize` alone fails on a path that doesn't exist yet (a
/// baseline about to be written, say).
pub fn resolve_lenient(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let mut resolved = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            other => {
                resolved.push(other.as_os_str());
                if let Ok(real) = resolved.canonicalize() {
                    resolved = real;
                }
            }
        }
    }
    resolved
}

// ── Application ───────────────────────────────────────────────────────────────

/// The `config` state `settings` describes — mirrors `settings.py::apply_settings`
/// minus the mutation; pass the result to `config::install_runtime`.
pub fn to_runtime(settings: &Settings) -> Runtime {
    let mut thresholds = Thresholds::default();
    for (name, value) in &settings.thresholds {
        thresholds.set(name, *value);
    }
    Runtime {
        thresholds,
        layer_rules: settings.layers.clone(),
        library_packages: settings.library_packages.iter().cloned().collect(),
        rule_overrides: settings
            .rules
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect(),
    }
}

/// Install `settings` as the live configuration every check reads.
pub fn apply_settings(settings: &Settings) {
    crate::config::install_runtime(to_runtime(settings));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "spaghetti_rs_settings_{}_{tag}_{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn json(text: &str) -> Map<String, Value> {
        serde_json::from_str::<Value>(text)
            .unwrap()
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn find_pyproject_walks_up_and_requires_tool_table() {
        let root = temp_dir("walk");
        std::fs::write(
            root.join("pyproject.toml"),
            "[tool.spaghetti]\nexclude = []\n",
        )
        .unwrap();
        let nested = root.join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(root.join("a/pyproject.toml"), "[project]\nname = 'x'\n").unwrap();
        let found = find_pyproject(&nested).unwrap();
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(found, Some(root.join("pyproject.toml")));
    }

    #[test]
    fn find_pyproject_refuses_to_skip_invalid_toml() {
        let root = temp_dir("invalid");
        std::fs::write(root.join("pyproject.toml"), "[tool.spaghetti]\nx = \n").unwrap();
        let result = find_pyproject(&root);
        std::fs::remove_dir_all(&root).ok();
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("invalid TOML"), "{msg}");
    }

    #[test]
    fn parse_mapping_full_example() {
        let root = temp_dir("full");
        let origin = root.join("pyproject.toml");
        let s = parse_mapping(
            &json(
                r#"{
                "exclude": ["tests/"],
                "fail-on": "error",
                "baseline": ".baseline.json",
                "library-packages": ["lib"],
                "packages": {"lib": "src/lib"},
                "thresholds": {"max-function-lines": 80, "default-twin-similarity": 0.7},
                "rules": {"magic-number": "off", "missing-return-type": "error"},
                "layers": {"lib": {"routes/": ["lib.db."]}}
            }"#,
            ),
            &origin,
        )
        .unwrap();
        let real_root = root.canonicalize().unwrap();
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(s.exclude, ["tests/"]);
        assert_eq!(s.fail_on.as_deref(), Some("error"));
        assert_eq!(s.baseline, Some(real_root.join(".baseline.json")));
        assert_eq!(s.library_packages, ["lib"]);
        assert_eq!(s.packages["lib"], real_root.join("src/lib"));
        assert_eq!(s.thresholds["MAX_FUNCTION_LINES"], ThresholdValue::Int(80));
        assert_eq!(
            s.thresholds["DEFAULT_TWIN_SIMILARITY"],
            ThresholdValue::Float(0.7)
        );
        assert_eq!(s.rules["magic-number"], RuleSetting::Off);
        assert_eq!(
            s.rules["missing-return-type"],
            RuleSetting::Severity(Severity::Error)
        );
        assert_eq!(s.layers["lib"]["routes/"], ["lib.db."]);
        assert_eq!(s.sources, [origin]);
    }

    #[test]
    fn parse_mapping_rejects_bad_input_with_pythons_wording() {
        let cases = [
            (
                r#"{"bogus": 1}"#,
                "unknown setting(s): bogus. Known: baseline, exclude, fail-on, layers, library-packages, packages, rules, thresholds",
            ),
            (
                r#"{"fail-on": "sometimes"}"#,
                "fail-on must be one of error, warning, info, never",
            ),
            (
                r#"{"thresholds": {"bogus": 1}}"#,
                "unknown threshold 'bogus'. Known: complexity-threshold, default-min-duplicate-lines",
            ),
            (
                r#"{"thresholds": {"max-function-lines": "50"}}"#,
                "threshold 'max-function-lines' must be a number",
            ),
            (
                r#"{"thresholds": {"max-function-lines": 50.5}}"#,
                "threshold 'max-function-lines' must be an integer",
            ),
            (
                r#"{"thresholds": {"max-function-lines": true}}"#,
                "must be a number",
            ),
            (
                r#"{"rules": {"not-a-rule": "off"}}"#,
                "unknown rule 'not-a-rule'",
            ),
            (
                r#"{"rules": {"magic-number": "maybe"}}"#,
                "rule 'magic-number' must be one of off, info, warning, error",
            ),
            (
                r#"{"layers": {"lib": ["x"]}}"#,
                "layers.lib must map path prefixes to lists",
            ),
            (
                r#"{"layers": {"lib": {"a/": "x"}}}"#,
                "layers.lib.a/ must be a list of strings",
            ),
            (
                r#"{"exclude": "tests/"}"#,
                "exclude must be a list of strings",
            ),
            (
                r#"{"packages": {"lib": 3}}"#,
                "packages must map names to path strings",
            ),
            (r#"{"thresholds": []}"#, "thresholds must be a table"),
        ];
        for (data, expected) in cases {
            let msg = parse_mapping(&json(data), Path::new("/x/pyproject.toml"))
                .unwrap_err()
                .to_string();
            assert!(msg.starts_with("/x/pyproject.toml: "), "{msg}");
            assert!(msg.contains(expected), "{data}: {msg}");
        }
    }

    #[test]
    fn threshold_names_cover_every_python_tunable() {
        let names: Vec<&str> = THRESHOLD_NAMES.iter().map(|(n, _)| *n).collect();
        assert_eq!(names.len(), 28);
        for required in [
            "MAX_FUNCTION_LINES",
            "COMPLEXITY_THRESHOLD",
            "MAX_CLASS_LCOM4",
        ] {
            assert!(names.contains(&required));
        }
        assert!(!names.contains(&"BANNER_WIDTH"));
        assert!(!names.contains(&"LINES_PER_KLOC"));
    }

    #[test]
    fn load_settings_yaml_overrides_pyproject_and_replaces_packages() {
        let root = temp_dir("merge");
        let pyproject = root.join("pyproject.toml");
        std::fs::write(
            &pyproject,
            "[tool.spaghetti]\nfail-on = \"warning\"\nexclude = [\"a/\"]\n\
             [tool.spaghetti.packages]\nold = 'src/old'\n\
             [tool.spaghetti.thresholds]\nmax-function-lines = 60\n",
        )
        .unwrap();
        let cfg_dir = root.join("cfg");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        let yaml_path = cfg_dir.join("spaghetti.yaml");
        std::fs::write(
            &yaml_path,
            "fail-on: error\nexclude: [b/]\npackages:\n  new: pkg\nthresholds:\n  max-returns: 5\n",
        )
        .unwrap();
        let s = load_settings(Some(&pyproject), Some(&yaml_path)).unwrap();
        let real_cfg = cfg_dir.canonicalize().unwrap();
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(s.fail_on.as_deref(), Some("error"));
        assert_eq!(s.exclude, ["a/", "b/"]);
        assert_eq!(s.thresholds["MAX_FUNCTION_LINES"], ThresholdValue::Int(60));
        assert_eq!(s.thresholds["MAX_RETURNS"], ThresholdValue::Int(5));
        assert_eq!(s.packages.len(), 1);
        assert_eq!(s.packages["new"], real_cfg.join("pkg"));
    }

    #[test]
    fn yaml_scalars_keep_their_types() {
        let root = temp_dir("yaml_types");
        let yaml_path = root.join("s.yaml");
        std::fs::write(&yaml_path, "thresholds:\n  max-function-lines: 50.5\n").unwrap();
        let msg = load_settings(None, Some(&yaml_path))
            .unwrap_err()
            .to_string();
        std::fs::write(&yaml_path, "thresholds:\n  max-function-lines: true\n").unwrap();
        let msg2 = load_settings(None, Some(&yaml_path))
            .unwrap_err()
            .to_string();
        std::fs::write(&yaml_path, "- a\n").unwrap();
        let msg3 = load_settings(None, Some(&yaml_path))
            .unwrap_err()
            .to_string();
        std::fs::write(&yaml_path, "").unwrap();
        let empty = load_settings(None, Some(&yaml_path)).unwrap();
        std::fs::remove_dir_all(&root).ok();
        assert!(msg.contains("must be an integer"), "{msg}");
        assert!(msg2.contains("must be a number"), "{msg2}");
        assert!(msg3.contains("top level must be a mapping"), "{msg3}");
        assert_eq!(empty.sources, [yaml_path]);
    }

    #[test]
    fn load_settings_with_nothing_is_empty() {
        assert_eq!(load_settings(None, None).unwrap(), Settings::default());
    }

    #[test]
    fn to_runtime_reflects_thresholds_rules_layers_and_libraries() {
        let mut s = Settings::default();
        s.thresholds
            .insert("MAX_FUNCTION_LINES".into(), ThresholdValue::Int(7));
        s.thresholds
            .insert("DEFAULT_TWIN_SIMILARITY".into(), ThresholdValue::Int(1));
        s.rules.insert("magic-number".into(), RuleSetting::Off);
        let mut layer = LayerRules::new();
        layer.insert("".into(), vec!["x".into()]);
        s.layers.insert("lib".into(), layer);
        s.library_packages.push("lib".into());
        let runtime = to_runtime(&s);
        assert_eq!(runtime.thresholds.max_function_lines, 7);
        assert_eq!(runtime.thresholds.default_twin_similarity, 1.0);
        assert_eq!(
            runtime.thresholds.max_file_lines,
            crate::config::MAX_FILE_LINES
        );
        assert_eq!(runtime.rule_overrides["magic-number"], RuleSetting::Off);
        assert_eq!(runtime.layer_rules["lib"][""], ["x"]);
        assert!(runtime.library_packages.contains("lib"));
    }
}
