//! Baseline file: the findings a project has accepted for now — mirrors
//! `spaghetti/baseline.py`.
//!
//! A baseline lets a legacy codebase adopt spaghetti with zero new findings on
//! day one and ratchet down from there. Findings are keyed by their
//! `Issue::fingerprint`, so they survive line shifts and unrelated edits.
//!
//! File shape (`schema_version` 1):
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "generated_by": "spaghetti 1.5.0",
//!   "findings": {
//!     "7ef53d04ad35db1d": {"rule": "long-function", "file": "src/m.py", "message": "..."}
//!   }
//! }
//! ```

use crate::json::dumps_pretty;
use crate::models::{Issue, display_path};
use indexmap::IndexMap;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::path::Path;

pub const BASELINE_SCHEMA_VERSION: u64 = 1;

/// The baseline file exists but cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineError(pub String);

impl fmt::Display for BaselineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BaselineError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineEntry {
    pub fingerprint: String,
    pub rule: String,
    pub file: String,
    pub message: String,
}

/// Python's `str()` of a JSON scalar, for the lenient `str(entry.get(...))`
/// reads in `load_baseline`.
fn py_str(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) if value.is_none() => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) => "None".to_string(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(Value::Bool(false)) => "False".to_string(),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

/// Fingerprint → entry, in file order. A missing file is an empty baseline,
/// not an error.
pub fn load_baseline(path: &Path) -> Result<IndexMap<String, BaselineEntry>, BaselineError> {
    if !path.exists() {
        return Ok(IndexMap::new());
    }
    let p = path.display();
    let text = std::fs::read_to_string(path)
        .map_err(|e| BaselineError(format!("{p}: cannot read baseline — {e}")))?;
    let data: Value = serde_json::from_str(&text)
        .map_err(|e| BaselineError(format!("{p}: cannot read baseline — {e}")))?;
    let Some(object) = data.as_object() else {
        return Err(BaselineError(format!(
            "{p}: expected a baseline with schema_version {BASELINE_SCHEMA_VERSION}"
        )));
    };
    if object.get("schema_version").and_then(Value::as_u64) != Some(BASELINE_SCHEMA_VERSION) {
        return Err(BaselineError(format!(
            "{p}: expected a baseline with schema_version {BASELINE_SCHEMA_VERSION}"
        )));
    }
    let findings = match object.get("findings") {
        None => return Ok(IndexMap::new()),
        Some(Value::Object(map)) => map,
        Some(_) => {
            return Err(BaselineError(format!(
                "{p}: 'findings' must be an object keyed by fingerprint"
            )));
        }
    };
    let mut out = IndexMap::new();
    for (fp, entry) in findings {
        let Some(entry) = entry.as_object() else {
            return Err(BaselineError(format!(
                "{p}: entry '{fp}' must be an object"
            )));
        };
        out.insert(
            fp.clone(),
            BaselineEntry {
                fingerprint: fp.clone(),
                rule: py_str(entry.get("rule")),
                file: py_str(entry.get("file")),
                message: py_str(entry.get("message")),
            },
        );
    }
    Ok(out)
}

#[derive(Serialize)]
struct FindingJson<'a> {
    rule: &'a str,
    file: String,
    message: &'a str,
}

#[derive(Serialize)]
struct BaselineJson<'a> {
    schema_version: u64,
    generated_by: &'a str,
    /// Sorted by fingerprint — a `BTreeMap` serializes in key order.
    findings: BTreeMap<&'a str, FindingJson<'a>>,
}

/// Write `issues` as the new baseline — `json.dumps(indent=2)` plus a
/// trailing newline, findings sorted by fingerprint.
pub fn save_baseline(
    path: &Path,
    issues: &[Issue],
    generated_by: &str,
    workspace_root: Option<&Path>,
) -> std::io::Result<()> {
    let findings: BTreeMap<&str, FindingJson<'_>> = issues
        .iter()
        .map(|i| {
            (
                i.fingerprint.as_str(),
                FindingJson {
                    rule: i.rule,
                    file: display_path(&i.file, workspace_root),
                    message: &i.message,
                },
            )
        })
        .collect();
    let payload = BaselineJson {
        schema_version: BASELINE_SCHEMA_VERSION,
        generated_by,
        findings,
    };
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, dumps_pretty(&payload) + "\n")
}

#[derive(Debug, Default)]
pub struct BaselineSplit {
    /// Findings not in the baseline — what the run reports and gates on.
    pub new: Vec<Issue>,
    /// Findings the baseline accepts — hidden from the report, counted.
    pub known: Vec<Issue>,
    /// Baseline entries no finding matched any more — the ratchet's progress.
    pub fixed: Vec<BaselineEntry>,
}

pub fn split_against_baseline(
    issues: Vec<Issue>,
    baseline: &IndexMap<String, BaselineEntry>,
) -> BaselineSplit {
    let mut split = BaselineSplit::default();
    let mut seen: HashSet<&str> = HashSet::new();
    for issue in issues {
        if let Some((fp, _)) = baseline.get_key_value(&issue.fingerprint) {
            seen.insert(fp.as_str());
            split.known.push(issue);
        } else {
            split.new.push(issue);
        }
    }
    split.fixed = baseline
        .iter()
        .filter(|(fp, _)| !seen.contains(fp.as_str()))
        .map(|(_, entry)| entry.clone())
        .collect();
    split
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "spaghetti_rs_baseline_{}_{tag}_{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn issue(fp: &str) -> Issue {
        let mut i = Issue::new(
            Path::new("/pkg/m.py"),
            1,
            Severity::Warning,
            "long-function",
            "pkg",
            format!("long-function {fp}"),
        );
        i.fingerprint = fp.to_string();
        i
    }

    #[test]
    fn save_then_load_roundtrip_sorted_by_fingerprint() {
        let root = temp_dir("roundtrip");
        let path = root.join("nested/baseline.json");
        save_baseline(
            &path,
            &[issue("bbbb"), issue("aaaa")],
            "spaghetti test",
            None,
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let loaded = load_baseline(&path).unwrap();
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(
            text,
            "{\n  \"schema_version\": 1,\n  \"generated_by\": \"spaghetti test\",\n  \"findings\": {\n    \"aaaa\": {\n      \"rule\": \"long-function\",\n      \"file\": \"/pkg/m.py\",\n      \"message\": \"long-function aaaa\"\n    },\n    \"bbbb\": {\n      \"rule\": \"long-function\",\n      \"file\": \"/pkg/m.py\",\n      \"message\": \"long-function bbbb\"\n    }\n  }\n}\n"
        );
        assert_eq!(loaded.keys().collect::<Vec<_>>(), ["aaaa", "bbbb"]);
        assert_eq!(loaded["aaaa"].rule, "long-function");
    }

    #[test]
    fn missing_file_is_an_empty_baseline() {
        assert!(
            load_baseline(Path::new("/nonexistent/nope.json"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn unusable_baseline_errors() {
        let root = temp_dir("unusable");
        let path = root.join("b.json");
        for content in [
            "not json",
            r#"{"schema_version": 2, "findings": {}}"#,
            r#"{"schema_version": 1, "findings": []}"#,
            r#"{"schema_version": 1, "findings": {"x": 1}}"#,
        ] {
            std::fs::write(&path, content).unwrap();
            let msg = load_baseline(&path).unwrap_err().to_string();
            assert!(msg.starts_with(&path.display().to_string()), "{msg}");
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn split_partitions_new_known_and_fixed() {
        let root = temp_dir("split");
        let path = root.join("b.json");
        save_baseline(&path, &[issue("known"), issue("gone")], "t", None).unwrap();
        let baseline = load_baseline(&path).unwrap();
        std::fs::remove_dir_all(&root).ok();
        let split = split_against_baseline(vec![issue("known"), issue("fresh")], &baseline);
        assert_eq!(
            split
                .new
                .iter()
                .map(|i| i.fingerprint.as_str())
                .collect::<Vec<_>>(),
            ["fresh"]
        );
        assert_eq!(
            split
                .known
                .iter()
                .map(|i| i.fingerprint.as_str())
                .collect::<Vec<_>>(),
            ["known"]
        );
        assert_eq!(
            split
                .fixed
                .iter()
                .map(|e| e.fingerprint.as_str())
                .collect::<Vec<_>>(),
            ["gone"]
        );
    }
}
