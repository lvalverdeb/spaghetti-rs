//! Snapshot store and run-to-run comparison (ROADMAP Phase 3) — mirrors
//! `spaghetti/snapshots.py`.
//!
//! `spaghetti --snapshot` appends one JSON line per run to a local store
//! (default `.spaghetti/snapshots.jsonl`): git SHA, timestamp, per-package
//! scores, per-file penalties and every finding's fingerprint. `--compare REF`
//! diffs the current run against a stored one — score deltas, findings
//! introduced and fixed, files that got worse — so a PR check can say exactly
//! what a change did to the codebase's health. The store format is shared
//! with the Python original: either tool reads what the other wrote.

use crate::json::{dumps_compact, py_float_repr, py_round};
use crate::models::{Issue, ScanResult, display_path};
use crate::scoring::{compute_score, file_penalties};
use indexmap::IndexMap;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::path::Path;

pub const SNAPSHOT_SCHEMA_VERSION: i64 = 1;
pub const DEFAULT_STORE: &str = ".spaghetti/snapshots.jsonl";

/// The store or a reference into it is unusable; the message says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotError(pub String);

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SnapshotError {}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SnapshotFinding {
    pub fingerprint: String,
    pub rule: String,
    pub severity: String,
    pub file: String,
    pub line: i64,
    pub message: String,
}

impl SnapshotFinding {
    pub fn from_issue(issue: &Issue, workspace_root: Option<&Path>) -> Self {
        SnapshotFinding {
            fingerprint: issue.fingerprint.clone(),
            rule: issue.rule.to_string(),
            severity: issue.severity.as_str().to_string(),
            file: display_path(&issue.file, workspace_root),
            line: issue.line as i64,
            message: issue.message.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub timestamp: String,
    pub sha: Option<String>,
    pub tool_version: String,
    /// Package name -> health score; `"*"` is the overall score.
    pub scores: IndexMap<String, f64>,
    /// Display path -> penalty (sum of severity weights of its findings).
    pub files: IndexMap<String, f64>,
    pub findings: Vec<SnapshotFinding>,
}

#[derive(Serialize)]
struct SnapshotJson<'a> {
    schema_version: i64,
    timestamp: &'a str,
    sha: &'a Option<String>,
    tool_version: &'a str,
    scores: &'a IndexMap<String, f64>,
    files: &'a IndexMap<String, f64>,
    findings: &'a [SnapshotFinding],
}

impl Snapshot {
    pub fn label(&self) -> String {
        let sha = match &self.sha {
            Some(sha) if !sha.is_empty() => sha.chars().take(12).collect(),
            _ => "no-sha".to_string(),
        };
        format!("{sha} @ {}", self.timestamp)
    }

    /// One store line: `json.dumps(snapshot.to_json(), ensure_ascii=False)`.
    pub fn to_line(&self) -> String {
        dumps_compact(
            &SnapshotJson {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                timestamp: &self.timestamp,
                sha: &self.sha,
                tool_version: &self.tool_version,
                scores: &self.scores,
                files: &self.files,
                findings: &self.findings,
            },
            false,
        )
    }

    pub fn from_json(data: &Value, origin: &str) -> Result<Snapshot, SnapshotError> {
        let malformed =
            |why: String| SnapshotError(format!("{origin}: malformed snapshot ({why})"));
        let Some(data) = data.as_object() else {
            return Err(malformed("not an object".to_string()));
        };
        let version = data.get("schema_version");
        let version_ok = match version {
            Some(Value::Number(n)) => n.as_f64() == Some(SNAPSHOT_SCHEMA_VERSION as f64),
            Some(Value::Bool(b)) => *b, // Python: True == 1
            _ => false,
        };
        if !version_ok {
            return Err(SnapshotError(format!(
                "{origin}: unsupported snapshot schema_version {}",
                py_value_repr(version.unwrap_or(&Value::Null))
            )));
        }
        let required = |key: &str| data.get(key).ok_or_else(|| malformed(format!("'{key}'")));
        let findings = required("findings")?
            .as_array()
            .ok_or_else(|| malformed("findings is not a list".to_string()))?
            .iter()
            .map(|f| finding_from_json(f).ok_or_else(|| malformed("bad finding".to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        let timestamp = py_str(required("timestamp")?);
        let sha = match data.get("sha") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(other) => Some(py_str(other)),
        };
        let tool_version = data.get("tool_version").map(py_str).unwrap_or_default();
        let floats = |key: &str| -> Result<IndexMap<String, f64>, SnapshotError> {
            required(key)?
                .as_object()
                .ok_or_else(|| malformed(format!("{key} is not a mapping")))?
                .iter()
                .map(|(k, v)| {
                    as_float(v)
                        .map(|f| (k.clone(), f))
                        .ok_or_else(|| malformed(format!("{key}[{k:?}] is not a number")))
                })
                .collect()
        };
        Ok(Snapshot {
            timestamp,
            sha,
            tool_version,
            scores: floats("scores")?,
            files: floats("files")?,
            findings,
        })
    }
}

fn as_float(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn finding_from_json(value: &Value) -> Option<SnapshotFinding> {
    let map: &Map<String, Value> = value.as_object()?;
    const KEYS: [&str; 6] = ["fingerprint", "rule", "severity", "file", "line", "message"];
    if map.len() != KEYS.len() || !KEYS.iter().all(|k| map.contains_key(*k)) {
        return None;
    }
    let s = |k: &str| map.get(k).and_then(Value::as_str).map(str::to_string);
    Some(SnapshotFinding {
        fingerprint: s("fingerprint")?,
        rule: s("rule")?,
        severity: s("severity")?,
        file: s("file")?,
        line: map.get("line")?.as_i64()?,
        message: s("message")?,
    })
}

/// Python's `str(value)` for a JSON scalar.
fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => py_value_repr(other),
    }
}

/// Python's `repr()` of a decoded JSON value (approximate for containers).
pub fn py_value_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(n) if n.is_f64() => py_float_repr(n.as_f64().unwrap_or_default()),
        Value::Number(n) => n.to_string(),
        Value::String(s) => py_str_repr(s),
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(py_value_repr)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(k, v)| format!("{}: {}", py_str_repr(k), py_value_repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Python's `repr(str)`.
pub fn py_str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `git rev-parse HEAD` in `cwd`, or `None` outside a repository.
pub fn git_head_sha(cwd: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(cwd)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!sha.is_empty()).then_some(sha)
}

/// `datetime.now(UTC).replace(microsecond=0).isoformat()`.
pub fn utc_now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    iso_from_unix(secs)
}

fn iso_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}+00:00",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// The current run as a snapshot — mirrors `snapshots.py::take_snapshot`.
pub fn take_snapshot(
    per_package: &IndexMap<String, ScanResult>,
    total: &ScanResult,
    tool_version: &str,
    sha: Option<String>,
    timestamp: String,
    workspace_root: Option<&Path>,
) -> Snapshot {
    let mut scores: IndexMap<String, f64> = per_package
        .iter()
        .map(|(name, r)| (name.clone(), py_round(compute_score(r).0, 1)))
        .collect();
    scores.insert("*".to_string(), py_round(compute_score(total).0, 1));
    let files = file_penalties(&total.issues)
        .into_iter()
        .map(|(path, p)| (display_path(&path, workspace_root), py_round(p, 2)))
        .collect();
    Snapshot {
        timestamp,
        sha,
        tool_version: tool_version.to_string(),
        scores,
        files,
        findings: total
            .issues
            .iter()
            .map(|i| SnapshotFinding::from_issue(i, workspace_root))
            .collect(),
    }
}

pub fn append_snapshot(store: &Path, snapshot: &Snapshot) -> std::io::Result<()> {
    use std::io::Write as _;
    if let Some(parent) = store.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut fh = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(store)?;
    fh.write_all(format!("{}\n", snapshot.to_line()).as_bytes())
}

/// Every snapshot in the store, oldest first; an absent store is empty.
pub fn load_snapshots(store: &Path) -> Result<Vec<Snapshot>, SnapshotError> {
    if !store.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(store)
        .map_err(|e| SnapshotError(format!("{}: {e}", store.display())))?;
    let mut snapshots = Vec::new();
    for (number, line) in text.split('\n').enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim().is_empty() {
            continue;
        }
        let origin = format!("{}:{}", store.display(), number + 1);
        let data: Value = serde_json::from_str(line)
            .map_err(|e| SnapshotError(format!("{origin}: not JSON ({e})")))?;
        snapshots.push(Snapshot::from_json(&data, &origin)?);
    }
    Ok(snapshots)
}

/// `latest`; `~N` for the N-th most recent (`~1` = the one before latest); a
/// git SHA prefix; or a timestamp prefix (`2026-11`).
pub fn find_snapshot<'a>(
    snapshots: &'a [Snapshot],
    r: &str,
) -> Result<&'a Snapshot, SnapshotError> {
    let Some(latest) = snapshots.last() else {
        return Err(SnapshotError(
            "the snapshot store is empty — run with --snapshot first".to_string(),
        ));
    };
    if r == "latest" {
        return Ok(latest);
    }
    if let Some(back) = r.strip_prefix('~')
        && !back.is_empty()
        && back.bytes().all(|b| b.is_ascii_digit())
    {
        return match back.parse::<usize>() {
            Ok(n) if n < snapshots.len() => Ok(&snapshots[snapshots.len() - 1 - n]),
            _ => Err(SnapshotError(format!(
                "only {} snapshot(s) stored; {r} is out of range",
                snapshots.len()
            ))),
        };
    }
    if let Some(s) = snapshots.iter().rev().find(|s| {
        s.sha
            .as_deref()
            .is_some_and(|sha| !sha.is_empty() && sha.starts_with(r))
    }) {
        return Ok(s);
    }
    if let Some(s) = snapshots.iter().rev().find(|s| s.timestamp.starts_with(r)) {
        return Ok(s);
    }
    Err(SnapshotError(format!(
        "no snapshot matches {} (use latest, ~N, a SHA prefix or a timestamp prefix)",
        py_str_repr(r)
    )))
}

pub struct Comparison {
    pub against: Snapshot,
    pub score_before: f64,
    pub score_after: f64,
    /// name -> (score before or `None` if the package is new, score after).
    pub packages: IndexMap<String, (Option<f64>, f64)>,
    pub introduced: Vec<SnapshotFinding>,
    pub fixed: Vec<SnapshotFinding>,
    /// (display path, penalty before, penalty after) where it increased, worst first.
    pub files_worse: Vec<(String, f64, f64)>,
    pub files_better: Vec<(String, f64, f64)>,
}

#[derive(Serialize)]
struct AgainstJson<'a> {
    sha: &'a Option<String>,
    timestamp: &'a str,
}

#[derive(Serialize)]
struct BeforeAfter {
    before: Option<f64>,
    after: f64,
}

#[derive(Serialize)]
struct FileDelta<'a> {
    file: &'a str,
    before: f64,
    after: f64,
}

/// `Comparison.to_json()` — the `compare` object of the JSON report.
#[derive(Serialize)]
pub struct ComparisonJson<'a> {
    against: AgainstJson<'a>,
    score_before: f64,
    score_after: f64,
    score_delta: f64,
    packages: IndexMap<&'a str, BeforeAfter>,
    introduced: &'a [SnapshotFinding],
    fixed: &'a [SnapshotFinding],
    files_worse: Vec<FileDelta<'a>>,
    files_better: Vec<FileDelta<'a>>,
}

impl Comparison {
    pub fn score_delta(&self) -> f64 {
        py_round(self.score_after - self.score_before, 1)
    }

    pub fn notes(&self) -> Vec<String> {
        let delta = self.score_delta();
        let sign = if delta >= 0.0 { "+" } else { "" };
        vec![format!(
            "Compared to {}: score {} \u{2192} {} ({sign}{}), {} finding(s) introduced, \
             {} fixed, {} file(s) worse",
            self.against.label(),
            py_float_repr(self.score_before),
            py_float_repr(self.score_after),
            py_float_repr(delta),
            self.introduced.len(),
            self.fixed.len(),
            self.files_worse.len()
        )]
    }

    pub fn to_json(&self) -> ComparisonJson<'_> {
        fn deltas(list: &[(String, f64, f64)]) -> Vec<FileDelta<'_>> {
            list.iter()
                .map(|(file, before, after)| FileDelta {
                    file,
                    before: *before,
                    after: *after,
                })
                .collect()
        }
        ComparisonJson {
            against: AgainstJson {
                sha: &self.against.sha,
                timestamp: &self.against.timestamp,
            },
            score_before: self.score_before,
            score_after: self.score_after,
            score_delta: self.score_delta(),
            packages: self
                .packages
                .iter()
                .map(|(name, (before, after))| {
                    (
                        name.as_str(),
                        BeforeAfter {
                            before: *before,
                            after: *after,
                        },
                    )
                })
                .collect(),
            introduced: &self.introduced,
            fixed: &self.fixed,
            files_worse: deltas(&self.files_worse),
            files_better: deltas(&self.files_better),
        }
    }
}

/// What changed between `against` and the current run — mirrors
/// `snapshots.py::compare`. Findings are matched by fingerprint, so a finding
/// that merely moved lines is neither introduced nor fixed.
pub fn compare(
    against: &Snapshot,
    current: &Snapshot,
    current_issues: &[Issue],
    workspace_root: Option<&Path>,
) -> Comparison {
    let old_fps: HashSet<&str> = against
        .findings
        .iter()
        .map(|f| f.fingerprint.as_str())
        .collect();
    let new_fps: HashSet<&str> = current
        .findings
        .iter()
        .map(|f| f.fingerprint.as_str())
        .collect();
    let introduced = current_issues
        .iter()
        .filter(|i| !old_fps.contains(i.fingerprint.as_str()))
        .map(|i| SnapshotFinding::from_issue(i, workspace_root))
        .collect();
    let fixed = against
        .findings
        .iter()
        .filter(|f| !new_fps.contains(f.fingerprint.as_str()))
        .cloned()
        .collect();
    let packages = current
        .scores
        .iter()
        .filter(|(name, _)| name.as_str() != "*")
        .map(|(name, score)| (name.clone(), (against.scores.get(name).copied(), *score)))
        .collect();
    let mut worse = Vec::new();
    let mut better = Vec::new();
    let paths: BTreeSet<&String> = against.files.keys().chain(current.files.keys()).collect();
    for path in paths {
        let before = against.files.get(path).copied().unwrap_or(0.0);
        let after = current.files.get(path).copied().unwrap_or(0.0);
        if after > before {
            worse.push((path.clone(), before, after));
        } else if after < before {
            better.push((path.clone(), before, after));
        }
    }
    worse.sort_by(|a: &(String, f64, f64), b| {
        (b.2 - b.1)
            .total_cmp(&(a.2 - a.1))
            .then_with(|| a.0.cmp(&b.0))
    });
    better.sort_by(|a: &(String, f64, f64), b| {
        (b.1 - b.2)
            .total_cmp(&(a.1 - a.2))
            .then_with(|| a.0.cmp(&b.0))
    });
    Comparison {
        against: against.clone(),
        score_before: against.scores.get("*").copied().unwrap_or(0.0),
        score_after: current.scores.get("*").copied().unwrap_or(0.0),
        packages,
        introduced,
        fixed,
        files_worse: worse,
        files_better: better,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(
        sha: Option<&str>,
        ts: &str,
        fps: &[&str],
        files: &[(&str, f64)],
        score: f64,
    ) -> Snapshot {
        Snapshot {
            timestamp: ts.to_string(),
            sha: sha.map(str::to_string),
            tool_version: "x".to_string(),
            scores: [("pkg".to_string(), score), ("*".to_string(), score)]
                .into_iter()
                .collect(),
            files: files.iter().map(|(f, p)| (f.to_string(), *p)).collect(),
            findings: fps
                .iter()
                .map(|fp| SnapshotFinding {
                    fingerprint: fp.to_string(),
                    rule: "r".to_string(),
                    severity: "warning".to_string(),
                    file: "a.py".to_string(),
                    line: 1,
                    message: "m".to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn iso_timestamp_matches_python_isoformat() {
        assert_eq!(iso_from_unix(0), "1970-01-01T00:00:00+00:00");
        assert_eq!(iso_from_unix(1_794_599_494), "2026-11-13T19:51:34+00:00");
        assert_eq!(iso_from_unix(951_782_400), "2000-02-29T00:00:00+00:00");
    }

    #[test]
    fn store_round_trips_and_lines_use_python_separators() {
        let s = snap(
            Some("abc"),
            "2026-11-13T00:00:00+00:00",
            &["f1"],
            &[("a.py", 1.5)],
            90.0,
        );
        let line = s.to_line();
        assert!(line.starts_with(
            r#"{"schema_version": 1, "timestamp": "2026-11-13T00:00:00+00:00", "sha": "abc""#
        ));
        assert!(line.contains(r#""scores": {"pkg": 90.0, "*": 90.0}"#));
        let back = Snapshot::from_json(&serde_json::from_str(&line).unwrap(), "x").unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn store_lines_split_on_newline_only_and_must_be_objects() {
        let dir = std::env::temp_dir().join(format!("spaghetti_rs_store_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("s.jsonl");
        let mut s = snap(Some("abc"), "t", &["f1"], &[("a\u{2028}b.py", 1.5)], 90.0);
        s.findings[0].message = "x\u{2029}y\u{85}z".to_string();
        append_snapshot(&store, &s).unwrap();
        assert_eq!(load_snapshots(&store).unwrap(), [s]);
        std::fs::write(&store, "[]\n").unwrap();
        let err = load_snapshots(&store).unwrap_err().0;
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            err.ends_with("s.jsonl:1: malformed snapshot (not an object)"),
            "{err}"
        );
    }

    #[test]
    fn find_snapshot_references() {
        let all = vec![
            snap(Some("aaa111"), "2026-10-01T00:00:00+00:00", &[], &[], 80.0),
            snap(None, "2026-11-01T00:00:00+00:00", &[], &[], 85.0),
            snap(Some("bbb222"), "2026-11-02T00:00:00+00:00", &[], &[], 90.0),
        ];
        assert_eq!(find_snapshot(&all, "latest").unwrap().scores["*"], 90.0);
        assert_eq!(find_snapshot(&all, "~1").unwrap().scores["*"], 85.0);
        assert_eq!(find_snapshot(&all, "aaa").unwrap().scores["*"], 80.0);
        assert_eq!(find_snapshot(&all, "2026-11").unwrap().scores["*"], 90.0);
        assert!(
            find_snapshot(&all, "~3")
                .unwrap_err()
                .0
                .contains("out of range")
        );
        assert!(
            find_snapshot(&all, "nope")
                .unwrap_err()
                .0
                .contains("no snapshot matches 'nope'")
        );
        assert!(
            find_snapshot(&[], "latest")
                .unwrap_err()
                .0
                .contains("store is empty")
        );
    }

    #[test]
    fn compare_matches_by_fingerprint_and_ranks_files() {
        let before = snap(
            Some("a"),
            "t1",
            &["keep", "gone"],
            &[("a.py", 3.0), ("b.py", 1.0)],
            80.0,
        );
        let after = snap(
            Some("b"),
            "t2",
            &["keep"],
            &[("a.py", 1.5), ("c.py", 6.0)],
            82.35,
        );
        let comp = compare(&before, &after, &[], None);
        assert_eq!(comp.fixed.len(), 1);
        assert_eq!(comp.fixed[0].fingerprint, "gone");
        assert_eq!(comp.files_worse, [("c.py".to_string(), 0.0, 6.0)]);
        assert_eq!(
            comp.files_better,
            [
                ("a.py".to_string(), 3.0, 1.5),
                ("b.py".to_string(), 1.0, 0.0)
            ]
        );
        assert_eq!(comp.score_delta(), 2.3);
        assert_eq!(
            comp.notes()[0],
            "Compared to a @ t1: score 80.0 \u{2192} 82.35 (+2.3), 0 finding(s) introduced, 1 fixed, 1 file(s) worse"
        );
    }
}
