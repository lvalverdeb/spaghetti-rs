//! SARIF 2.1.0 output (`--format sarif`) — mirrors `spaghetti/sarif.py`.
//!
//! One run, one tool (`spaghetti`), one result per finding. Findings silenced
//! by an inline `# spaghetti-ignore` marker are emitted as suppressed results
//! so reviewers can still see them; findings matched by a baseline carry
//! `baselineState: "unchanged"` and the rest `"new"` when a baseline is in
//! use. File URIs are relative to the working directory under `%SRCROOT%`.
//!
//! Field order in every struct is the Python dict's insertion order, so the
//! serialized document is byte-identical.

use crate::models::{Issue, Severity};
use crate::rules::RULE_CATALOG;
use serde::Serialize;
use std::path::{Component, Path};

pub const SARIF_VERSION: &str = "2.1.0";
pub const SARIF_SCHEMA: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";
pub const INFORMATION_URI: &str = "https://github.com/lvalverdeb/spaghetti";
pub const FINGERPRINT_KEY: &str = "spaghetti/v1";

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

#[derive(Serialize)]
struct Text {
    text: String,
}

#[derive(Serialize)]
struct Level {
    level: &'static str,
}

#[derive(Serialize)]
struct RuleProperties {
    tier: &'static str,
}

#[derive(Serialize)]
struct Rule {
    id: &'static str,
    #[serde(rename = "shortDescription")]
    short_description: Text,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: Level,
    properties: RuleProperties,
}

#[derive(Serialize)]
struct Driver {
    name: &'static str,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<Rule>,
}

#[derive(Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Serialize)]
struct Uri {
    uri: String,
}

#[derive(Serialize)]
struct OriginalUriBaseIds {
    #[serde(rename = "%SRCROOT%")]
    srcroot: Uri,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
    #[serde(rename = "uriBaseId")]
    uri_base_id: &'static str,
}

#[derive(Serialize)]
struct Region {
    #[serde(rename = "startLine")]
    start_line: usize,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    start_column: Option<usize>,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    end_line: Option<usize>,
    #[serde(rename = "endColumn", skip_serializing_if = "Option::is_none")]
    end_column: Option<usize>,
}

#[derive(Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Serialize)]
struct Location {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
struct PartialFingerprints {
    #[serde(rename = "spaghetti/v1")]
    v1: String,
}

#[derive(Serialize)]
struct ResultProperties {
    package: String,
}

#[derive(Serialize)]
struct Suppression {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    justification: Option<String>,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: &'static str,
    level: &'static str,
    message: Text,
    locations: Vec<Location>,
    #[serde(rename = "partialFingerprints")]
    partial_fingerprints: PartialFingerprints,
    properties: ResultProperties,
    #[serde(rename = "baselineState", skip_serializing_if = "Option::is_none")]
    baseline_state: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suppressions: Option<Vec<Suppression>>,
}

#[derive(Serialize)]
struct Run {
    tool: Tool,
    #[serde(rename = "originalUriBaseIds")]
    original_uri_base_ids: OriginalUriBaseIds,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
pub struct SarifDocument {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Run>,
}

fn rules_component() -> Vec<Rule> {
    RULE_CATALOG
        .iter()
        .filter(|meta| meta.enabled_by_default)
        .map(|meta| Rule {
            id: meta.id,
            short_description: Text {
                text: meta.summary.to_string(),
            },
            default_configuration: Level {
                level: level(meta.default_severity),
            },
            properties: RuleProperties {
                tier: meta.tier.as_str(),
            },
        })
        .collect()
}

fn posix(path: &Path) -> String {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            Component::ParentDir => Some("..".to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// `os.path.relpath(path, start)` for two absolute paths.
fn relpath(path: &Path, start: &Path) -> String {
    let p: Vec<_> = path.components().collect();
    let s: Vec<_> = start.components().collect();
    let common = p.iter().zip(&s).take_while(|(a, b)| a == b).count();
    let mut parts: Vec<String> = vec!["..".to_string(); s.len() - common];
    parts.extend(
        p[common..]
            .iter()
            .map(|c| c.as_os_str().to_string_lossy().into_owned()),
    );
    if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}

/// `path.resolve().relative_to(root).as_posix()`, falling back to
/// `os.path.relpath` when the file lives outside `root`.
fn relative_uri(path: &Path, root: &Path) -> String {
    let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    match resolved.strip_prefix(root) {
        Ok(rel) => posix(rel),
        Err(_) => relpath(path, root),
    }
}

/// `pathlib.Path.as_uri()`: `file://` plus the path percent-encoded the way
/// `urllib.parse.quote` does with its default `safe="/"`.
pub fn file_uri(path: &Path) -> String {
    const UNRESERVED: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~/";
    let mut out = String::from("file://");
    for byte in path.to_string_lossy().as_bytes() {
        if UNRESERVED.contains(byte) {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn result(issue: &Issue, root: &Path, baseline_state: Option<&'static str>) -> SarifResult {
    SarifResult {
        rule_id: issue.rule,
        level: level(issue.severity),
        message: Text {
            text: issue.message.clone(),
        },
        locations: vec![Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: relative_uri(&issue.file, root),
                    uri_base_id: "%SRCROOT%",
                },
                region: Region {
                    start_line: issue.line,
                    start_column: issue.column,
                    end_line: issue.end_line,
                    end_column: issue.end_column,
                },
            },
        }],
        partial_fingerprints: PartialFingerprints {
            v1: issue.fingerprint.clone(),
        },
        properties: ResultProperties {
            package: issue.package.clone(),
        },
        baseline_state,
        suppressions: None,
    }
}

/// Mirrors `sarif.py::build_sarif`.
pub fn build_sarif(
    new: &[&Issue],
    known: &[Issue],
    ignored: &[Issue],
    tool_version: &str,
    root: &Path,
    baseline_used: bool,
) -> SarifDocument {
    let mut results = Vec::with_capacity(new.len() + known.len() + ignored.len());
    for issue in new {
        results.push(result(issue, root, baseline_used.then_some("new")));
    }
    for issue in known {
        results.push(result(issue, root, Some("unchanged")));
    }
    for issue in ignored {
        let mut suppressed = result(issue, root, None);
        suppressed.suppressions = Some(vec![Suppression {
            kind: "inSource",
            justification: issue.reason.clone().filter(|r| !r.is_empty()),
        }]);
        results.push(suppressed);
    }
    let resolved_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    SarifDocument {
        schema: SARIF_SCHEMA,
        version: SARIF_VERSION,
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "spaghetti",
                    version: tool_version.to_string(),
                    information_uri: INFORMATION_URI,
                    rules: rules_component(),
                },
            },
            original_uri_base_ids: OriginalUriBaseIds {
                srcroot: Uri {
                    uri: file_uri(&resolved_root) + "/",
                },
            },
            results,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn issue(root: &Path) -> Issue {
        let mut i = Issue::new(
            &root.join("src/m.py"),
            3,
            Severity::Warning,
            "long-function",
            "pkg",
            "f() is long".into(),
        );
        i.column = Some(5);
        i.end_line = Some(4);
        i.end_column = Some(9);
        i.fingerprint = "0123456789abcdef".into();
        i
    }

    #[test]
    fn build_sarif_structure() {
        let root = Path::new("/nonexistent/root");
        let new = issue(root);
        let mut known = issue(root);
        known.fingerprint = "1111111111111111".into();
        known.rule = "god-class";
        known.severity = Severity::Error;
        let mut ignored = issue(root);
        ignored.fingerprint = "2222222222222222".into();
        ignored.severity = Severity::Info;
        ignored.reason = Some("ok".into());
        let doc = build_sarif(&[&new], &[known], &[ignored], "9.9.9", root, true);
        let v: Value = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let run = &v["runs"][0];
        let driver = &run["tool"]["driver"];
        assert_eq!(driver["name"], "spaghetti");
        assert_eq!(driver["version"], "9.9.9");
        assert_eq!(driver["rules"].as_array().unwrap().len(), 37);
        assert_eq!(
            run["originalUriBaseIds"]["%SRCROOT%"]["uri"],
            "file:///nonexistent/root/"
        );
        let results = run["results"].as_array().unwrap();
        let loc = &results[0]["locations"][0]["physicalLocation"];
        assert_eq!(
            loc["artifactLocation"],
            serde_json::json!({"uri": "src/m.py", "uriBaseId": "%SRCROOT%"})
        );
        assert_eq!(
            loc["region"],
            serde_json::json!({"startLine": 3, "startColumn": 5, "endLine": 4, "endColumn": 9})
        );
        assert_eq!(results[0]["level"], "warning");
        assert_eq!(results[0]["baselineState"], "new");
        assert_eq!(
            results[0]["partialFingerprints"],
            serde_json::json!({"spaghetti/v1": "0123456789abcdef"})
        );
        assert_eq!(results[1]["level"], "error");
        assert_eq!(results[1]["baselineState"], "unchanged");
        assert_eq!(results[2]["level"], "note");
        assert_eq!(
            results[2]["suppressions"],
            serde_json::json!([{"kind": "inSource", "justification": "ok"}])
        );
        assert!(results[2].get("baselineState").is_none());
        // Key order follows the Python dict.
        let keys: Vec<&String> = results[0].as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "ruleId",
                "level",
                "message",
                "locations",
                "partialFingerprints",
                "properties",
                "baselineState"
            ]
        );
    }

    #[test]
    fn omits_baseline_state_and_null_columns_without_them() {
        let root = Path::new("/nonexistent/root");
        let mut i = issue(root);
        i.column = None;
        i.end_line = None;
        i.end_column = None;
        let doc = build_sarif(&[&i], &[], &[], "0", root, false);
        let v: Value = serde_json::to_value(&doc).unwrap();
        let result = &v["runs"][0]["results"][0];
        assert!(result.get("baselineState").is_none());
        assert_eq!(
            result["locations"][0]["physicalLocation"]["region"],
            serde_json::json!({"startLine": 3})
        );
    }

    #[test]
    fn file_uri_percent_encodes_like_pathlib() {
        assert_eq!(file_uri(Path::new("/a b/ü")), "file:///a%20b/%C3%BC");
        assert_eq!(relpath(Path::new("/a/b/c"), Path::new("/a/x")), "../b/c");
    }
}
