//! `spaghetti mcp` — a Model Context Protocol server over stdio — mirrors
//! `spaghetti/mcp.py` reply for reply.
//!
//! Coding agents ask "what should I fix in this package and how" and get the
//! report, the remediation plan and the fix patterns as structured data. The
//! transport is MCP's stdio one (newline-delimited JSON-RPC 2.0), implemented
//! directly: the protocol surface a tool server needs is five methods.
//!
//! Every scan tool runs the CLI (this same binary) in a child process. That
//! keeps the long-lived server free of the process-global settings
//! `apply_settings` installs, so two calls with different projects cannot
//! leak into each other, and it is the same code path users run by hand.

use crate::config::thresholds;
use crate::json::{dumps_compact, dumps_pretty};
use crate::rule_docs::rule_doc;
use crate::rules::{RULE_CATALOG, rule_meta};
use crate::settings::kebab;
use crate::snapshots::py_value_repr;
use serde_json::{Map, Value, json};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub const PROTOCOL_VERSION: &str = "2025-06-18";

const INSTRUCTIONS: &str = "Call plan first: it ranks what to fix and includes the fix pattern per \
                            rule. Use explain_rule for the reasoning behind a rule and scan for the \
                            raw findings.";

/// The five tool definitions, exported verbatim from Python's `mcp.TOOLS`.
pub static TOOLS: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("mcp_tools.json")).expect("mcp_tools.json is valid JSON")
});

/// What a CLI run returned — `subprocess.CompletedProcess` minus `args`.
#[derive(Debug, Clone)]
pub struct CliOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Runs the CLI with `argv` in `cwd`; swappable in tests.
pub type Runner<'a> = &'a dyn Fn(&[String], &Path) -> Result<CliOutput, String>;

/// A tool call failed; the message is for the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolError(pub String);

fn tool_err<T>(message: impl Into<String>) -> Result<T, ToolError> {
    Err(ToolError(message.into()))
}

/// `[sys.executable, "-m", "spaghetti.detector", *argv]` — here, this binary.
pub fn run_cli(argv: &[String], cwd: &Path) -> Result<CliOutput, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let out = std::process::Command::new(exe)
        .args(argv)
        .current_dir(cwd)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(CliOutput {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Python truthiness of a decoded JSON value.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// Python's `str(value)`.
fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => py_value_repr(other),
    }
}

/// Python's `int(value)` for a decoded JSON value.
fn py_int(value: &Value) -> Result<i64, ToolError> {
    match value {
        Value::Bool(b) => Ok(i64::from(*b)),
        Value::Number(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) => Ok(i),
            (None, Some(f)) if f.is_finite() => Ok(f.trunc() as i64),
            _ => tool_err(format!("cannot convert {n} to an integer")),
        },
        Value::String(s) => s.trim().replace('_', "").parse::<i64>().or_else(|_| {
            tool_err(format!(
                "invalid literal for int() with base 10: {}",
                py_value_repr(value)
            ))
        }),
        other => tool_err(format!(
            "int() argument must be a string or a number, not {}",
            py_value_repr(other)
        )),
    }
}

/// The last line of `text.strip()`, or `None` when it is blank.
fn last_line(text: &str) -> Option<String> {
    text.trim().lines().last().map(str::to_string)
}

fn common_argv(args: &Map<String, Value>) -> Result<(Vec<String>, PathBuf), ToolError> {
    let cwd = match args.get("path") {
        Some(p) if truthy(Some(p)) => PathBuf::from(py_str(p)),
        _ => std::env::current_dir().map_err(|e| ToolError(e.to_string()))?,
    };
    if !cwd.is_dir() {
        return tool_err(format!("path is not a directory: {}", cwd.display()));
    }
    let mut argv = vec!["--fail-on".to_string(), "never".to_string()];
    let packages = args.get("packages");
    if truthy(packages) {
        let Some(packages) = packages.and_then(Value::as_object) else {
            return tool_err("packages must be an object of {name: path}");
        };
        for (name, path) in packages {
            argv.push("--package".to_string());
            argv.push(format!("{name}={}", py_str(path)));
        }
    }
    Ok((argv, cwd))
}

fn json_from(proc: &CliOutput) -> Result<Value, ToolError> {
    if proc.code == 2 && proc.stdout.trim().is_empty() {
        return tool_err(last_line(&proc.stderr).unwrap_or_else(|| "usage error".to_string()));
    }
    serde_json::from_str(&proc.stdout).or_else(|_| {
        let stderr: Vec<char> = proc.stderr.trim().chars().collect();
        let tail: String = stderr[stderr.len().saturating_sub(500)..].iter().collect();
        tool_err(format!("spaghetti produced no JSON report: {tail}"))
    })
}

fn run(runner: Runner<'_>, argv: &[String], cwd: &Path) -> Result<CliOutput, ToolError> {
    runner(argv, cwd).map_err(ToolError)
}

fn required<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a Value, ToolError> {
    args.get(key)
        .ok_or_else(|| ToolError(format!("missing required argument '{key}'")))
}

pub fn explain_rule(rule: &str) -> Result<Value, ToolError> {
    let Some(meta) = rule_meta(rule) else {
        let mut known: Vec<&str> = RULE_CATALOG.iter().map(|r| r.id).collect();
        known.sort_unstable();
        return tool_err(format!(
            "unknown rule '{rule}'; known: {}",
            known.join(", ")
        ));
    };
    let doc = rule_doc(rule).ok_or_else(|| ToolError(format!("no documentation for '{rule}'")))?;
    let live = thresholds();
    let mut limits = Map::new();
    for name in doc.thresholds {
        let key = if crate::config::threshold_kind(name).is_some() {
            kebab(name)
        } else {
            name.to_string()
        };
        let value = match live.get(name) {
            Some(crate::config::ThresholdValue::Int(i)) => json!(i),
            Some(crate::config::ThresholdValue::Float(f)) => json!(f),
            None => Value::Null,
        };
        limits.insert(key, value);
    }
    Ok(json!({
        "id": meta.id,
        "summary": meta.summary,
        "default_severity": meta.default_severity.as_str(),
        "tier": meta.tier.as_str(),
        "enabled_by_default": meta.enabled_by_default,
        "why": doc.why,
        "fix": doc.fix,
        "equivalents": doc.equivalents,
        "thresholds": limits,
        "suppress": format!("# spaghetti-ignore[{}]: reason", meta.id),
    }))
}

fn scan(args: &Map<String, Value>, runner: Runner<'_>) -> Result<Value, ToolError> {
    let (mut argv, cwd) = common_argv(args)?;
    argv.push("--json".to_string());
    if truthy(args.get("severity")) {
        argv.push("--severity".to_string());
        argv.push(py_str(&args["severity"]));
    }
    json_from(&run(runner, &argv, &cwd)?)
}

fn plan(args: &Map<String, Value>, runner: Runner<'_>) -> Result<Value, ToolError> {
    let (mut argv, cwd) = common_argv(args)?;
    argv.extend(["--plan".to_string(), "--json".to_string()]);
    if truthy(args.get("top")) {
        argv.push("--top".to_string());
        argv.push(py_int(&args["top"])?.to_string());
    }
    if truthy(args.get("hotspots")) {
        argv.push("--hotspots".to_string());
    }
    json_from(&run(runner, &argv, &cwd)?)
}

fn compare(args: &Map<String, Value>, runner: Runner<'_>) -> Result<Value, ToolError> {
    let (mut argv, cwd) = common_argv(args)?;
    let reference = py_str(required(args, "ref")?);
    argv.extend(["--json".to_string(), "--compare".to_string(), reference]);
    if truthy(args.get("store")) {
        argv.push("--snapshot-store".to_string());
        argv.push(py_str(&args["store"]));
    }
    let report = json_from(&run(runner, &argv, &cwd)?)?;
    report
        .get("compare")
        .cloned()
        .ok_or_else(|| ToolError("the report has no 'compare' object".to_string()))
}

fn baseline(args: &Map<String, Value>, runner: Runner<'_>) -> Result<Value, ToolError> {
    let (mut argv, cwd) = common_argv(args)?;
    if truthy(args.get("baseline")) {
        argv.push("--baseline".to_string());
        argv.push(py_str(&args["baseline"]));
    }
    if required(args, "action")?.as_str() == Some("update") {
        argv.push("--update-baseline".to_string());
        let proc = run(runner, &argv, &cwd)?;
        if proc.code != 0 {
            return tool_err(last_line(&proc.stderr).unwrap_or_else(|| "failed".to_string()));
        }
        return Ok(json!({
            "updated": true,
            "message": last_line(&proc.stderr).unwrap_or_default(),
        }));
    }
    argv.push("--json".to_string());
    let report = json_from(&run(runner, &argv, &cwd)?)?;
    let new_findings = report
        .get("issues")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    Ok(json!({
        "baseline": report.get("baseline").cloned().unwrap_or(Value::Null),
        "new_findings": new_findings,
    }))
}

pub fn call_tool(
    name: &str,
    args: &Map<String, Value>,
    runner: Runner<'_>,
) -> Result<Value, ToolError> {
    match name {
        "explain_rule" => explain_rule(&args.get("rule").map(py_str).unwrap_or_default()),
        "scan" => scan(args, runner),
        "plan" => plan(args, runner),
        "compare" => compare(args, runner),
        "baseline" => baseline(args, runner),
        _ => tool_err(format!("unknown tool '{name}'")),
    }
}

// ── JSON-RPC over stdio ───────────────────────────────────────────────────────

fn result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn tool_result(name: &str, args: &Map<String, Value>, runner: Runner<'_>) -> Value {
    match call_tool(name, args, runner) {
        Ok(payload) => json!({
            "content": [{"type": "text", "text": dumps_pretty(&payload)}],
            "structuredContent": payload,
        }),
        Err(ToolError(message)) => json!({
            "content": [{"type": "text", "text": message}],
            "isError": true,
        }),
    }
}

/// One request → one response; notifications → `None`.
pub fn handle(message: &Value, version: &str, runner: Runner<'_>) -> Option<Value> {
    let Some(message) = message.as_object() else {
        // Python raises AttributeError here and the server dies; answer instead.
        return Some(error(Value::Null, -32600, "not a request"));
    };
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let method = match message.get("method") {
        None | Some(Value::Null) => return Some(error(id, -32600, "not a request")),
        Some(Value::String(m)) => m.as_str(),
        // Python raises on `.startswith` of a non-string; answer instead.
        Some(_) => return Some(error(id, -32600, "not a request")),
    };
    if method.starts_with("notifications/") {
        return None;
    }
    let empty = Map::new();
    let params = match message.get("params") {
        Some(Value::Object(p)) => p,
        _ => &empty,
    };
    Some(match method {
        "initialize" => result(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "spaghetti", "version": version},
                "instructions": INSTRUCTIONS,
            }),
        ),
        "ping" => result(id, json!({})),
        "tools/list" => result(id, json!({"tools": *TOOLS})),
        "tools/call" => {
            let malformed_params = truthy(message.get("params")) && !message["params"].is_object();
            let name = params.get("name").and_then(Value::as_str);
            let args = if truthy(params.get("arguments")) {
                params.get("arguments").and_then(Value::as_object)
            } else {
                Some(&empty)
            };
            match (name, args) {
                (Some(name), Some(args)) if !malformed_params => {
                    result(id, tool_result(name, args, runner))
                }
                _ => error(
                    id,
                    -32602,
                    "tools/call needs a name and an arguments object",
                ),
            }
        }
        other => error(id, -32601, &format!("method not found: {other}")),
    })
}

/// Serve until EOF. Every request gets exactly one reply line.
pub fn serve(
    stdin: impl BufRead,
    mut stdout: impl Write,
    version: &str,
    runner: Runner<'_>,
) -> i32 {
    for line in stdin.split(b'\n') {
        let Ok(line) = line else { break };
        let line = String::from_utf8_lossy(&line);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(line) {
            Ok(message) => handle(&message, version, runner),
            Err(_) => Some(error(Value::Null, -32700, "parse error")),
        };
        if let Some(response) = response {
            let _ = writeln!(stdout, "{}", dumps_compact(&response, true));
            let _ = stdout.flush();
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_run(_: &[String], _: &Path) -> Result<CliOutput, String> {
        panic!("no CLI run expected")
    }

    #[test]
    fn explain_rule_bundles_catalog_docs_and_live_thresholds() {
        let info = explain_rule("high-complexity").unwrap();
        assert_eq!(info["default_severity"], "warning");
        assert_eq!(info["tier"], "ast");
        assert_eq!(info["thresholds"], json!({"complexity-threshold": 10}));
        assert!(info["fix"].as_str().unwrap().contains("dispatch table"));
        assert!(
            info["equivalents"]
                .as_array()
                .unwrap()
                .contains(&json!("Ruff C901 (mccabe)"))
        );
        assert_eq!(
            info["suppress"],
            "# spaghetti-ignore[high-complexity]: reason"
        );
        for rule in RULE_CATALOG {
            assert_eq!(explain_rule(rule.id).unwrap()["id"], rule.id);
        }
    }

    #[test]
    fn handle_initialize_list_and_errors() {
        let init = handle(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            "9",
            &no_run,
        )
        .unwrap();
        assert_eq!(init["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(
            init["result"]["serverInfo"],
            json!({"name": "spaghetti", "version": "9"})
        );
        assert!(
            handle(
                &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                "9",
                &no_run
            )
            .is_none()
        );
        let listed = handle(
            &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            "9",
            &no_run,
        )
        .unwrap();
        let names: Vec<&str> = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            ["scan", "plan", "explain_rule", "compare", "baseline"]
        );
        let missing = handle(
            &json!({"jsonrpc": "2.0", "id": 3, "method": "resources/list"}),
            "9",
            &no_run,
        )
        .unwrap();
        assert_eq!(missing["error"]["code"], -32601);
        let bad = handle(
            &json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                    "params": {"name": "explain_rule", "arguments": {"rule": "nope"}}}),
            "9",
            &no_run,
        )
        .unwrap();
        assert_eq!(bad["result"]["isError"], true);
        assert!(
            bad["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("unknown rule")
        );
        let not_object = handle(&json!([1]), "9", &no_run).unwrap();
        assert_eq!(not_object["error"]["code"], -32600);
    }

    #[test]
    fn plan_tool_builds_the_cli_invocation() {
        let dir = std::env::temp_dir();
        let seen = std::cell::RefCell::new(Vec::new());
        let fake = |argv: &[String], cwd: &Path| -> Result<CliOutput, String> {
            assert_eq!(cwd, dir.as_path());
            seen.borrow_mut().push(argv.to_vec());
            Ok(CliOutput {
                code: 0,
                stdout: r#"{"plan": [], "issues": []}"#.to_string(),
                stderr: String::new(),
            })
        };
        let args = json!({"path": dir.display().to_string(), "packages": {"p": "src/p"},
                          "top": 3, "hotspots": true});
        let out = call_tool("plan", args.as_object().unwrap(), &fake).unwrap();
        assert_eq!(out, json!({"plan": [], "issues": []}));
        assert_eq!(
            *seen.borrow(),
            [[
                "--fail-on",
                "never",
                "--package",
                "p=src/p",
                "--plan",
                "--json",
                "--top",
                "3",
                "--hotspots"
            ]
            .map(String::from)
            .to_vec()]
        );
    }

    #[test]
    fn reply_lines_use_python_json_dumps_defaults() {
        let mut out = Vec::new();
        serve(
            "{\"jsonrpc\": \"2.0\", \"id\": 7, \"method\": \"ping\"}\nnot json\n\n".as_bytes(),
            &mut out,
            "9",
            &no_run,
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "{\"jsonrpc\": \"2.0\", \"id\": 7, \"result\": {}}\n\
             {\"jsonrpc\": \"2.0\", \"id\": null, \"error\": {\"code\": -32700, \"message\": \"parse error\"}}\n"
        );
    }
}
