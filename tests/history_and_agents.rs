//! End-to-end tests for the Phase 3 (snapshots, --compare, hotspots, HTML)
//! and Phase 4 (contracts, `--plan --json`, `spaghetti mcp`) features —
//! ports of the Python original's `tests/test_cli.py` Phase 3 block,
//! `tests/test_contracts.py` and `tests/test_mcp.py::test_stdio_server_end_to_end`.

use serde_json::Value;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("spaghetti_rs_p34_{}_{tag}_{n}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir.canonicalize().unwrap()
}

fn run(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_spaghetti"))
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("failed to run spaghetti binary")
}

fn git(cwd: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git")
        .status
        .success();
    assert!(ok, "git {args:?}");
}

/// A git repo with a pyproject `[tool.spaghetti]` table and one messy package.
fn project() -> PathBuf {
    let root = temp_dir("proj");
    std::fs::create_dir_all(root.join("src/mylib")).unwrap();
    std::fs::write(
        root.join("pyproject.toml"),
        "[tool.spaghetti]\n[tool.spaghetti.packages]\nmylib = \"src/mylib\"\n\
         [tool.spaghetti.rules]\nmissing-param-type = \"off\"\nmissing-return-type = \"off\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/mylib/m.py"),
        "def f(a, b, c, d, e, f, g, h):\n    return a\n",
    )
    .unwrap();
    git(&root, &["init", "-q"]);
    git(&root, &["config", "user.email", "t@example.com"]);
    git(&root, &["config", "user.name", "T"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-qm", "init"]);
    root
}

fn json_of(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn snapshot_then_compare_reports_the_introduced_finding() {
    let root = project();
    let store = root.join(".spaghetti/snapshots.jsonl");
    let store_arg = store.display().to_string();
    let out = run(
        &root,
        &[
            "--snapshot",
            "--snapshot-store",
            &store_arg,
            "--fail-on",
            "never",
        ],
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("appended to"));
    assert_eq!(std::fs::read_to_string(&store).unwrap().lines().count(), 1);
    std::fs::write(
        root.join("src/mylib/extra.py"),
        "def g(a, b, c, d, e, f, g, h):\n    return a\n",
    )
    .unwrap();
    let out = run(
        &root,
        &[
            "--compare",
            "latest",
            "--snapshot-store",
            &store_arg,
            "--fail-on",
            "never",
            "--json",
        ],
    );
    let report = json_of(&out);
    let compare = &report["compare"];
    let rules: Vec<&str> = compare["introduced"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["rule"].as_str().unwrap())
        .collect();
    assert_eq!(rules, ["too-many-params"]);
    assert_eq!(compare["fixed"], Value::Array(vec![]));
    assert!(
        compare["files_worse"][0]["file"]
            .as_str()
            .unwrap()
            .ends_with("extra.py")
    );
    let (before, after) = (
        compare["score_before"].as_f64().unwrap(),
        compare["score_after"].as_f64().unwrap(),
    );
    let delta: f64 = format!("{:.1}", after - before).parse().unwrap();
    assert_eq!(compare["score_delta"].as_f64().unwrap(), delta);
    // Absent, not null, when not asked for.
    assert!(report.get("hotspots").is_none() && report.get("plan").is_none());
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn compare_with_an_empty_store_is_a_usage_error() {
    let root = project();
    let out = run(&root, &["--compare", "nope", "--fail-on", "never"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("snapshot store is empty"));
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn hotspots_rank_and_weight_the_plan() {
    let root = project();
    let report = json_of(&run(&root, &["--hotspots", "--fail-on", "never", "--json"]));
    let hotspots = &report["hotspots"];
    assert_eq!(hotspots["months"], 6);
    assert!(hotspots["files"][0]["commits"].as_u64().unwrap() >= 1);
    let plan = run(&root, &["--hotspots", "--plan", "--fail-on", "never"]);
    assert!(String::from_utf8_lossy(&plan.stdout).contains("Weighted by git change frequency"));
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn html_format_writes_a_single_page_with_trend() {
    let root = project();
    let store = root.join("snap.jsonl").display().to_string();
    for _ in 0..3 {
        run(
            &root,
            &[
                "--snapshot",
                "--snapshot-store",
                &store,
                "--fail-on",
                "never",
                "--quiet",
            ],
        );
    }
    let out = run(
        &root,
        &[
            "--format",
            "html",
            "--snapshot-store",
            &store,
            "--fail-on",
            "never",
        ],
    );
    let page = String::from_utf8_lossy(&out.stdout);
    assert!(page.starts_with("<!DOCTYPE html>"));
    assert!(page.contains("aria-label=\"4 snapshot(s)\""));
    assert!(page.contains("<h2>Findings"));
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn plan_json_carries_the_fix_pattern() {
    let root = project();
    let report = json_of(&run(&root, &["--plan", "--json", "--fail-on", "never"]));
    let step = &report["plan"][0];
    assert_eq!(step["rule"], "too-many-params");
    assert_eq!(step["severity"], "warning");
    assert!(step["fix"].as_str().unwrap().contains("Parameter Object"));
    assert!(report["issues"].is_array());
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn contract_violation_reported_from_the_workspace_pass() {
    let root = temp_dir("contracts");
    let shop = root.join("shop");
    std::fs::create_dir_all(shop.join("domain")).unwrap();
    std::fs::create_dir_all(shop.join("transport")).unwrap();
    for init in ["__init__.py", "domain/__init__.py", "transport/__init__.py"] {
        std::fs::write(shop.join(init), "").unwrap();
    }
    std::fs::write(
        shop.join("domain/order.py"),
        "import json\nfrom shop.transport.http import Client\nfrom fastapi import FastAPI\n",
    )
    .unwrap();
    std::fs::write(
        shop.join("transport/http.py"),
        "from shop.domain.order import Order\n",
    )
    .unwrap();
    std::fs::write(
        root.join("pyproject.toml"),
        r#"[tool.spaghetti.packages]
shop = "shop"

[[tool.spaghetti.contracts]]
name = "domain stays framework-free"
type = "forbidden"
source = ["shop.domain"]
forbidden = ["shop.transport", "fastapi"]

[[tool.spaghetti.contracts]]
name = "layering"
type = "layers"
layers = ["shop.transport", "shop.domain"]
"#,
    )
    .unwrap();
    let report = json_of(&run(&root, &["--json", "--fail-on", "never"]));
    let violations: Vec<&Value> = report["issues"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["rule"] == "contract-violation")
        .collect();
    let located: Vec<(String, u64)> = violations
        .iter()
        .map(|i| {
            let file = i["file"].as_str().unwrap();
            (
                file.rsplit('/').next().unwrap().to_string(),
                i["line"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        located,
        [
            ("order.py".to_string(), 2),
            ("order.py".to_string(), 2),
            ("order.py".to_string(), 3)
        ]
    );
    let message = |n: usize| violations[n]["message"].as_str().unwrap();
    assert!(message(0).contains(
        "Contract 'domain stays framework-free': shop.domain.order imports shop.transport.http"
    ));
    assert!(
        message(1)
            .contains("layer 'shop.domain' may not depend on the higher layer 'shop.transport'")
    );
    assert!(
        violations
            .iter()
            .all(|i| i["severity"] == "error" && !i["fingerprint"].as_str().unwrap().is_empty())
    );

    std::fs::write(
        root.join("pyproject.toml"),
        "[[tool.spaghetti.contracts]]\nname = \"a\"\n",
    )
    .unwrap();
    let out = run(&root, &["--json"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("contracts[1]: type must be one of"));
    std::fs::remove_dir_all(&root).ok();
}

fn rpc(id: u64, method: &str, params: Value) -> String {
    serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}

#[test]
fn stdio_server_end_to_end() {
    let root = temp_dir("mcp");
    std::fs::create_dir_all(root.join("src/pkg")).unwrap();
    std::fs::write(
        root.join("src/pkg/m.py"),
        "def f(a, b, c, d, e, f, g, h):\n    return a\n",
    )
    .unwrap();
    let path = root.display().to_string();
    let requests = [
        rpc(
            1,
            "initialize",
            serde_json::json!({"protocolVersion": "2025-06-18", "capabilities": {}}),
        ),
        r#"{"jsonrpc": "2.0", "method": "notifications/initialized"}"#.to_string(),
        rpc(
            2,
            "tools/call",
            serde_json::json!({"name": "plan",
                               "arguments": {"path": path, "packages": {"pkg": "src/pkg"}}}),
        ),
        rpc(
            3,
            "tools/call",
            serde_json::json!({"name": "explain_rule", "arguments": {"rule": "too-many-params"}}),
        ),
        "not json".to_string(),
    ]
    .join("\n");
    let mut child = Command::new(env!("CARGO_BIN_EXE_spaghetti"))
        .arg("mcp")
        .current_dir(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{requests}\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let replies: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let ids: Vec<Value> = replies.iter().map(|r| r["id"].clone()).collect();
    assert_eq!(ids, [1.into(), 2.into(), 3.into(), Value::Null]);
    let plan = &replies[1]["result"]["structuredContent"];
    let step = &plan["plan"][0];
    assert_eq!(step["rule"], "too-many-params");
    assert_eq!(step["severity"], "warning");
    assert!(step["files"][0].as_str().unwrap().ends_with("src/pkg/m.py"));
    assert!(step["fix"].as_str().unwrap().contains("Parameter Object"));
    assert_eq!(plan["issues"][0]["line"], 1);
    assert_eq!(
        replies[2]["result"]["structuredContent"]["id"],
        "too-many-params"
    );
    assert_eq!(replies[3]["error"]["code"], -32700);
    std::fs::remove_dir_all(&root).ok();
}
