//! End-to-end CLI tests that exercise the compiled binary directly, the same
//! way `spaghetti/tests/test_detector.py`'s `test_cli_json_output_is_well_formed`
//! does for the Python original via `subprocess.run`.

use std::process::Command;

fn spaghetti_bin() -> &'static str {
    env!("CARGO_BIN_EXE_spaghetti")
}

#[test]
fn errors_on_nonexistent_package_path() {
    // Regression test: a --package NAME=PATH pointing at a path that
    // doesn't exist (e.g. a typo, or a relative PATH resolved against the
    // wrong cwd — the real-world case that surfaced this in the Python
    // original: `--package boti-dask=src/boti_dask` run from the workspace
    // root instead of from inside boti-dask/) used to scan silently to an
    // empty, "clean" 0-issues result instead of erroring — indistinguishable
    // from a genuinely clean package that actually got scanned. Same fix as
    // the Python port (spaghetti/src/spaghetti/cli.py).
    let tmp = std::env::temp_dir().join(format!("spaghetti_rs_test_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();

    let output = Command::new(spaghetti_bin())
        .args([
            "--package",
            "fake_pkg=does-not-exist-on-disk",
            "--severity",
            "info",
        ])
        .current_dir(&tmp)
        .output()
        .expect("failed to run spaghetti binary");

    std::fs::remove_dir_all(&tmp).ok();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("package path(s) do not exist"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn scans_real_existing_package_successfully() {
    let tmp = std::env::temp_dir().join(format!("spaghetti_rs_test_ok_{}", std::process::id()));
    let pkg_dir = tmp.join("fake_pkg");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("messy.py"),
        "def f():\n    try:\n        pass\n    except:\n        pass\n",
    )
    .unwrap();

    let output = Command::new(spaghetti_bin())
        .args([
            "--package",
            "fake_pkg=fake_pkg",
            "--json",
            "--severity",
            "info",
        ])
        .current_dir(&tmp)
        .output()
        .expect("failed to run spaghetti binary");

    std::fs::remove_dir_all(&tmp).ok();

    assert!(output.status.success() || output.status.code() == Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bare-except"),
        "unexpected stdout: {stdout}"
    );
}

#[test]
fn suppressed_issue_reason_appears_in_json_output() {
    // Mirrors Python's test_suppression_marker_on_flagged_line, but checks
    // the `ignored` JSON array (spaghetti/cli.py's counterpart) carries the
    // human-supplied reason through instead of just being silently dropped.
    let tmp = std::env::temp_dir().join(format!("spaghetti_rs_test_reason_{}", std::process::id()));
    let pkg_dir = tmp.join("fake_pkg");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("messy.py"),
        "def f():\n    try:\n        pass\n    except:  # spaghetti-ignore[bare-except]: intentional catch-all\n        pass\n",
    )
    .unwrap();

    let output = Command::new(spaghetti_bin())
        .args([
            "--package",
            "fake_pkg=fake_pkg",
            "--json",
            "--severity",
            "info",
        ])
        .current_dir(&tmp)
        .output()
        .expect("failed to run spaghetti binary");

    std::fs::remove_dir_all(&tmp).ok();

    assert!(output.status.success() || output.status.code() == Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    let active_issues = parsed["issues"].as_array().expect("issues array");
    assert!(
        !active_issues.iter().any(|i| i["rule"] == "bare-except"),
        "bare-except must not appear in the active issues list: {stdout}"
    );
    let ignored = parsed["ignored"].as_array().expect("ignored array");
    assert_eq!(ignored.len(), 1, "unexpected ignored array: {ignored:?}");
    assert_eq!(ignored[0]["rule"], "bare-except");
    assert_eq!(ignored[0]["reason"], "intentional catch-all");
}

#[test]
fn bare_invocation_discovers_cwd_and_never_scans_boti() {
    // End-to-end: `spaghetti` with zero flags, run from a tmp cwd containing
    // its own subpackage plus a loose root script, must scan exactly that —
    // never the workspace's real boti/boti-data/boti-dask registry. Mirrors
    // Python's test_main_bare_invocation_discovers_cwd_and_never_scans_boti.
    let tmp = std::env::temp_dir().join(format!("spaghetti_rs_test_bare_{}", std::process::id()));
    std::fs::create_dir_all(tmp.join("mylib")).unwrap();
    std::fs::write(
        tmp.join("mylib/core.py"),
        "def f():\n    try:\n        pass\n    except:\n        pass\n",
    )
    .unwrap();
    std::fs::write(tmp.join("loose.py"), "x = 1\n").unwrap();

    let output = Command::new(spaghetti_bin())
        .args(["--json", "--severity", "info"])
        .current_dir(&tmp)
        .output()
        .expect("failed to run spaghetti binary");

    std::fs::remove_dir_all(&tmp).ok();

    assert!(output.status.success() || output.status.code() == Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    let packages_seen: std::collections::HashSet<&str> = parsed["issues"]
        .as_array()
        .expect("issues array")
        .iter()
        .filter_map(|i| i["package"].as_str())
        .collect();
    assert!(
        packages_seen.contains("mylib"),
        "expected 'mylib' among scanned packages: {packages_seen:?}"
    );
    for boti_name in ["boti", "boti-data", "boti-dask"] {
        assert!(
            !packages_seen.contains(boti_name),
            "must never scan {boti_name} on a bare invocation: {packages_seen:?}"
        );
    }
    assert!(
        stdout.contains("bare-except"),
        "unexpected stdout: {stdout}"
    );
}

#[test]
fn bare_invocation_empty_cwd_errors() {
    let tmp = std::env::temp_dir().join(format!(
        "spaghetti_rs_test_bare_empty_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&tmp).unwrap();

    let output = Command::new(spaghetti_bin())
        .current_dir(&tmp)
        .output()
        .expect("failed to run spaghetti binary");

    std::fs::remove_dir_all(&tmp).ok();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no packages to scan"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn version_flag_prints_version_and_exits_zero() {
    let output = Command::new(spaghetti_bin())
        .args(["--version"])
        .output()
        .expect("failed to run spaghetti binary");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("spaghetti"), "unexpected stdout: {stdout}");
}

#[test]
fn quiet_flag_suppresses_banner_but_keeps_summary() {
    let tmp = std::env::temp_dir().join(format!("spaghetti_rs_test_quiet_{}", std::process::id()));
    let pkg_dir = tmp.join("fake_pkg");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(pkg_dir.join("mod.py"), "x = 1\n").unwrap();

    let output = Command::new(spaghetti_bin())
        .args([
            "--package",
            "fake_pkg=fake_pkg",
            "--severity",
            "info",
            "--quiet",
        ])
        .current_dir(&tmp)
        .output()
        .expect("failed to run spaghetti binary");

    std::fs::remove_dir_all(&tmp).ok();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("SPAGHETTI CODE DETECTION REPORT"),
        "unexpected stdout: {stdout}"
    );
    assert!(
        stdout.contains("Files scanned:"),
        "unexpected stdout: {stdout}"
    );
}

#[test]
fn config_file_resolves_packages_relative_to_itself() {
    let tmp = std::env::temp_dir().join(format!("spaghetti_rs_test_cfg_{}", std::process::id()));
    let pkg_dir = tmp.join("nested").join("fake_pkg");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("messy.py"),
        "def f():\n    try:\n        pass\n    except:\n        pass\n",
    )
    .unwrap();
    // Paths in the config are relative to the config file, not the cwd
    // (same as the Python original).
    std::fs::write(
        tmp.join("nested").join("spaghetti.yaml"),
        "packages:\n  fake_pkg: fake_pkg\n",
    )
    .unwrap();

    let output = Command::new(spaghetti_bin())
        .args([
            "--config",
            "nested/spaghetti.yaml",
            "--json",
            "--severity",
            "info",
        ])
        .current_dir(&tmp)
        .output()
        .expect("failed to run spaghetti binary");

    std::fs::remove_dir_all(&tmp).ok();

    assert!(output.status.success() || output.status.code() == Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bare-except"),
        "unexpected stdout: {stdout}"
    );
}

#[test]
fn config_file_without_packages_mapping_errors() {
    let tmp = std::env::temp_dir().join(format!("spaghetti_rs_test_badcfg_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("spaghetti.yaml"), "not_packages:\n  a: b\n").unwrap();

    let output = Command::new(spaghetti_bin())
        .args(["--config", "spaghetti.yaml"])
        .current_dir(&tmp)
        .output()
        .expect("failed to run spaghetti binary");

    std::fs::remove_dir_all(&tmp).ok();

    // The --config file is a settings file now: an unknown key is rejected
    // with the valid names listed, like the Python original.
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown setting(s): not_packages. Known: baseline, exclude, fail-on"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn config_file_without_packages_leaves_an_empty_registry() {
    let tmp = std::env::temp_dir().join(format!("spaghetti_rs_test_nopkgs_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("spaghetti.yaml"), "fail-on: never\n").unwrap();

    let output = Command::new(spaghetti_bin())
        .args(["--config", "spaghetti.yaml"])
        .current_dir(&tmp)
        .output()
        .expect("failed to run spaghetti binary");

    std::fs::remove_dir_all(&tmp).ok();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no packages to scan"),
        "unexpected stderr: {stderr}"
    );
}

// ── Phase 1 flags: settings, baseline, --diff-base, --fail-on, --format ─────
//
// Mirrors the `project` fixture and tests in the Python original's
// tests/test_cli.py: a git repo with a pyproject [tool.spaghetti] table and
// one messy package.

fn git(cwd: &std::path::Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git is available");
    assert!(
        status.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

fn project(tag: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir()
        .join(format!(
            "spaghetti_rs_test_project_{tag}_{}",
            std::process::id()
        ))
        .join("proj");
    std::fs::remove_dir_all(root.parent().unwrap()).ok();
    std::fs::create_dir_all(root.join("src/mylib/routes")).unwrap();
    std::fs::write(
        root.join("pyproject.toml"),
        "[tool.spaghetti]\n\
         fail-on = \"error\"\n\
         baseline = \".spaghetti-baseline.json\"\n\
         library-packages = [\"mylib\"]\n\
         [tool.spaghetti.packages]\n\
         mylib = \"src/mylib\"\n\
         [tool.spaghetti.thresholds]\n\
         max-func-params = 0\n\
         [tool.spaghetti.rules]\n\
         missing-param-type = \"off\"\n\
         missing-return-type = \"error\"\n\
         [tool.spaghetti.layers.mylib]\n\
         \"routes/\" = [\"mylib.db.\"]\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/mylib/m.py"),
        "def f(x):\n    a = 1\n    b = 2\n    c = 3\n    return a + b + c + x\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/mylib/routes/r.py"),
        "from fastapi import APIRouter\nfrom mylib.db.conn import C\n",
    )
    .unwrap();
    git(&root, &["init", "-q"]);
    git(&root, &["config", "user.email", "t@example.com"]);
    git(&root, &["config", "user.name", "t"]);
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "init"]);
    root
}

fn run_cli(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(spaghetti_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("failed to run spaghetti binary")
}

fn json_of(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}): {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn rules_and_severities(report: &serde_json::Value) -> Vec<(String, String)> {
    report["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["rule"].as_str().unwrap().to_string(),
                i["severity"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn pyproject_settings_drive_the_scan() {
    let root = project("settings");
    let output = run_cli(&root, &["--json"]);
    std::fs::remove_dir_all(root.parent().unwrap()).ok();
    assert_eq!(output.status.code(), Some(2)); // fail-on=error and errors exist
    let report = json_of(&output);
    let rules = rules_and_severities(&report);
    let has = |r: &str, s: &str| rules.iter().any(|(rr, ss)| rr == r && ss == s);
    assert!(has("missing-return-type", "error")); // severity override
    assert!(!rules.iter().any(|(r, _)| r == "missing-param-type")); // rule off
    assert!(has("layer-violation", "error")); // layers table
    assert!(has("transport-in-library", "error")); // library-packages
    assert!(has("too-many-params", "warning")); // threshold lowered to 0
    assert!(report["baseline"].is_null() && report["diff_base"].is_null());
}

#[test]
fn no_pyproject_flag_ignores_the_table() {
    let root = project("nopyproject");
    let output = run_cli(
        &root,
        &["--no-pyproject", "--package", "mylib=src/mylib", "--json"],
    );
    std::fs::remove_dir_all(root.parent().unwrap()).ok();
    let rules = rules_and_severities(&json_of(&output));
    assert!(rules.iter().any(|(r, _)| r == "missing-param-type"));
    assert!(!rules.iter().any(|(r, _)| r == "layer-violation"));
}

#[test]
fn invalid_pyproject_is_an_error_not_a_silent_fallback() {
    let root = project("invalid");
    std::fs::write(
        root.join("pyproject.toml"),
        "[tool.spaghetti]\nfail-on = \n",
    )
    .unwrap();
    let output = run_cli(&root, &["--json"]);
    std::fs::remove_dir_all(root.parent().unwrap()).ok();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid TOML"));
    assert!(output.stdout.is_empty());
}

#[test]
fn fail_on_policy_controls_exit_code() {
    let root = project("failon");
    assert_eq!(
        run_cli(&root, &["--fail-on", "never"]).status.code(),
        Some(0)
    );
    assert_eq!(
        run_cli(&root, &["--fail-on", "error"]).status.code(),
        Some(2)
    );
    // drop the error-level rules: only warnings/infos remain
    std::fs::remove_file(root.join("src/mylib/routes/r.py")).unwrap();
    std::fs::write(
        root.join("pyproject.toml"),
        "[tool.spaghetti]\n[tool.spaghetti.packages]\nmylib = 'src/mylib'\n",
    )
    .unwrap();
    let error = run_cli(&root, &["--fail-on", "error"]).status.code();
    let warning = run_cli(&root, &["--fail-on", "warning"]).status.code();
    let default = run_cli(&root, &[]).status.code();
    std::fs::remove_dir_all(root.parent().unwrap()).ok();
    assert_eq!(error, Some(0));
    assert_eq!(warning, Some(1));
    assert_eq!(default, Some(1)); // default policy is warning
}

#[test]
fn baseline_roundtrip_hides_known_and_reports_fixed() {
    let root = project("baseline");
    let write = run_cli(&root, &["--update-baseline"]);
    assert_eq!(
        write.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&write.stderr)
    );
    let baseline_path = root.join(".spaghetti-baseline.json");
    let baseline: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&baseline_path).unwrap()).unwrap();
    let n = baseline["findings"].as_object().unwrap().len();
    assert!(n >= 4);
    assert!(
        std::fs::read_to_string(&baseline_path)
            .unwrap()
            .ends_with("}\n")
    );

    let gated = run_cli(&root, &["--json"]);
    assert_eq!(gated.status.code(), Some(0)); // everything is baselined
    let report = json_of(&gated);
    assert_eq!(report["issues"], serde_json::json!([]));
    assert_eq!(report["baseline"]["known"], n);
    assert_eq!(report["baseline"]["fixed"], serde_json::json!([]));
    assert_eq!(report["summary"]["issues"], n); // summary still counts the full picture

    // Fix one finding and add a new one: the new one shows, the fixed one is listed.
    std::fs::write(
        root.join("src/mylib/routes/r.py"),
        "from mylib.db.conn import C\n",
    )
    .unwrap();
    std::fs::write(root.join("src/mylib/m.py"), "def g(y):\n    return y\n").unwrap();
    let after = json_of(&run_cli(&root, &["--json"]));
    std::fs::remove_dir_all(root.parent().unwrap()).ok();
    let mut rules: Vec<String> = rules_and_severities(&after)
        .into_iter()
        .map(|(r, _)| r)
        .collect();
    rules.sort();
    rules.dedup();
    assert_eq!(rules, ["missing-return-type", "too-many-params"]);
    assert!(
        after["baseline"]["fixed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["rule"] == "transport-in-library")
    );
}

#[test]
fn update_baseline_without_a_path_is_an_error() {
    let root = project("nobaseline");
    std::fs::write(
        root.join("pyproject.toml"),
        "[tool.spaghetti]\n[tool.spaghetti.packages]\nmylib = 'src/mylib'\n",
    )
    .unwrap();
    let output = run_cli(&root, &["--update-baseline"]);
    std::fs::remove_dir_all(root.parent().unwrap()).ok();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--update-baseline needs"));
}

#[test]
fn diff_base_restricts_to_changed_lines() {
    let root = project("diffbase");
    let m = root.join("src/mylib/m.py");
    let mut source = std::fs::read_to_string(&m).unwrap();
    source.push_str("\n\ndef g(y):\n    return y\n");
    std::fs::write(&m, source).unwrap();
    let output = run_cli(
        &root,
        &["--diff-base", "HEAD", "--json", "--fail-on", "never"],
    );
    let text = run_cli(&root, &["--diff-base", "HEAD", "-q"]);
    std::fs::remove_dir_all(root.parent().unwrap()).ok();
    let report = json_of(&output);
    let mut rules: Vec<String> = rules_and_severities(&report)
        .into_iter()
        .map(|(r, _)| r)
        .collect();
    rules.sort();
    rules.dedup();
    assert_eq!(rules, ["missing-return-type", "too-many-params"]);
    assert!(
        report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["message"].as_str().unwrap().starts_with("g()"))
    );
    assert_eq!(report["diff_base"]["ref"], "HEAD");
    assert!(report["diff_base"]["hidden"].as_u64().unwrap() >= 4);
    assert!(String::from_utf8_lossy(&text.stdout).contains("Changed lines only (vs HEAD)"));
}

#[test]
fn diff_base_outside_a_repo_is_an_error() {
    let tmp = std::env::temp_dir().join(format!("spaghetti_rs_test_norepo_{}", std::process::id()));
    std::fs::create_dir_all(tmp.join("pkg")).unwrap();
    std::fs::write(tmp.join("pkg/m.py"), "x = 1\n").unwrap();
    let output = run_cli(
        &tmp,
        &[
            "--no-pyproject",
            "--package",
            "pkg=pkg",
            "--diff-base",
            "not-a-ref-0xdeadbeef",
        ],
    );
    std::fs::remove_dir_all(&tmp).ok();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--diff-base"));
}

#[test]
fn sarif_output_is_well_formed() {
    let root = project("sarif");
    run_cli(&root, &["--update-baseline"]);
    std::fs::write(
        root.join("src/mylib/m.py"),
        "def g(y):  # spaghetti-ignore[missing-return-type]: demo\n    return y\n",
    )
    .unwrap();
    let output = run_cli(&root, &["--format", "sarif", "--fail-on", "never"]);
    std::fs::remove_dir_all(root.parent().unwrap()).ok();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let sarif = json_of(&output);
    assert_eq!(sarif["version"], "2.1.0");
    let run = &sarif["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "spaghetti");
    let results = run["results"].as_array().unwrap();
    assert!(results.iter().any(|r| r["baselineState"] == "unchanged"));
    let suppressed: Vec<_> = results
        .iter()
        .filter(|r| r.get("suppressions").is_some())
        .collect();
    assert!(!suppressed.is_empty());
    assert_eq!(suppressed[0]["suppressions"][0]["justification"], "demo");
    let uris: Vec<&str> = results
        .iter()
        .map(|r| {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap()
        })
        .collect();
    assert!(uris.iter().all(|u| !u.starts_with('/')));
    assert!(uris.contains(&"src/mylib/m.py"));
}

#[test]
fn rules_table_opts_an_off_by_default_rule_back_in() {
    // Mirrors tests/test_calibration.py::test_rules_off_by_default_are_dropped_unless_opted_in
    let root = project("optin");
    let source =
        "def f() -> int:\n    x = 42\n    if x:\n        y = 1\n        z = 2\n    return x\n";
    std::fs::write(root.join("src/mylib/m.py"), source).unwrap();
    let pyproject = |rules: &str| {
        format!(
            "[tool.spaghetti]\nfail-on = \"never\"\n[tool.spaghetti.packages]\nmylib = \
             \"src/mylib\"\n{rules}"
        )
    };
    std::fs::write(root.join("pyproject.toml"), pyproject("")).unwrap();
    let rules = rules_and_severities(&json_of(&run_cli(&root, &["--json"])));
    assert!(
        !rules
            .iter()
            .any(|(r, _)| r == "magic-number" || r == "missing-else")
    );

    std::fs::write(
        root.join("pyproject.toml"),
        pyproject("[tool.spaghetti.rules]\nmagic-number = \"warning\"\n"),
    )
    .unwrap();
    let rules = rules_and_severities(&json_of(&run_cli(&root, &["--json"])));
    std::fs::remove_dir_all(root.parent().unwrap()).ok();
    let magic: Vec<&(String, String)> = rules.iter().filter(|(r, _)| r == "magic-number").collect();
    assert!(!magic.is_empty());
    assert!(magic.iter().all(|(_, s)| s == "warning"));
    assert!(!rules.iter().any(|(r, _)| r == "missing-else"));
}
