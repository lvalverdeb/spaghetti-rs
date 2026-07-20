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
