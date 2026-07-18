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
