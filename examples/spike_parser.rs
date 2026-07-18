//! Phase 0 spike: does rustpython-parser parse this workspace's real .py files
//! without incident? Walks each target package, parses every .py file, and
//! reports any that fail — success is "zero failures", not "fast".
//!
//! Originally spiked against ruff_python_parser/ruff_python_ast (the
//! proposal's first choice), but that crate is broken as published on
//! crates.io: ruff_python_parser 0.0.5 unconditionally requires
//! ruff_python_ast's "get-size" feature, which pulls in get-size2 0.10.x's
//! own compact_str 0.10.x, while ruff_python_parser itself depends directly
//! on compact_str 0.9.x — two incompatible versions of the same crate in
//! the graph, so the GetSize derive can't be satisfied. Not a local
//! misconfiguration: the crate hasn't been published past 0.0.5 at all,
//! consistent with it being an internal Ruff component, not a maintained
//! public dependency. Falling back to rustpython-parser per the proposal's
//! §7.1 documented fallback.

use std::path::Path;
use std::time::Instant;

use walkdir::WalkDir;

fn scan_package(name: &str, root: &Path) -> (usize, usize, Vec<(String, String)>) {
    let mut ok = 0;
    let mut failed = 0;
    let mut failures = Vec::new();

    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("py") {
            continue;
        }
        if path.components().any(|c| c.as_os_str() == "__pycache__") {
            continue;
        }

        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                failed += 1;
                failures.push((path.display().to_string(), format!("read error: {e}")));
                continue;
            }
        };

        let path_str = path.display().to_string();
        match rustpython_parser::parse(&source, rustpython_parser::Mode::Module, &path_str) {
            Ok(_) => ok += 1,
            Err(e) => {
                failed += 1;
                failures.push((path_str, e.to_string()));
            }
        }
    }

    println!("[{name}] ok={ok} failed={failed}");
    (ok, failed, failures)
}

fn main() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("spaghetti-rs must sit inside the workspace root");

    let targets: &[(&str, &str)] = &[
        ("boti", "boti/src/boti"),
        ("boti-data", "boti-data/src/boti_data"),
        ("boti-dask", "boti-dask/src/boti_dask"),
        ("spaghetti", "spaghetti/src/spaghetti"),
    ];

    let start = Instant::now();
    let mut total_ok = 0;
    let mut total_failed = 0;
    let mut all_failures = Vec::new();

    for (name, rel_path) in targets {
        let root = workspace_root.join(rel_path);
        if !root.exists() {
            println!("[{name}] SKIPPED — path does not exist: {}", root.display());
            continue;
        }
        let (ok, failed, failures) = scan_package(name, &root);
        total_ok += ok;
        total_failed += failed;
        all_failures.extend(failures);
    }

    let elapsed = start.elapsed();
    println!("\n=== TOTAL: ok={total_ok} failed={total_failed} in {elapsed:?} ===");

    if !all_failures.is_empty() {
        println!("\n--- Failures ---");
        for (path, err) in &all_failures {
            println!("{path}: {err}");
        }
        std::process::exit(1);
    }
}
