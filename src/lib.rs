pub mod ast_helpers;
pub mod baseline;
pub mod cache;
pub mod checks;
pub mod churn;
pub mod cli;
pub mod clones;
pub mod config;
pub mod contracts;
pub mod diff_filter;
pub mod fstrings;
pub mod html_report;
pub mod json;
pub mod limits;
pub mod mcp;
pub mod metrics;
pub mod models;
pub mod py_printable;
pub mod pyast;
pub mod pydump;
pub mod rule_docs;
pub mod rules;
pub mod sarif;
pub mod scanner;
pub mod scoring;
pub mod settings;
pub mod similarity;
pub mod snapshots;
pub mod suppression;
pub mod unparse;

/// Stack size for the threads that parse and scan files. rustpython's AST
/// is dropped (and cloned) recursively, so a pathologically nested file
/// needs more than the 2-8 MiB a default thread gets; this is address space
/// reserved, not memory committed.
pub const SCAN_STACK_BYTES: usize = 1 << 30;

/// Give rayon's global pool (which scans packages and their files)
/// `SCAN_STACK_BYTES` stacks. Idempotent; a pool that cannot be built with
/// that stack keeps rayon's default.
pub fn init_scan_pool() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rayon::ThreadPoolBuilder::new()
            .stack_size(SCAN_STACK_BYTES)
            .build_global();
    });
}

/// Run `f` on a thread with a `SCAN_STACK_BYTES` stack and return its
/// result; on a system that refuses that reservation, run it here instead.
pub fn with_scan_stack<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    let f = std::sync::Mutex::new(Some(f));
    let spawned = std::thread::scope(|scope| {
        let handle = std::thread::Builder::new()
            .name("spaghetti-scan".to_string())
            .stack_size(SCAN_STACK_BYTES)
            .spawn_scoped(scope, || {
                let f = f.lock().unwrap_or_else(|e| e.into_inner()).take();
                f.map(|f| f())
            });
        handle.ok().map(|h| {
            h.join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        })
    });
    match spawned.flatten() {
        Some(result) => result,
        None => {
            let f = f
                .into_inner()
                .unwrap_or_else(|e| e.into_inner())
                .expect("the scan closure runs exactly once");
            f()
        }
    }
}
