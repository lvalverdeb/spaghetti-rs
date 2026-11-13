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

/// Run `f` on a thread with a `SCAN_STACK_BYTES` stack and return its result.
pub fn with_scan_stack<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("spaghetti-scan".to_string())
            .stack_size(SCAN_STACK_BYTES)
            .spawn_scoped(scope, f)
            .expect("spawning the scan thread")
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}
