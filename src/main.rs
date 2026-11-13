use clap::Parser;
use spaghetti::{SCAN_STACK_BYTES, cli, mcp, with_scan_stack};

fn main() {
    // Packages are scanned on rayon's pool and the rest of the run on one
    // big-stack thread: rustpython drops and clones its AST recursively, so
    // a pathologically nested file needs more stack than a default thread.
    let _ = rayon::ThreadPoolBuilder::new()
        .stack_size(SCAN_STACK_BYTES)
        .build_global();
    let code = with_scan_stack(|| {
        // `spaghetti mcp` is intercepted before argument parsing, like Python's
        // `main()` does with `sys.argv[1:2] == ["mcp"]`.
        if std::env::args().nth(1).as_deref() == Some("mcp") {
            let stdin = std::io::stdin().lock();
            let stdout = std::io::stdout().lock();
            return mcp::serve(stdin, stdout, env!("CARGO_PKG_VERSION"), &mcp::run_cli);
        }
        let args = cli::Args::parse();
        cli::run(args)
    });
    std::process::exit(code);
}
