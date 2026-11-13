use clap::Parser;
use spaghetti::{cli, init_scan_pool, mcp, with_scan_stack};

fn main() {
    // Packages are scanned on rayon's pool and the rest of the run on one
    // big-stack thread: rustpython drops and clones its AST recursively, so
    // a pathologically nested file needs more stack than a default thread.
    init_scan_pool();
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
