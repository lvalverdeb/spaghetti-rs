use clap::Parser;
use spaghetti::{cli, mcp};

fn main() {
    // `spaghetti mcp` is intercepted before argument parsing, like Python's
    // `main()` does with `sys.argv[1:2] == ["mcp"]`.
    if std::env::args().nth(1).as_deref() == Some("mcp") {
        let stdin = std::io::stdin().lock();
        let stdout = std::io::stdout().lock();
        std::process::exit(mcp::serve(
            stdin,
            stdout,
            env!("CARGO_PKG_VERSION"),
            &mcp::run_cli,
        ));
    }
    let args = cli::Args::parse();
    std::process::exit(cli::run(args));
}
