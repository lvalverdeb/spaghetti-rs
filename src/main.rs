use clap::Parser;
use spaghetti::cli;

fn main() {
    let args = cli::Args::parse();
    std::process::exit(cli::run(args));
}
