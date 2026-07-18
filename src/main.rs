use clap::Parser;
use spaghetti_detector_rs::cli;

fn main() {
    let args = cli::Args::parse();
    std::process::exit(cli::run(args));
}
