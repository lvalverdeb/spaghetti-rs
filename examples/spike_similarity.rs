//! Phase 0 spike: does the `similar` crate's TextDiff::ratio() track Python's
//! difflib.SequenceMatcher(None, a, b).ratio() closely enough that the
//! existing --twin-similarity threshold (default 0.6, and the value
//! CLAUDE.md itself gates on) means the same thing in both languages?
//!
//! Reads paired text files produced by a companion Python extraction script
//! (unparsed real sync/async twin function bodies from this workspace),
//! computes the ratio under each of `similar`'s algorithms, and prints them
//! next to the Python-computed reference ratio for by-hand comparison.

use similar::{Algorithm, TextDiff};
use std::fs;
use std::path::Path;

fn ratio_with(a: &str, b: &str, algo: Algorithm) -> f32 {
    TextDiff::configure()
        .algorithm(algo)
        .diff_chars(a, b)
        .ratio()
}

fn main() {
    let cases: &[(&str, &str, &str, f32)] = &[
        (
            "load/aload",
            "/tmp/twin_0_a.txt",
            "/tmp/twin_0_b.txt",
            0.6897,
        ),
        (
            "before_load/abefore_load",
            "/tmp/twin_1_a.txt",
            "/tmp/twin_1_b.txt",
            0.9710,
        ),
        (
            "after_load/aafter_load",
            "/tmp/twin_2_a.txt",
            "/tmp/twin_2_b.txt",
            0.9710,
        ),
    ];

    println!(
        "{:<28} {:>10} {:>10} {:>10} {:>10}",
        "case", "python", "myers", "patience", "lcs"
    );
    for (name, path_a, path_b, python_ratio) in cases {
        if !Path::new(path_a).exists() || !Path::new(path_b).exists() {
            println!("[{name}] SKIPPED — run the Python extraction script first");
            continue;
        }
        let a = fs::read_to_string(path_a).unwrap();
        let b = fs::read_to_string(path_b).unwrap();
        let myers = ratio_with(&a, &b, Algorithm::Myers);
        let patience = ratio_with(&a, &b, Algorithm::Patience);
        let lcs = ratio_with(&a, &b, Algorithm::Lcs);
        println!("{name:<28} {python_ratio:>10.4} {myers:>10.4} {patience:>10.4} {lcs:>10.4}");
    }
}
