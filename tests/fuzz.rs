//! Robustness: the scanner never panics or overflows its stack, and every
//! input yields a report — mirrors the Python repo's tests/test_fuzz.py.
//!
//! Each property runs one batch of `SPAGHETTI_FUZZ_CASES` cases (default 48)
//! by default. With `SPAGHETTI_FUZZ_SECONDS` set, every property keeps
//! running fresh batches until that many seconds have passed (the
//! properties run in parallel, so that is also the wall-clock time) — CI's
//! fuzz job runs it for about ten minutes:
//!
//!     SPAGHETTI_FUZZ_SECONDS=600 cargo test --release --test fuzz
//!
//! A failure prints the minimal input proptest shrank it to.

use indexmap::IndexMap;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use spaghetti::models::{ScanConfig, ScanResult};
use spaghetti::scanner::{scan_package, scan_workspace};
use spaghetti::with_scan_stack;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn config() -> ScanConfig {
    ScanConfig {
        exclude: vec![],
        min_duplicate_lines: 5,
        twin_similarity: 0.6,
        recursive: true,
        min_clone_tokens: 50,
        cache_dir: None,
        cache_key: String::new(),
    }
}

/// Scan `bytes` as the only file of a package, on a scan-sized stack, and
/// check the report is well formed. Returns the rules it reported.
fn scan_bytes(bytes: &[u8]) -> Vec<&'static str> {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root: PathBuf =
        std::env::temp_dir().join(format!("spaghetti_rs_fuzz_{}_{n}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("m.py"), bytes).unwrap();
    let result = with_scan_stack(|| {
        let config = config();
        let mut per: IndexMap<String, ScanResult> = IndexMap::new();
        per.insert("pkg".to_string(), scan_package("pkg", &root, &config));
        let registry: IndexMap<String, PathBuf> =
            [("pkg".to_string(), root.clone())].into_iter().collect();
        scan_workspace(&mut per, &registry, &config, None);
        per.shift_remove("pkg").unwrap()
    });
    std::fs::remove_dir_all(&root).ok();
    assert_eq!(result.files_scanned, 1);
    for issue in &result.issues {
        assert!(!issue.rule.is_empty() && !issue.fingerprint.is_empty() && issue.line >= 1);
    }
    let mut rules: Vec<&'static str> = result.issues.iter().map(|i| i.rule).collect();
    rules.sort_unstable();
    rules.dedup();
    rules
}

fn cases() -> u32 {
    std::env::var("SPAGHETTI_FUZZ_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48)
}

/// How long each property runs, if `SPAGHETTI_FUZZ_SECONDS` is set.
fn budget() -> Option<Duration> {
    let seconds: f64 = std::env::var("SPAGHETTI_FUZZ_SECONDS").ok()?.parse().ok()?;
    Some(Duration::from_secs_f64(seconds))
}

/// Run `property` over `strategy` in batches until the time budget is spent
/// (or once, without one). Panics with the shrunk input on failure.
fn fuzz<S: Strategy>(strategy: S, property: impl Fn(S::Value) + Sync)
where
    S::Value: std::fmt::Debug,
{
    let deadline = budget().map(|b| Instant::now() + b);
    let mut batches = 0u64;
    loop {
        batches += 1;
        let mut runner = TestRunner::new(Config {
            cases: cases(),
            failure_persistence: None,
            ..Config::default()
        });
        if let Err(e) = runner.run(&strategy, |value| {
            property(value);
            Ok(())
        }) {
            panic!("{e}");
        }
        match deadline {
            Some(d) if Instant::now() < d => continue,
            _ => break,
        }
    }
    if deadline.is_some() {
        eprintln!("{} cases, no failure", batches * u64::from(cases()));
    }
}

/// Fragments that recombine into Python-shaped text: the parser gets past
/// its first token often enough to reach the checks.
const FRAGMENTS: &[&str] = &[
    "def ",
    "async def ",
    "class ",
    "f",
    "g",
    "self",
    "x",
    "y",
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    ":",
    ",",
    ".",
    " = ",
    " += ",
    " == ",
    " and ",
    " or ",
    " not ",
    " if ",
    " else ",
    " for ",
    " in ",
    " is ",
    " lambda ",
    "return ",
    "yield ",
    "await ",
    "raise ",
    "try:",
    "except ",
    "finally:",
    "with ",
    " as ",
    "import ",
    "from ",
    "global ",
    "match ",
    "case ",
    "pass",
    "...",
    "0",
    "1",
    "3.5",
    "1e309",
    "0x1F",
    "'s'",
    "\"s\"",
    "'''",
    "\"\"\"",
    "f'{x}'",
    "f\"{x!r:>{y}}\"",
    "b'\\x00'",
    "'\\ud83d'",
    "# c",
    "\\\n",
    "\n",
    "\n    ",
    "\n        ",
    "\t",
    "*",
    "**",
    "->",
    "@",
    "dict",
    "-> dict",
    ": dict",
    "\u{feff}",
    "\0",
    "\r\n",
    "\u{2028}",
];

const SEEDS: &[&str] = &[
    "import os\n\ndef f(a, b=1, *c, d, **e) -> int:\n    \"\"\"Doc.\"\"\"\n    if a:\n        return b\n    for x in c:\n        try:\n            os.f(x)\n        except (ValueError, KeyError) as err:\n            raise RuntimeError() from err\n    return a or (b and not c)\n",
    "class K(Base, metaclass=M):\n    x: dict = {}\n    def m(self):\n        return self._x.y.z.w\n    async def am(self):\n        async with self.lock:\n            return await self.m()\n",
    "def load(self):\n    with open(p) as fh:\n        return fh.read()\n\nasync def aload(self):\n    async with open(p) as fh:\n        return await fh.read()\n",
    "match cmd:\n    case [x, *rest] if x > 3:\n        pass\n    case {\"k\": v, **kw}:\n        pass\n    case Point(x=0) | None:\n        pass\n",
    "x = f\"\"\"a\n{b!r:>{w}}\n\"\"\" + 'c' 'd' + b'e'\ny = [i for i in range(10) if i % 2]\nz = {k: v for k, v in d.items()}\n",
];

fn mutated_seed() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::sample::select(SEEDS),
        prop::collection::vec((any::<prop::sample::Index>(), 0u8..3, any::<u8>()), 0..12),
    )
        .prop_map(|(seed, edits)| {
            let mut bytes = seed.as_bytes().to_vec();
            for (at, op, byte) in edits {
                if bytes.is_empty() {
                    bytes.push(byte);
                    continue;
                }
                let i = at.index(bytes.len());
                match op {
                    0 => bytes.insert(i, byte),
                    1 => {
                        bytes.remove(i);
                    }
                    _ => bytes[i] = byte,
                }
            }
            bytes
        })
}

#[test]
fn scanner_never_panics_on_arbitrary_bytes() {
    fuzz(prop::collection::vec(any::<u8>(), 0..2048), |bytes| {
        scan_bytes(&bytes);
    });
}

#[test]
fn scanner_never_panics_on_python_shaped_text() {
    fuzz(
        prop::collection::vec(prop::sample::select(FRAGMENTS), 0..120),
        |fragments| {
            scan_bytes(fragments.concat().as_bytes());
        },
    );
}

#[test]
fn scanner_never_panics_on_mutated_programs() {
    fuzz(mutated_seed(), |bytes| {
        scan_bytes(&bytes);
    });
}

/// Python's fixed edge-case list, with the rules the Python port reports for
/// each (CPython 3.13); the two ports agree on every one of them.
#[test]
fn scanner_survives_known_edge_cases() {
    let deep_ifs = |n: usize| {
        let mut s: String = (0..n)
            .map(|i| format!("{}if x:\n", "    ".repeat(i)))
            .collect();
        s.push_str(&format!("{}pass\n", "    ".repeat(n)));
        s
    };
    let cases: Vec<(String, &[&str])> = vec![
        (String::new(), &[]),
        ("\u{feff}import os\n".into(), &["syntax-error"]),
        ("x = 1\r\ny = 2\r\n".into(), &[]),
        ("x = '\0'\n".into(), &["syntax-error"]),
        (
            "def f():\n\tif 1:\n\t\treturn\n".into(),
            &["missing-return-type"],
        ),
        (
            format!("x = 1\n{}    pass\n", "if x:\n".repeat(150)),
            &["syntax-error"],
        ),
        (
            format!("x = {}{}\n", "[".repeat(3000), "]".repeat(3000)),
            &["syntax-error"],
        ),
        (
            format!(
                "class A({}): pass\n",
                (0..500)
                    .map(|i| format!("B{i}"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            &["deep-inheritance"],
        ),
        (format!("{}0\n", "lambda: ".repeat(300)), &[]),
        (
            format!(
                "f({})\n",
                (0..2000)
                    .map(|i| format!("a{i}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            &[],
        ),
        (
            format!("x = {}\n", vec!["1"; 5000].join(" + ")),
            &["scan-limit"],
        ),
        // Lone surrogate escapes in string annotations (found in pandas).
        ("x: \"\\ud83d\" = 1\n".into(), &[]),
        (
            "def f(a: \"\\udcff\") -> \"List[\\ud800]\": ...\n".into(),
            &[],
        ),
        // CPython's tokenizer limits.
        (
            format!("x = {}{}\n", "[".repeat(200), "]".repeat(200)),
            &["global-mutable"],
        ),
        (
            format!("x = {}{}\n", "[".repeat(201), "]".repeat(201)),
            &["syntax-error"],
        ),
        (deep_ifs(99), &[]),
        (deep_ifs(100), &["syntax-error"]),
    ];
    for (text, expected) in cases {
        let rules = scan_bytes(text.as_bytes());
        assert_eq!(rules, expected, "{:?}", &text[..text.len().min(60)]);
    }
}
