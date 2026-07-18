# spaghetti-rs

A Rust port of [`spaghetti`](https://github.com/lvalverdeb/spaghetti), the spaghetti-code and architectural-smell detector for Python projects.

This is a from-scratch reimplementation, not a wrapper or FFI binding — a native binary with no Python runtime dependency, built for speed and easy distribution (drop it into any CI image or pre-commit hook with nothing else installed). The [Python original](https://github.com/lvalverdeb/spaghetti) remains the actively maintained **spec of record**: when the two disagree, the Python behavior is correct by definition and this is a bug here, not there. See [`RUST_PORT_PROPOSAL.md`](https://github.com/lvalverdeb/spaghetti/blob/main/RUST_PORT_PROPOSAL.md) in the Python repo for the full design rationale, phased build history, and every behavioral quirk (some quite subtle — e.g. `difflib.SequenceMatcher.ratio()`'s asymmetry under `autojunk`) uncovered and matched along the way.

**Status**: all 36 rules ported and verified — 674/674 issues identical to Python's own output across a real multi-package codebase, output is reproducible run-to-run, and `--plan` output is byte-for-byte identical to Python's. Not yet published; packaging (this README, `LICENSE`, `cargo-dist` config) is in progress.

## Install

```bash
cargo install spaghetti-detector-rs
```

This installs a binary named `spaghetti` (matching the Python CLI's command name), not `spaghetti-detector-rs` — the crate name and the command you run are deliberately different.

## Usage

```bash
spaghetti
spaghetti --packages boti-data boti-dask
spaghetti --severity error
spaghetti --top 10 --exclude tests/ examples/
spaghetti --json > report.json
spaghetti --plan --top 10
spaghetti --config spaghetti.yaml
spaghetti --package my-lib=my-lib/src/my_lib
```

Exit codes: `0` (clean), `1` (warnings present), `2` (errors present) — safe to wire into CI as a gate.

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `--config` | none | YAML file with a `packages: {name: path}` mapping; replaces the built-in defaults |
| `--package` | none | Add or override one package as `NAME=PATH` (repeatable); applied on top of `--config` or the defaults |
| `--packages` | all resolved packages | Names to scan from the resolved registry |
| `--severity` | `info` | Minimum severity to display (`info` / `warning` / `error`) |
| `--json` | off | Output as JSON instead of the console report |
| `--top` | `5` | Number of worst files/rules to list |
| `--exclude` | none | Path substrings to exclude from scanning |
| `--min-duplicate-lines` | `5` | Minimum function length to consider for duplicate-body detection |
| `--twin-similarity` | `0.6` | Minimum text-similarity ratio (0–1) to flag a sync/async twin pair |
| `--plan` | off | Output a prioritized remediation plan instead of the standard report |

## Inline suppression

Same convention as the Python original — suppress a finding with `# spaghetti-ignore[rule]` on the offending line or the line above it:

```python
def f():  # spaghetti-ignore[long-function]: intentionally large
    ...

x: dict = {}  # spaghetti-ignore: reviewed, no issue
```

## Rules

All 36 rules from the Python original: 30 documented per-file AST checks, the (also-ported) undocumented `pass-through-method`, 2 source-text checks, 1 infrastructure check (`syntax-error`), and the 3 cross-file package checks (`import-cycle`, `duplicate-function-body`, `sync-async-duplication`). See the Python repo's [`SDD.md`](https://github.com/lvalverdeb/spaghetti/blob/main/SDD.md) for the full rule catalog, thresholds, and scoring formula — this port matches it exactly, not approximately.

## Development

```bash
cargo build --release
cargo test
cargo clippy --all-targets
```

## License

MIT
