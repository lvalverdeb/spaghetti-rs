# spaghetti

Spaghetti code and architectural-smell detector **for Python codebases**, implemented in Rust.

This is a from-scratch reimplementation of [`spaghetti-detector`](https://github.com/lvalverdeb/spaghetti) (the Python original) — not a wrapper or FFI binding. It parses and scans Python source directly, with no Python runtime dependency, producing a single native binary you can drop into any CI image or pre-commit hook with nothing else installed. Scans workspace packages for anti-patterns, architectural violations, and structural code smells — from single-function issues (long functions, deep nesting, high cyclomatic complexity) up to whole-package issues that only show up once you can see across files: real circular imports (not just a parent/child heuristic), copy-pasted function bodies, and the sync/async "twin" duplication pattern (`load`/`aload`, `foo`/`foo_async`) where a fix applied to one twin silently never reaches the other.

The [Python original](https://github.com/lvalverdeb/spaghetti) remains the actively maintained **spec of record**: when the two disagree, the Python behaviour is correct by definition and this is a bug here, not there. See [`RUST_PORT_PROPOSAL.md`](https://github.com/lvalverdeb/spaghetti/blob/main/RUST_PORT_PROPOSAL.md) in the Python repo for the full design rationale, phased build history, and every behavioural quirk (some quite subtle — e.g. `difflib.SequenceMatcher.ratio()`'s asymmetry under `autojunk`) uncovered and matched along the way.

**Status**: all 39 rules ported and verified — 674/674 issues identical to Python's own output across a real multi-package codebase, output is reproducible run-to-run, and `--plan` output is byte-for-byte identical to Python's.

## Why It Exists

AI-generated spaghetti code — often referred to as "slop code" — is extremely common because Large Language Models prioritise immediate functional completion (the "happy path") over long-term software architecture. It looks syntactically perfect and heavily commented, but often suffers from monolithic structures, copy-paste duplication, accidental complexity, and hallucinated dependencies. Human-written spaghetti code predates AI and has its own causes — tight deadlines, scope creep, skill gaps — but the fix is the same either way: mechanically-enforced rules that measure concrete thresholds instead of relying on review vibes.

### Problem → Rule Mapping

| Problem | Detector Rules | What It Catches |
|---------|---------------|-----------------|
| **Monolithic structures** | `god-class`, `god-module`, `long-function`, `long-file`, `deep-nesting` | Classes with 25+ methods, files over 400 lines, functions exceeding 50 lines, nesting beyond 5 levels |
| **Copy-paste duplication** | `duplicate-function-body`, `sync-async-duplication` | Identical function bodies (5+ lines), sync/async twin pairs with ≥60% text similarity |
| **Accidental complexity** | `high-complexity`, `excessive-returns`, `message-chain`, `deep-inheritance`, `excessive-decorators` | Cyclomatic complexity above 10, functions with 4+ return paths, chained calls deeper than 3 levels, inheritance exceeding 4 levels |
| **Layering violations** | `layer-violation`, `transport-in-library`, `import-cycle`, `encapsulation-violation` | Library code importing transport frameworks, circular import chains, accessing private attributes across objects |
| **Type safety gaps** | `missing-return-type`, `missing-param-type`, `untyped-dict`, `bare-except` | Public functions missing annotations, bare `dict` in type hints, bare `except:` clauses |
| **Dead code & clutter** | `dead-code`, `unused-import`, `star-import`, `todo-marker`, `magic-number`, `magic-string` | Unreachable statements after `return`/`raise`/`break`, `from x import *`, unexplained numeric literals, repeated string comparisons standing in for a category code |

## Install

```bash
cargo install spaghetti
```

This installs a binary named `spaghetti` (matching the Python CLI's command name and the crate name).

## Usage

```bash
spaghetti
spaghetti --packages package1 package2
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
| `--plan` | off | Output a prioritised remediation plan instead of the standard report |

## Inline suppression

Same convention as the Python original — suppress a finding with `# spaghetti-ignore[rule]` on the offending line or the line above it:

```python
def f():  # spaghetti-ignore[long-function]: intentionally large
    ...

x: dict = {}  # spaghetti-ignore: reviewed, no issue
```

## Rules

All 39 rules from the Python original: 31 per-file AST checks (including `pass-through-method`), 2 source-text checks, 1 infrastructure check (`syntax-error`), and 5 cross-file package checks (`import-cycle`, `high-coupling`, `orphan-interface`, `duplicate-function-body`, `sync-async-duplication`). A `low-cohesion` (LCOM4) check also exists in the codebase but is intentionally not enabled by default — see the rule's own doc comment for why. See the Python repo's [`SDD.md`](https://github.com/lvalverdeb/spaghetti/blob/main/SDD.md) for the full rule catalog, thresholds, and scoring formula — this port matches it exactly, not approximately.

## Development

```bash
cargo build --release
cargo test
cargo clippy --all-targets
```

## License

MIT
