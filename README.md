# spaghetti

Spaghetti code and architectural-smell detector **for Python codebases**, implemented in Rust.

This is a from-scratch reimplementation of [`spaghetti-detector`](https://github.com/lvalverdeb/spaghetti) (the Python original) — not a wrapper or FFI binding. It parses and scans Python source directly, with no Python runtime dependency, producing a single native binary you can drop into any CI image or pre-commit hook with nothing else installed. Scans workspace packages for anti-patterns, architectural violations, and structural code smells — from single-function issues (long functions, deep nesting, high cyclomatic complexity) up to whole-package issues that only show up once you can see across files: real circular imports (not just a parent/child heuristic), copy-pasted function bodies, and the sync/async "twin" duplication pattern (`load`/`aload`, `foo`/`foo_async`) where a fix applied to one twin silently never reaches the other.

The [Python original](https://github.com/lvalverdeb/spaghetti) remains the actively maintained **spec of record**: when the two disagree, the Python behaviour is correct by definition and this is a bug here, not there. See [`RUST_PORT_PROPOSAL.md`](https://github.com/lvalverdeb/spaghetti/blob/main/RUST_PORT_PROPOSAL.md) in the Python repo for the full design rationale, phased build history, and every behavioural quirk (some quite subtle — e.g. `difflib.SequenceMatcher.ratio()`'s asymmetry under `autojunk`) uncovered and matched along the way.

**Status**: all 47 catalogued rules ported and verified — `--json`, `--format sarif`, `--format html`, `--plan` (text and `--json`), the baseline file and the snapshot store are byte-for-byte identical to Python's output on the same input, and `spaghetti mcp` answers the same JSON-RPC lines (Phases 1-4 of the Python [ROADMAP](https://github.com/lvalverdeb/spaghetti/blob/main/ROADMAP.md): settings, baseline, changed-lines mode, SARIF, `--fail-on`, Radon-exact complexity, cognitive complexity, clone detection, the workspace import graph, the Maintainability Index, snapshots and `--compare`, churn-weighted hotspots, the HTML report, architecture contracts and the MCP server; Phase 5: the incremental cache, scan limits, fuzzing and the corpus conformance check), and output is reproducible run-to-run. Over the pinned eight-repository corpus (django, pandas, airflow, httpx, rich, FastAPI, pydantic, black) plus the Python port's own source, `--json` and `--plan --json` are byte-identical between the two ports; CI checks this on every push.

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
spaghetti -q
spaghetti --baseline .spaghetti-baseline.json --update-baseline
spaghetti --diff-base origin/main --fail-on error
spaghetti --format sarif > spaghetti.sarif
spaghetti --snapshot && spaghetti --compare latest
spaghetti --hotspots --plan
spaghetti --format html > report.html
spaghetti --plan --json
spaghetti --cache
spaghetti mcp
```

Exit codes: `0` (clean), `1` (warnings present), `2` (errors present) — safe to wire into CI as a gate. `--fail-on error|warning|info|never` picks the lowest severity that makes the exit code non-zero (default `warning`); the code is computed on the findings that survive the baseline and `--diff-base` filters, not on the `--severity` display floor. Usage and settings errors exit `2` with a message on stderr.

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `--config` | none | YAML settings file (same keys as `[tool.spaghetti]`); its `packages: {name: path}` mapping replaces the pyproject one |
| `--package` | none | Add or override one package as `NAME=PATH` (repeatable); applied on top of `--config` or the defaults |
| `--packages` | all resolved packages | Names to scan from the resolved registry |
| `--severity` | `info` | Minimum severity to display (`info` / `warning` / `error`) |
| `--format` | `text` | `text`, `json`, `sarif` (SARIF 2.1.0 for code-scanning tools) or `html` (a self-contained page with scorecard, trend, hotspots and findings) |
| `--json` | off | Shorthand for `--format json` |
| `--fail-on` | `warning` | Lowest severity that makes the exit code non-zero; `never` always exits 0 |
| `--baseline` | from settings | Baseline file of accepted findings; see [Baseline](#baseline) |
| `--update-baseline` | off | Write every current finding to the baseline file and exit 0 |
| `--diff-base` | none | Git ref; report only findings on lines added or changed since it |
| `--snapshot` | off | Append this run (git SHA, scores, per-file penalties, finding fingerprints) to the snapshot store |
| `--snapshot-store` | `.spaghetti/snapshots.jsonl` | JSONL snapshot store (or `snapshot-store` in `[tool.spaghetti]`) |
| `--compare` | none | Delta against a stored snapshot: `latest`, `~N`, a git SHA prefix or a timestamp prefix |
| `--hotspots` | off | Rank files by health penalty × git change frequency and weight `--plan` by it |
| `--churn-months` | `6` | History window for `--hotspots` |
| `--cache` | off | Reuse per-file results for files whose content and settings are unchanged (store: `.spaghetti/cache`); see [Incremental cache](#incremental-cache) |
| `--no-cache` | off | Ignore `cache = true` from the settings for this run |
| `--cache-dir` | `.spaghetti/cache` | Where `--cache` stores its entries (implies `--cache`; or `cache-dir` in `[tool.spaghetti]`) |
| `--no-pyproject` | off | Ignore any `[tool.spaghetti]` table found above the working directory |
| `--quiet` / `-q` | off | Suppress the report banner (text-report mode only; `--json` is unaffected) |
| `--top` | `5` | Number of worst files/rules to list |
| `--exclude` | none | Path substrings to exclude from scanning |
| `--min-duplicate-lines` | `5` | Minimum function length to consider for duplicate-body detection |
| `--twin-similarity` | `0.6` | Minimum text-similarity ratio (0–1) to flag a sync/async twin pair |
| `--plan` | off | Output a prioritised remediation plan instead of the standard report; with `--json`, the JSON report plus a `plan` array |
| `--version` | — | Print the installed spaghetti version and exit |

## Inline suppression

Same convention as the Python original — suppress a finding with `# spaghetti-ignore[rule]` on the offending line or the line above it:

```python
def f():  # spaghetti-ignore[long-function]: intentionally large
    ...

x: dict = {}  # spaghetti-ignore: reviewed, no issue
```

The marker applies to the line it appears on and the line directly above it (so a marker can sit above a `def` line too long for a trailing comment). Suppressed findings are counted in the report summary (`Suppressed: N`) rather than silently dropped — they remain visible, and `--json` lists each one under `ignored` (below).

## JSON Output

With `--json`, the report is a single JSON object to stdout — **schema version 1**, byte-for-byte the same document the Python original emits for the same input. The schema is committed in the Python repo at [`schema/report.v1.json`](https://github.com/lvalverdeb/spaghetti/blob/main/schema/report.v1.json); `schema_version` is bumped only on a breaking change to the shape (additive fields keep it).

```json
{
  "schema_version": 1,
  "summary": { "grade": "B", "score": 89.8, "files": 13, "lines": 4137, "functions": 168, "issues": 33, "errors": 0, "warnings": 27, "infos": 6, "maintainability_index": 64.2 },
  "packages": {
    "my-lib": { "grade": "B", "score": 89.8, "files": 13, "lines": 4137, "functions": 168, "issues": 33, "errors": 0, "warnings": 27, "infos": 6, "maintainability_index": 64.2 }
  },
  "issues": [
    {
      "file": "src/my_module.py",
      "line": 42,
      "column": 1,
      "end_line": 107,
      "end_column": 18,
      "severity": "warning",
      "rule": "long-function",
      "message": "my_func() is 65 lines (max 50)",
      "package": "my-lib",
      "fingerprint": "3f2a9c1b7e4d5a60"
    }
  ],
  "suppressed": 3,
  "suppression_help": "Silence a confirmed non-issue by adding '# spaghetti-ignore[rule-name]: reason' on the flagged line (or the line above).",
  "ignored": [
    {
      "file": "src/legacy.py",
      "line": 10,
      "column": 5,
      "end_line": 11,
      "end_column": 13,
      "severity": "warning",
      "rule": "bare-except",
      "message": "Bare except clause — catch specific exceptions instead",
      "package": "my-lib",
      "fingerprint": "9b0d4e2f6a1c3857",
      "reason": "reviewed, no issue"
    }
  ]
}
```

- `summary` and each entry of `packages` carry the same grade/score/count block; `score` is rounded to one decimal.
- `column`/`end_column` are 1-based *character* columns (so a non-ASCII character earlier on the line doesn't shift them); `end_column` is exclusive. Rules that flag a whole file or a line without a node (`long-file`, `todo-marker`, `unused-import`, `dead-code`, `god-module`, `magic-string`, the cross-file rules and the infrastructure rules) report `null` for all three.
- `fingerprint` is a stable 16-hex-digit identity for a finding (rule + package-relative path + message with digits stripped, disambiguated per occurrence), so it survives line shifts and re-runs — the hook for baselines and SARIF `partialFingerprints`.
- `ignored` lists the findings a `# spaghetti-ignore` marker actually silenced (each with its `reason`, if one was given), so a suppression is visible rather than invisible in the JSON report too.
- Non-ASCII characters are escaped as `\uXXXX`, as Python's `json.dumps` does by default.
- `diff_base` (`{"ref", "hidden"}`) and `baseline` (`{"path", "known", "fixed": [...]}`) follow `ignored`; each is `null` when the corresponding filter was not used. `summary`/`packages` always count the full picture; `issues` is what survived the filters.
- `compare` (with `--compare`), `hotspots` (with `--hotspots`) and `plan` (with `--plan --json`: priority, rule, severity, effort, count, score, files, description and the rule's fix pattern per step) are added only when asked for — absent, not `null`, otherwise.

## Configuration

Settings live in `pyproject.toml` under `[tool.spaghetti]` (found by walking up from the working directory) and/or in the YAML file passed to `--config` — the same files, keys and precedence as the Python original (defaults < `pyproject.toml` < `--config` < CLI flags). A malformed file, an unknown key, rule or threshold is an error listing the valid names, never a silent fallback to defaults; `--no-pyproject` ignores the table.

```toml
[tool.spaghetti]
exclude = ["tests/", "migrations/"]
fail-on = "error"                        # error | warning | info | never
baseline = ".spaghetti-baseline.json"    # relative to this file
snapshot-store = ".spaghetti/snapshots.jsonl"  # relative to this file
cache = true                             # incremental per-file cache (--cache)
cache-dir = ".spaghetti/cache"           # relative to this file
library-packages = ["my-lib"]            # packages `transport-in-library` applies to

[tool.spaghetti.packages]                # same mapping as --config's `packages:`
my-lib = "src/my_lib"

[tool.spaghetti.thresholds]              # any numeric constant in config.rs / config.py, kebab-case
max-function-lines = 60
complexity-threshold = 12

[tool.spaghetti.rules]                   # "off", or a severity override
magic-number = "off"
missing-return-type = "error"

[tool.spaghetti.layers.my-lib]           # path prefix inside the package -> forbidden import prefixes
"routes/" = ["my_lib.db."]

[[tool.spaghetti.contracts]]             # architecture contracts, see below
name = "domain stays framework-free"
type = "forbidden"
source = ["my_lib.domain"]
forbidden = ["my_lib.transport", "fastapi"]
```

See the Python README's [Configuration](https://github.com/lvalverdeb/spaghetti#configuration) section for the full key reference. (In YAML, quote `"off"` — bare `off` is a boolean in YAML 1.1, and both implementations reject it.)

## Baseline

```bash
spaghetti --baseline .spaghetti-baseline.json --update-baseline   # accept everything, once
spaghetti --baseline .spaghetti-baseline.json                      # from now on: new findings only
```

Set `baseline` in `[tool.spaghetti]` and the flag becomes unnecessary. Findings are matched by `fingerprint`, so they survive line shifts. Known findings are hidden from the report and the exit code; entries no longer matched are listed as fixed (in the JSON `baseline.fixed` and the text summary). The file format is identical to the Python original's (`schema_version` 1), so either binary can write or read it.

## Changed Lines Only

```bash
spaghetti --diff-base origin/main
```

Reports only findings whose span touches a line added or modified since the ref (working tree included), via `git diff -U0 REF`. The summary states how many findings the filter hid. Not a git repository or an unknown ref is a usage error (exit 2).

## SARIF

`--format sarif` emits SARIF 2.1.0 — rule metadata for every default-on rule, character columns, the fingerprint under `partialFingerprints["spaghetti/v1"]`, `baselineState` when a baseline is in use, and inline `# spaghetti-ignore` suppressions as suppressed results with their justification. Upload it with `github/codeql-action/upload-sarif`; see the Python README's [SARIF section](https://github.com/lvalverdeb/spaghetti#sarif-and-github-code-scanning) for the Action and pre-commit wiring.

## Editor integration

SARIF is the supported path. Install a SARIF viewer (VS Code: *SARIF Viewer* by Microsoft;
JetBrains: *Qodana*/SARIF import) and point it at `spaghetti --format sarif > spaghetti.sarif`;
findings land in the Problems panel with the fix hint as the message. An LSP server is not
planned unless users ask: the smells here are file- and workspace-level, and a save-time scan of
one package takes about a second.

## Agents: the MCP server

`spaghetti mcp` serves five tools over the Model Context Protocol on stdio so a coding agent can
ask "what should I fix in this package and how" and get the answer as data, including the
refactoring pattern per rule — the thing the fix hints were written for.

```bash
claude mcp add spaghetti -- spaghetti mcp          # Claude Code
# Cursor / other clients: command "spaghetti", args ["mcp"]
```

| Tool | Returns |
|---|---|
| `plan` | The remediation plan as data: priority, rule, severity, effort, files, **fix pattern**, plus every finding. Start here. |
| `scan` | The JSON report (grades, scores, findings with fingerprints). |
| `explain_rule` | Why a rule matters, how to fix it, its thresholds and equivalents elsewhere. |
| `compare` | Delta against a stored snapshot: introduced, fixed, files worse. |
| `baseline` | `status` of the baseline, or `update` it from the current scan. |

Each scan tool runs this binary in a child process in the given `path`, so the project's own
`[tool.spaghetti]` settings apply. The same structured plan is available from the shell with
`spaghetti --plan --json`. The protocol (newline-delimited JSON-RPC 2.0, protocol version
`2025-06-18`), the tool schemas and the rule documentation behind `explain_rule` are the Python
original's, reply for reply.

## Architecture contracts

The custom rule most teams want is "this must not import that". Declare it; spaghetti evaluates
it on the import graph it already builds and reports `contract-violation` (error).

```toml
[[tool.spaghetti.contracts]]
name = "domain stays framework-free"
type = "forbidden"
source = ["shop.domain"]                    # modules under these prefixes…
forbidden = ["shop.transport", "fastapi"]   # …may not import these (third-party too)
allow = ["fastapi.encoders"]                # …except these

[[tool.spaghetti.contracts]]
name = "clean layering"
type = "layers"
layers = ["shop.api", "shop.service", "shop.domain"]   # highest first; lower may not import higher
```

Prefixes match whole dotted segments (`shop.domain` matches `shop.domain.order`, not
`shop.domainx`). This is the import-linter / Tach feature without a second tool or config file.
The same list is accepted under `contracts:` in the `--config` YAML.

## Trend, Compare, Hotspots and the HTML Report

Linters answer "what is wrong now". These answer "is it getting better, what did this
change do, and where should the effort go".

```bash
spaghetti --snapshot                       # append this run to .spaghetti/snapshots.jsonl
spaghetti --compare latest                 # delta vs the last snapshot: score, introduced, fixed, files worse
spaghetti --compare ~3                     # vs three snapshots back; a SHA or timestamp prefix also works
spaghetti --hotspots                       # files ranked by health penalty × git change frequency
spaghetti --hotspots --plan                # the remediation plan, weighted by that churn
spaghetti --format html > report.html      # one self-contained page: scorecard, trend, hotspots, findings
```

- **Snapshots** record the git SHA, timestamp, per-package scores, per-file penalties and
  every finding's fingerprint. The store is a JSONL file (`--snapshot-store`, or
  `snapshot-store` in `[tool.spaghetti]`), so it diffs and merges like any text file. The
  format is the Python original's: either binary reads a store the other wrote.
- **Compare** matches findings by fingerprint, so a finding that moved lines is neither
  introduced nor fixed. The JSON report gains a `compare` object; the text and HTML reports
  a summary line plus the introduced and fixed lists. Run it in CI with `--snapshot` on the
  default branch and `--compare latest` on PRs. An empty store or an unmatched reference is a
  usage error (exit 2).
- **Hotspots** are CodeScene's idea: a file that is both tangled and actively edited is
  where remediation pays off; a tangled file nobody touches can wait. Change frequency is
  commits touching the file in the last `--churn-months` (default 6, or the
  `hotspot-window-months` threshold) with the author count alongside. Each finding's priority
  in `--plan` is multiplied by a factor between 1 (file untouched) and 2 (the repository's
  most-edited file), log-scaled, so P0 means "worst *and* hottest".
- **HTML** needs no server or account. Trend sparklines come from the snapshot store when
  one exists.

## Incremental cache

```bash
spaghetti --cache                 # per-file results reused when content and settings are unchanged
spaghetti --cache-dir .cache/sp   # elsewhere (implies --cache); or `cache = true` in [tool.spaghetti]
```

Same design as the Python original: entries live under a directory named by a hash of the applied
settings, the tool version and the Python language version, so a threshold change or an upgrade
invalidates everything at once. A hit skips the thirty-odd per-file checks; the file is still
parsed because the cross-file checks need the tree, and those always run. Writes are atomic (temp
file + rename), a damaged entry is a miss, never an error, and stderr reports
`Cache: N hit(s), M miss(es) in DIR/KEY`. On the benchmark corpus (11-core laptop) a warm run
takes 2.7 s against 3.5 s uncached and 4.4 s cold (writing the entries); the remainder is the
workspace-wide clone detection, which always runs.

Differences from the Python port, both deliberate: the configuration key has the same structure
(`{"schema", "tool", "python", "overrides"}`, canonical JSON, first 16 hex digits of its SHA-1) but
its `tool` is `"<version>-rs"`, so the two ports never read each other's entries even in the same
`.spaghetti/cache`; and an entry is named by the SHA-1 of the file's package, path and content
rather than the content alone, because several per-file checks depend on the path (test files,
`__init__.py`, the module path behind `potential-circular-import`, layer rules) — two identical
files at different paths must not share findings. The entry JSON has the same shape as Python's
(`schema_version` 1), so either can be inspected the same way.

## Performance, robustness and conformance

- **Benchmark.** The Python repo's `scripts/bench.py --rust BIN` scans django, pandas and airflow
  (1.07 M lines, pinned in its `scripts/corpus.lock`). On an 11-core laptop the Rust port takes
  8.2 s for all three in the published table ([docs/benchmark.md](https://github.com/lvalverdeb/spaghetti/blob/main/docs/benchmark.md)),
  against 81.6 s for Python; scanning each package's files in parallel brought that to 3.5 s in
  this release. CI runs it with `--rust-budget 15` (the ROADMAP budget: 15 s for Rust, 90 s for
  Python, on the 4-core GitHub runner, where the first run measured 11.9 s).
- **Limits.** A file over `max-file-bytes` (1 MiB) or nested past the point where the Python
  port's recursive checks hit CPython's recursion limit yields one `scan-limit` info finding
  instead of a stall; the Rust checks are iterative where depth is unbounded and the scanner runs
  on large-stack threads, so even a 1 MiB expression nested a million levels deep is reported,
  never a crash. CPython's tokenizer limits (NUL bytes, a BOM, more than 200 nested brackets, a
  hundredth indentation level) are mirrored as `syntax-error`, as Python reports them.
- **Fuzzing.** `tests/fuzz.rs` (proptest) scans arbitrary bytes, Python-shaped token soup and
  randomly mutated programs; the property is that the scanner never panics and every input yields
  a well-formed report. It also runs the Python repo's fixed edge-case list (empty file, BOM,
  CRLF, NUL, 150 nested `if`s, 3000 nested brackets, 500 bases, 300 nested lambdas, 2000 call
  arguments, a 5000-term sum, lone-surrogate string annotations) and checks each yields exactly
  the findings Python reports. CI's fuzz job sets `SPAGHETTI_FUZZ_SECONDS=600`.
- **Conformance.** CI checks out the Python port next to this one and runs its
  `scripts/conformance.py --rust target/release/spaghetti`, which fails on any byte difference in
  `--json` or `--plan --json` over the whole corpus.

## Rules

All 47 catalogued rules from the Python original, across five tiers: 34 per-file AST checks (including `high-complexity` — McCabe cyclomatic complexity, identical to `radon cc` — and `high-cognitive-complexity` — SonarSource cognitive complexity, default 15 — plus `pass-through-method`, `layer-violation` driven by the `layers` setting and `transport-in-library` driven by `library-packages`), 3 source-text checks (`long-file`, `todo-marker`, `low-maintainability` — SEI/Radon Maintainability Index under 10; the per-package mean is also reported as `maintainability_index`), 3 infrastructure checks (`syntax-error`, `unreadable-file`, and `scan-limit` — info: a file over `max-file-bytes`, default 1 MiB, or nested past the analysis recursion limit is skipped and said so, rather than stalling the scan; infrastructure findings take their severity from the catalog), 3 cross-file package checks (`orphan-interface`, `duplicate-function-body`, `sync-async-duplication`) and 4 workspace checks run once over every registered package: `import-cycle` and `high-coupling` on the union import graph, so a cycle between two packages is found; `contract-violation` for the [architecture contracts](#architecture-contracts) you declare; and `duplicate-code`, a PMD-CPD-style type-2 clone detector over a normalised AST token stream that finds copies with renamed variables (default window 50 tokens, `min-clone-tokens`; `info` by default because duplication is a density signal and mature libraries carry deliberate copies). The rule catalog (`src/rules.rs`) mirrors Python's `rules.py` entry for entry. See the Python repo's [`SDD.md`](https://github.com/lvalverdeb/spaghetti/blob/main/SDD.md) for the full rule catalog, thresholds, and scoring formula — this port matches it exactly, not approximately.

### Rules off by default

The Python project's 2026-11 precision audit over five public codebases (httpx, rich, FastAPI, pydantic, black — see its [`docs/precision.md`](https://github.com/lvalverdeb/spaghetti/blob/main/docs/precision.md)) switched eight catalogued rules off by default; this port follows it exactly, so 39 rules run out of the box and SARIF lists those 39. The others — `low-cohesion`, `missing-else`, `pass-through-method`, `magic-string`, `magic-number`, `star-import`, `unused-import` and `potential-circular-import` — are kept in the catalog and re-enabled per rule by naming them in `[tool.spaghetti.rules]` with a severity (an `"off"` entry keeps them off):

```toml
[tool.spaghetti.rules]
magic-number = "warning"   # opt back in, reported as a warning
```

The same audit narrowed several default-on rules (all mirrored here): `too-many-params` counts only required positional parameters; `boolean-flag-params` counts only positional booleans; `lazy-class` exempts any class with a base, keyword or decorator; `global-mutable` skips `UPPER_CASE` constants; `deep-inheritance` skips exception hierarchies; `encapsulation-violation` allows a class to reach into another instance of itself; `swallowed-exception` skips handlers that carry a comment; `scope-mutation` reports `global` only; `duplicate-function-body` skips dunder methods; `star-import` skips `__init__.py`; and the import graph behind `import-cycle`/`high-coupling` ignores `if __name__ == "__main__":` blocks and resolves `from pkg import name` to the submodule `pkg.name` when one exists.

**2.0 metric break.** Cyclomatic complexity is now McCabe-exact (Radon's rules: `match` arms, ternaries, comprehension clauses, `try/else`, no `with`). Scores and `high-complexity`/`god-class` findings shift accordingly; regenerate baselines when upgrading from 1.x.

## Development

```bash
cargo build --release
cargo test
cargo clippy --all-targets
```

## License

MIT
