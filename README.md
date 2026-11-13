# spaghetti

Spaghetti code and architectural-smell detector **for Python codebases**, implemented in Rust.

This is a from-scratch reimplementation of [`spaghetti-detector`](https://github.com/lvalverdeb/spaghetti) (the Python original) — not a wrapper or FFI binding. It parses and scans Python source directly, with no Python runtime dependency, producing a single native binary you can drop into any CI image or pre-commit hook with nothing else installed. Scans workspace packages for anti-patterns, architectural violations, and structural code smells — from single-function issues (long functions, deep nesting, high cyclomatic complexity) up to whole-package issues that only show up once you can see across files: real circular imports (not just a parent/child heuristic), copy-pasted function bodies, and the sync/async "twin" duplication pattern (`load`/`aload`, `foo`/`foo_async`) where a fix applied to one twin silently never reaches the other.

The [Python original](https://github.com/lvalverdeb/spaghetti) remains the actively maintained **spec of record**: when the two disagree, the Python behaviour is correct by definition and this is a bug here, not there. See [`RUST_PORT_PROPOSAL.md`](https://github.com/lvalverdeb/spaghetti/blob/main/RUST_PORT_PROPOSAL.md) in the Python repo for the full design rationale, phased build history, and every behavioural quirk (some quite subtle — e.g. `difflib.SequenceMatcher.ratio()`'s asymmetry under `autojunk`) uncovered and matched along the way.

**Status**: all 42 catalogued rules ported and verified — `--json`, `--format sarif`, `--plan` and the baseline file are byte-for-byte identical to Python's output on the same input (Phase 1 of the Python [ROADMAP](https://github.com/lvalverdeb/spaghetti/blob/main/ROADMAP.md): settings, baseline, changed-lines mode, SARIF, `--fail-on`), and output is reproducible run-to-run.

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
```

Exit codes: `0` (clean), `1` (warnings present), `2` (errors present) — safe to wire into CI as a gate. `--fail-on error|warning|info|never` picks the lowest severity that makes the exit code non-zero (default `warning`); the code is computed on the findings that survive the baseline and `--diff-base` filters, not on the `--severity` display floor. Usage and settings errors exit `2` with a message on stderr.

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `--config` | none | YAML settings file (same keys as `[tool.spaghetti]`); its `packages: {name: path}` mapping replaces the pyproject one |
| `--package` | none | Add or override one package as `NAME=PATH` (repeatable); applied on top of `--config` or the defaults |
| `--packages` | all resolved packages | Names to scan from the resolved registry |
| `--severity` | `info` | Minimum severity to display (`info` / `warning` / `error`) |
| `--format` | `text` | `text`, `json`, or `sarif` (SARIF 2.1.0 for code-scanning tools) |
| `--json` | off | Shorthand for `--format json` |
| `--fail-on` | `warning` | Lowest severity that makes the exit code non-zero; `never` always exits 0 |
| `--baseline` | from settings | Baseline file of accepted findings; see [Baseline](#baseline) |
| `--update-baseline` | off | Write every current finding to the baseline file and exit 0 |
| `--diff-base` | none | Git ref; report only findings on lines added or changed since it |
| `--no-pyproject` | off | Ignore any `[tool.spaghetti]` table found above the working directory |
| `--quiet` / `-q` | off | Suppress the report banner (text-report mode only; `--json` is unaffected) |
| `--top` | `5` | Number of worst files/rules to list |
| `--exclude` | none | Path substrings to exclude from scanning |
| `--min-duplicate-lines` | `5` | Minimum function length to consider for duplicate-body detection |
| `--twin-similarity` | `0.6` | Minimum text-similarity ratio (0–1) to flag a sync/async twin pair |
| `--plan` | off | Output a prioritised remediation plan instead of the standard report |
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
  "summary": { "grade": "B", "score": 89.8, "files": 13, "lines": 4137, "functions": 168, "issues": 33, "errors": 0, "warnings": 27, "infos": 6 },
  "packages": {
    "my-lib": { "grade": "B", "score": 89.8, "files": 13, "lines": 4137, "functions": 168, "issues": 33, "errors": 0, "warnings": 27, "infos": 6 }
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

## Configuration

Settings live in `pyproject.toml` under `[tool.spaghetti]` (found by walking up from the working directory) and/or in the YAML file passed to `--config` — the same files, keys and precedence as the Python original (defaults < `pyproject.toml` < `--config` < CLI flags). A malformed file, an unknown key, rule or threshold is an error listing the valid names, never a silent fallback to defaults; `--no-pyproject` ignores the table.

```toml
[tool.spaghetti]
exclude = ["tests/", "migrations/"]
fail-on = "error"                        # error | warning | info | never
baseline = ".spaghetti-baseline.json"    # relative to this file
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

## Rules

All 42 catalogued rules from the Python original: 33 per-file AST checks (including `pass-through-method`, `layer-violation` driven by the `layers` setting and `transport-in-library` driven by `library-packages`), 2 source-text checks, 2 infrastructure checks (`syntax-error`, `unreadable-file`), and 5 cross-file package checks (`import-cycle`, `high-coupling`, `orphan-interface`, `duplicate-function-body`, `sync-async-duplication`). The rule catalog (`src/rules.rs`) mirrors Python's `rules.py` entry for entry. See the Python repo's [`SDD.md`](https://github.com/lvalverdeb/spaghetti/blob/main/SDD.md) for the full rule catalog, thresholds, and scoring formula — this port matches it exactly, not approximately.

### Rules off by default

The Python project's 2026-11 precision audit over five public codebases (httpx, rich, FastAPI, pydantic, black — see its [`docs/precision.md`](https://github.com/lvalverdeb/spaghetti/blob/main/docs/precision.md)) switched eight catalogued rules off by default; this port follows it exactly, so 34 rules run out of the box and SARIF lists those 34. The others — `low-cohesion`, `missing-else`, `pass-through-method`, `magic-string`, `magic-number`, `star-import`, `unused-import` and `potential-circular-import` — are kept in the catalog and re-enabled per rule by naming them in `[tool.spaghetti.rules]` with a severity (an `"off"` entry keeps them off):

```toml
[tool.spaghetti.rules]
magic-number = "warning"   # opt back in, reported as a warning
```

The same audit narrowed several default-on rules (all mirrored here): `too-many-params` counts only required positional parameters; `boolean-flag-params` counts only positional booleans; `lazy-class` exempts any class with a base, keyword or decorator; `global-mutable` skips `UPPER_CASE` constants; `deep-inheritance` skips exception hierarchies; `encapsulation-violation` allows a class to reach into another instance of itself; `swallowed-exception` skips handlers that carry a comment; `scope-mutation` reports `global` only; `duplicate-function-body` skips dunder methods; `star-import` skips `__init__.py`; and the import graph behind `import-cycle`/`high-coupling` ignores `if __name__ == "__main__":` blocks and resolves `from pkg import name` to the submodule `pkg.name` when one exists.

## Development

```bash
cargo build --release
cargo test
cargo clippy --all-targets
```

## License

MIT
