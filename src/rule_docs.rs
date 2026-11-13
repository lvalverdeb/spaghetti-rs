//! Per-rule documentation: why it matters, how to fix it, what else detects
//! it — mirrors `spaghetti/rule_docs.py` verbatim.
//!
//! Generated from the Python original's `RULE_DOCS`, which owns the prose and
//! the published `docs/rules/` pages: change the wording there and re-export it
//! here rather than editing these strings independently. The test below fails
//! when a catalogued rule has no entry.
//! `thresholds` names the `config` constants the rule reads.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleDoc {
    pub why: &'static str,
    pub fix: &'static str,
    pub equivalents: &'static [&'static str],
    pub thresholds: &'static [&'static str],
}

/// `(rule id, doc)` in the Python dict's order.
pub const RULE_DOCS: &[(&str, RuleDoc)] = &[
    (
        "long-function",
        RuleDoc {
            why: "A function that does not fit on a screen is hard to name, test and review; its length is usually several responsibilities sharing one scope.",
            fix: "Extract Method: name each block that has its own comment or blank-line separation and move it out, passing the few values it needs. Flat, sequential pipelines are tolerated up to a low nesting depth.",
            equivalents: &[
                "Pylint R0915 too-many-statements",
                "Ruff PLR0915",
                "SonarQube python:S138",
            ],
            thresholds: &["MAX_FUNCTION_LINES", "LONG_FUNCTION_FLAT_NESTING_MAX"],
        },
    ),
    (
        "high-complexity",
        RuleDoc {
            why: "Cyclomatic complexity counts independent paths; each one is a test case you owe and a branch a reader must hold in mind. Computed exactly as Radon does.",
            fix: "Replace branch ladders with a dispatch table or polymorphism, hoist guard clauses to the top and return early, and split the function along its decision clusters.",
            equivalents: &[
                "Ruff C901 (mccabe)",
                "Pylint R1260 too-complex",
                "SonarQube python:S1541",
                "Radon cc",
            ],
            thresholds: &["COMPLEXITY_THRESHOLD"],
        },
    ),
    (
        "high-cognitive-complexity",
        RuleDoc {
            why: "Sonar's cognitive complexity scores what makes code hard to *read* — nesting, breaks in linear flow, mixed boolean operators — rather than paths. It is the metric most correlated with reviewer effort.",
            fix: "Flatten nesting with early returns and extracted helpers; one condition per `if`; replace nested loops over the same data with a single comprehension or a generator pipeline.",
            equivalents: &["SonarQube python:S3776"],
            thresholds: &["COGNITIVE_COMPLEXITY_THRESHOLD"],
        },
    ),
    (
        "low-maintainability",
        RuleDoc {
            why: "The Maintainability Index folds Halstead volume, cyclomatic complexity, lines and comment ratio into one 0–100 number per file; below the threshold a file is dense, branchy *and* long at once.",
            fix: "Split the module by responsibility, then apply the complexity and length fixes to what remains. Adding comments alone raises MI only marginally.",
            equivalents: &["Radon mi", "Visual Studio Maintainability Index"],
            thresholds: &["MIN_MAINTAINABILITY_INDEX"],
        },
    ),
    (
        "long-file",
        RuleDoc {
            why: "A file past a few hundred lines is a module with several reasons to change; merge conflicts and import-time cost follow.",
            fix: "Split by cohesion: group the functions that share private helpers or state into their own module and re-export from the package `__init__` if the public path must stay.",
            equivalents: &["Pylint C0302 too-many-lines", "SonarQube python:S104"],
            thresholds: &["MAX_FILE_LINES"],
        },
    ),
    (
        "deep-nesting",
        RuleDoc {
            why: "Every nesting level is a precondition the reader must carry; past four or five the indentation itself hides which branch a line belongs to.",
            fix: "Invert conditions into guard clauses that `return`/`continue` early, extract the inner block into a named function, or replace nested loops with a comprehension.",
            equivalents: &[
                "Pylint R1702 too-many-nested-blocks",
                "SonarQube python:S134",
            ],
            thresholds: &["MAX_NESTING_DEPTH"],
        },
    ),
    (
        "excessive-returns",
        RuleDoc {
            why: "Many return points mean many ways the function can finish; the combination with branching makes the result type and invariants hard to state.",
            fix: "Collapse a branch ladder that returns different values into a dictionary lookup or a single result variable; keep early returns only for guard clauses.",
            equivalents: &[
                "Pylint R0911 too-many-return-statements",
                "Ruff PLR0911",
                "SonarQube python:S1142",
            ],
            thresholds: &["MAX_RETURNS"],
        },
    ),
    (
        "too-many-params",
        RuleDoc {
            why: "Long parameter lists are hard to call correctly and usually mean several values that travel together have no name of their own.",
            fix: "Introduce Parameter Object: bundle the related arguments into a dataclass (or pass the object they came from); make rarely used ones keyword-only with defaults. `self`, `cls`, `*args` and `**kwargs` do not count.",
            equivalents: &[
                "Pylint R0913 too-many-arguments",
                "Ruff PLR0913",
                "SonarQube python:S107",
            ],
            thresholds: &["MAX_FUNC_PARAMS"],
        },
    ),
    (
        "boolean-flag-params",
        RuleDoc {
            why: "Several boolean flags multiply the behaviours one function implements (2ⁿ) and read as `f(data, True, False, True)` at the call site.",
            fix: "Split into one function per behaviour, or replace the flags with an `Enum` or a small options dataclass; at minimum make them keyword-only.",
            equivalents: &["Ruff FBT001/FBT002 (flake8-boolean-trap)"],
            thresholds: &["MIN_BOOLEAN_FLAGS"],
        },
    ),
    (
        "missing-return-type",
        RuleDoc {
            why: "Without a return annotation callers guess, type checkers give up at the boundary, and the contract lives only in the docstring.",
            fix: "Annotate the return type; use `-> None` for procedures. Private (underscore) functions and tests are exempt.",
            equivalents: &["Ruff ANN201", "mypy --disallow-untyped-defs"],
            thresholds: &[],
        },
    ),
    (
        "missing-param-type",
        RuleDoc {
            why: "An unannotated public parameter forces every caller to read the body to learn what to pass.",
            fix: "Annotate the parameter; prefer `Protocol`s or ABCs over concrete classes when several types are accepted.",
            equivalents: &["Ruff ANN001"],
            thresholds: &[],
        },
    ),
    (
        "untyped-dict",
        RuleDoc {
            why: "A bare `dict` in a signature says nothing about keys or values; it is a type hole that spreads to everything downstream.",
            fix: "Write `dict[str, int]`, or better a `TypedDict` or dataclass when the keys are fixed.",
            equivalents: &["mypy --disallow-any-generics"],
            thresholds: &[],
        },
    ),
    (
        "swallowed-exception",
        RuleDoc {
            why: "An `except` that only `pass`es, logs nothing or returns a default hides failures until they surface somewhere unrelated.",
            fix: "Catch the narrowest type, handle it (log with context, substitute a value *and* say why) or re-raise. A comment or logging call inside the block satisfies the rule.",
            equivalents: &["Ruff S110 (try-except-pass)"],
            thresholds: &[],
        },
    ),
    (
        "bare-except",
        RuleDoc {
            why: "`except:` also catches `KeyboardInterrupt`, `SystemExit` and `MemoryError`, turning a clean shutdown into a hang.",
            fix: "Name the exception type you expect; use `except Exception:` only at a top-level boundary that logs and re-raises or exits.",
            equivalents: &["Ruff E722", "Pylint W0702 bare-except"],
            thresholds: &[],
        },
    ),
    (
        "duplicate-branch",
        RuleDoc {
            why: "Two branches with identical bodies mean the condition is irrelevant or one branch is a copy-paste bug waiting to diverge.",
            fix: "Delete the condition if both branches are truly the same; otherwise fix the branch that should differ.",
            equivalents: &["SonarQube python:S1871"],
            thresholds: &[],
        },
    ),
    (
        "duplicate-function-body",
        RuleDoc {
            why: "Two functions with byte-identical bodies across files will be fixed in one place and not the other.",
            fix: "Keep one, import it from the other module; if the copies must diverge, make the difference a parameter.",
            equivalents: &["SonarQube python:S4144"],
            thresholds: &["DEFAULT_MIN_DUPLICATE_LINES"],
        },
    ),
    (
        "duplicate-code",
        RuleDoc {
            why: "Type-2 clones (same structure, renamed identifiers and literals) are the duplication tools like PMD-CPD and Sonar report; renaming variables does not make a copy independent.",
            fix: "Extract the shared logic into one function parameterised by what differs; for test setup prefer fixtures or parametrisation over copied blocks.",
            equivalents: &["SonarQube duplicated blocks (CPD)", "PMD CPD", "jscpd"],
            thresholds: &["MIN_CLONE_TOKENS"],
        },
    ),
    (
        "sync-async-duplication",
        RuleDoc {
            why: "A sync/async twin pair whose bodies are near-identical doubles every bug fix, and the two drift apart silently.",
            fix: "Push the shared logic into pure helpers both variants call, or generate one from the other (`unasync`), or keep only the async variant and wrap it for sync callers.",
            equivalents: &[],
            thresholds: &["DEFAULT_TWIN_SIMILARITY", "MIN_TWIN_FUNCTION_LINES"],
        },
    ),
    (
        "god-class",
        RuleDoc {
            why: "A class with too many methods, attributes or total complexity is a module in disguise; everything depends on it and nobody dares change it.",
            fix: "Extract Class along the attribute clusters its methods actually use (the LCOM groups); delegate to the new collaborators instead of inheriting from them.",
            equivalents: &[
                "Pylint R0902 too-many-instance-attributes",
                "Pylint R0904 too-many-public-methods",
                "Ruff PLR0904",
            ],
            thresholds: &["MAX_CLASS_METHODS", "MAX_CLASS_ATTRS", "MAX_CLASS_WMC"],
        },
    ),
    (
        "lazy-class",
        RuleDoc {
            why: "A class with fewer than two methods is usually a record with ceremony, or a function that wanted to be a class.",
            fix: "Make it a `dataclass`/`NamedTuple` if it holds data, a plain function if it holds behaviour. Exceptions, Protocols, Enums and ABCs are exempt.",
            equivalents: &["Pylint R0903 too-few-public-methods"],
            thresholds: &["MIN_CLASS_METHODS"],
        },
    ),
    (
        "low-cohesion",
        RuleDoc {
            why: "LCOM4 counts the connected groups of methods that share attributes; more than one group means the class is several classes sharing a name.",
            fix: "Split along the groups the message lists; each becomes its own class, or the stateless group becomes module-level functions.",
            equivalents: &["CodeScene / SonarQube LCOM4 metric"],
            thresholds: &["MIN_METHODS_FOR_COHESION", "MIN_STATEFUL_METHOD_FRACTION"],
        },
    ),
    (
        "deep-inheritance",
        RuleDoc {
            why: "Behaviour inherited through four or more levels can only be understood by reading every ancestor; overrides interact in ways nobody designed.",
            fix: "Flatten: compose the behaviours as collaborators or mixins with one job each, and keep hierarchies to a base plus concrete leaves.",
            equivalents: &["Pylint R0901 too-many-ancestors"],
            thresholds: &["MAX_INHERITANCE_DEPTH"],
        },
    ),
    (
        "orphan-interface",
        RuleDoc {
            why: "An abstract class with exactly one implementation is speculative generality: an indirection paid for every day for a flexibility nobody uses.",
            fix: "Collapse the ABC into its only implementation; reintroduce the abstraction when the second implementation actually arrives.",
            equivalents: &[],
            thresholds: &[],
        },
    ),
    (
        "pass-through-method",
        RuleDoc {
            why: "A method whose body only forwards its unchanged arguments to another object is a Middle Man: one more place to update for no added meaning.",
            fix: "Let callers use the delegate directly, or give the method a reason to exist (validation, translation, a narrower interface). Intended Facades are the common false positive, which is why this rule ships off.",
            equivalents: &[],
            thresholds: &[],
        },
    ),
    (
        "encapsulation-violation",
        RuleDoc {
            why: "Reaching into `obj._private` from another class couples the reader to an implementation detail the owner may change without notice.",
            fix: "Add the operation to the owning class, or expose the value through a property or method that states the contract.",
            equivalents: &["Pylint W0212 protected-access", "Ruff SLF001"],
            thresholds: &[],
        },
    ),
    (
        "message-chain",
        RuleDoc {
            why: "`a.b().c.d()` couples the caller to the shape of three objects it does not own; a change in any of them breaks it (Law of Demeter).",
            fix: "Hide Delegate: ask the first object for what you need, or pass the final object in directly.",
            equivalents: &[],
            thresholds: &["MAX_MESSAGE_CHAIN_DEPTH"],
        },
    ),
    (
        "excessive-decorators",
        RuleDoc {
            why: "Many stacked decorators compose behaviours in an order the reader must simulate, and hide the function's real signature.",
            fix: "Combine them into one purpose-built decorator, or move cross-cutting concerns (caching, retry, auth) to the framework layer that owns them.",
            equivalents: &[],
            thresholds: &["MAX_DECORATORS"],
        },
    ),
    (
        "god-module",
        RuleDoc {
            why: "A module exporting too many public names has no theme; importers take the whole thing and the import graph fills with hubs.",
            fix: "Split into cohesive modules and give the package `__init__` an explicit `__all__` of what is genuinely public.",
            equivalents: &[],
            thresholds: &["MAX_PUBLIC_SYMBOLS"],
        },
    ),
    (
        "global-mutable",
        RuleDoc {
            why: "A mutable object at module scope is shared state across every importer and every test; it makes order-dependent bugs possible.",
            fix: "Make it immutable (tuple, frozenset, `Final` constant), or move it into an object that is created explicitly and passed where needed.",
            equivalents: &[],
            thresholds: &[],
        },
    ),
    (
        "scope-mutation",
        RuleDoc {
            why: "`global`/`nonlocal` writes mean a function's effect is not visible in its signature; callers cannot reason about it locally.",
            fix: "Return the new value and let the caller assign it, or hold the state in an object the function receives.",
            equivalents: &["Pylint W0603 global-statement", "Ruff PLW0603"],
            thresholds: &[],
        },
    ),
    (
        "dead-code",
        RuleDoc {
            why: "Statements after `return`/`raise`/`break`/`continue` never run; they are misleading at best and a sign of a botched edit at worst.",
            fix: "Delete them, or move them before the exit if they were meant to run.",
            equivalents: &["Pylint W0101 unreachable", "SonarQube python:S1763"],
            thresholds: &[],
        },
    ),
    (
        "mutable-default",
        RuleDoc {
            why: "A mutable default (`def f(x=[])`) is created once and shared by every call; the second caller sees the first caller's data.",
            fix: "Default to `None` and create the object inside the function, or use `dataclasses.field(default_factory=...)`.",
            equivalents: &["Ruff B006", "Pylint W0102 dangerous-default-value"],
            thresholds: &[],
        },
    ),
    (
        "magic-number",
        RuleDoc {
            why: "An unexplained literal carries a meaning the reader must reverse-engineer and is duplicated wherever the meaning is reused.",
            fix: "Name it as a module-level constant (or an `Enum` member) where the meaning lives. Off by default: index arithmetic and obvious constants dominate real hits.",
            equivalents: &[
                "Ruff PLR2004 magic-value-comparison",
                "SonarQube python:S109",
            ],
            thresholds: &[],
        },
    ),
    (
        "magic-string",
        RuleDoc {
            why: "The same string compared for equality in several places is a stringly-typed enum; a typo in one copy is a silent bug.",
            fix: "Replace with an `Enum` or a named constant. Off by default: domain vocabulary (schema keywords, token strings) is the usual hit.",
            equivalents: &["SonarQube python:S1192"],
            thresholds: &[],
        },
    ),
    (
        "missing-else",
        RuleDoc {
            why: "A multi-statement `if` without `else` leaves the negative path implicit; the reader cannot tell if it was considered.",
            fix: "Add the `else` (or a comment stating the fall-through is intended). Off by default: the audit found no true positives.",
            equivalents: &["SonarQube python:S126"],
            thresholds: &[],
        },
    ),
    (
        "todo-marker",
        RuleDoc {
            why: "TODO/FIXME/XXX/HACK markers are debt with no owner or date; they accumulate until nobody trusts them.",
            fix: "Turn each into a tracked issue and reference it, or do it now. Keep the marker only with the ticket id.",
            equivalents: &[
                "Ruff FIX001–FIX004 / TD",
                "Pylint W0511 fixme",
                "SonarQube python:S1135",
            ],
            thresholds: &[],
        },
    ),
    (
        "unused-import",
        RuleDoc {
            why: "An import nobody uses costs import time and misleads about dependencies.",
            fix: "Remove it. Off by default: Ruff F401 owns this and does it better.",
            equivalents: &["Ruff F401", "Pylint W0611"],
            thresholds: &[],
        },
    ),
    (
        "star-import",
        RuleDoc {
            why: "`from x import *` makes the namespace depend on another module's contents and defeats static analysis.",
            fix: "Import the names you use. Off by default: Ruff F403 owns this.",
            equivalents: &["Ruff F403", "Pylint W0401 wildcard-import"],
            thresholds: &[],
        },
    ),
    (
        "potential-circular-import",
        RuleDoc {
            why: "A child module importing its parent package often creates a cycle through the package `__init__`.",
            fix: "Import the sibling module directly. Off by default: `import-cycle` detects the real cycles on the workspace graph.",
            equivalents: &["Pylint R0401 cyclic-import (partial)"],
            thresholds: &[],
        },
    ),
    (
        "import-cycle",
        RuleDoc {
            why: "Modules that import each other can only be loaded in one order, break on `from x import name`, and cannot be tested or reused apart.",
            fix: "Move the shared types to a leaf module both import; invert the dependency with a `Protocol`; or make one import lazy inside the function that needs it.",
            equivalents: &["Pylint R0401 cyclic-import", "import-linter"],
            thresholds: &[],
        },
    ),
    (
        "high-coupling",
        RuleDoc {
            why: "A module with both high fan-in and high fan-out is a hub: every change in it ripples out, and every change around it ripples in.",
            fix: "Split the module so that the widely imported part (stable types, constants) is separate from the part that imports many others (orchestration).",
            equivalents: &["CodeScene / SonarQube afferent–efferent coupling"],
            thresholds: &["MAX_MODULE_FAN_IN", "MAX_MODULE_FAN_OUT"],
        },
    ),
    (
        "layer-violation",
        RuleDoc {
            why: "An import across a configured layer boundary (`[tool.spaghetti.layers]`) means the architecture on the whiteboard and the one in the code differ.",
            fix: "Depend on an abstraction the lower layer implements and inject it, or move the code to the layer it belongs to.",
            equivalents: &["import-linter forbidden contract", "Tach"],
            thresholds: &["MAX_CROSS_LAYER_IMPORTS"],
        },
    ),
    (
        "contract-violation",
        RuleDoc {
            why: "An import that breaks an architecture contract (`[[tool.spaghetti.contracts]]`, forbidden edges or ordered layers) is the custom rule teams actually want: the design decision, enforced.",
            fix: "Apply the Dependency Inversion Principle: depend on a `Protocol` the lower layer implements and inject it; or add the edge to `allow` if it is a deliberate exception.",
            equivalents: &["import-linter contracts", "Tach", "ArchUnit (Java)"],
            thresholds: &[],
        },
    ),
    (
        "transport-in-library",
        RuleDoc {
            why: "A library package importing a web framework can no longer be used without that framework, and its tests need an HTTP stack.",
            fix: "Keep transport (FastAPI, Flask, httpx…) in an adapter package; the library exposes plain functions and dataclasses the adapter calls.",
            equivalents: &["import-linter forbidden contract"],
            thresholds: &[],
        },
    ),
    (
        "syntax-error",
        RuleDoc {
            why: "A file that does not parse cannot be analysed, imported or run.",
            fix: "Fix the syntax; if the file targets a newer Python than the scanner runs on, run spaghetti on that interpreter.",
            equivalents: &["Pylint E0001 syntax-error"],
            thresholds: &[],
        },
    ),
    (
        "scan-limit",
        RuleDoc {
            why: "A file over the size limit or nested past the interpreter's recursion limit is almost always generated code or data; analysing it would cost minutes and say nothing about the hand-written code around it.",
            fix: "Exclude generated files with `exclude`, or raise `max-file-bytes` if the file is genuinely hand-written. Nothing in it was checked.",
            equivalents: &[],
            thresholds: &["MAX_FILE_BYTES"],
        },
    ),
    (
        "unreadable-file",
        RuleDoc {
            why: "A file that cannot be read (permissions, invalid encoding) is a blind spot in every report.",
            fix: "Fix permissions or re-encode as UTF-8; exclude generated or binary paths with `exclude`.",
            equivalents: &[],
            thresholds: &[],
        },
    ),
];

/// `RULE_DOCS.get(rule)`.
pub fn rule_doc(rule: &str) -> Option<&'static RuleDoc> {
    RULE_DOCS
        .iter()
        .find(|(id, _)| *id == rule)
        .map(|(_, doc)| doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RULE_CATALOG;

    #[test]
    fn every_rule_is_documented_and_nothing_else() {
        let mut documented: Vec<&str> = RULE_DOCS.iter().map(|(id, _)| *id).collect();
        let mut catalogued: Vec<&str> = RULE_CATALOG.iter().map(|r| r.id).collect();
        documented.sort_unstable();
        catalogued.sort_unstable();
        assert_eq!(documented, catalogued);
        let live = crate::config::Thresholds::default();
        for (rule, doc) in RULE_DOCS {
            assert!(doc.why.ends_with('.') && doc.fix.ends_with('.'), "{rule}");
            for name in doc.thresholds {
                assert!(live.get(name).is_some(), "{rule}: {name}");
            }
        }
    }
}
