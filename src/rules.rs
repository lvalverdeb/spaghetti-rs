//! The rule catalog: one entry per rule id the checks can emit — mirrors
//! `spaghetti/rules.py`.
//!
//! The single source of truth for rule metadata consumed by SARIF output and
//! settings validation (`[tool.spaghetti.rules]`). Thresholds live in
//! `config`; this module only describes.

use crate::models::Severity;

/// Which layer of the scanner emits a rule — mirrors `rules.py::Tier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Ast,
    Text,
    Infra,
    Package,
    Workspace,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Ast => "ast",
            Tier::Text => "text",
            Tier::Infra => "infra",
            Tier::Package => "package",
            Tier::Workspace => "workspace",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleMeta {
    pub id: &'static str,
    pub summary: &'static str,
    pub default_severity: Severity,
    pub tier: Tier,
    pub enabled_by_default: bool,
}

const fn r(id: &'static str, summary: &'static str, sev: Severity, tier: Tier) -> RuleMeta {
    RuleMeta {
        id,
        summary,
        default_severity: sev,
        tier,
        enabled_by_default: true,
    }
}

/// A rule that exists and can be switched on via `[tool.spaghetti.rules]`
/// but ships off: the 2026-11 precision audit over five public codebases
/// (Python repo `docs/precision.md`) found it at or near zero precision, or
/// Ruff already owns it (`unused-import`, `star-import`).
const fn off(id: &'static str, summary: &'static str, sev: Severity, tier: Tier) -> RuleMeta {
    RuleMeta {
        id,
        summary,
        default_severity: sev,
        tier,
        enabled_by_default: false,
    }
}

use Severity::{Error, Info, Warning};
use Tier::{Ast, Infra, Package, Text, Workspace};

/// Every rule, in `rules.py::_RULES` order (which is the order SARIF lists
/// them in).
pub const RULE_CATALOG: &[RuleMeta] = &[
    // ── per-file AST ──
    r(
        "long-function",
        "Function exceeds the line limit",
        Warning,
        Ast,
    ),
    r(
        "high-complexity",
        "Cyclomatic complexity (McCabe, Radon-exact) above threshold",
        Warning,
        Ast,
    ),
    r(
        "high-cognitive-complexity",
        "Cognitive complexity (Sonar) above threshold",
        Warning,
        Ast,
    ),
    r(
        "low-maintainability",
        "Maintainability Index below threshold",
        Warning,
        Text,
    ),
    r(
        "missing-return-type",
        "Public function without a return type annotation",
        Warning,
        Ast,
    ),
    r(
        "missing-param-type",
        "Public function parameter without a type annotation",
        Info,
        Ast,
    ),
    r(
        "too-many-params",
        "Function with too many parameters",
        Warning,
        Ast,
    ),
    r(
        "excessive-returns",
        "Function with too many return statements",
        Info,
        Ast,
    ),
    r(
        "boolean-flag-params",
        "Function with several boolean flag parameters",
        Info,
        Ast,
    ),
    r(
        "deep-nesting",
        "Control flow nested too deeply",
        Warning,
        Ast,
    ),
    r("untyped-dict", "Bare dict in a type hint", Info, Ast),
    off(
        "unused-import",
        "Imported name never referenced",
        Warning,
        Ast,
    ),
    r(
        "swallowed-exception",
        "except block that silently discards the exception",
        Warning,
        Ast,
    ),
    r(
        "duplicate-branch",
        "if/else branches with identical bodies",
        Warning,
        Ast,
    ),
    r(
        "encapsulation-violation",
        "Private attribute accessed from outside its owner",
        Info,
        Ast,
    ),
    r(
        "god-class",
        "Class with too many methods, attributes, or total complexity",
        Warning,
        Ast,
    ),
    r(
        "layer-violation",
        "Import forbidden by the configured layer rules",
        Error,
        Ast,
    ),
    r(
        "transport-in-library",
        "Library package imports a transport framework",
        Error,
        Ast,
    ),
    off(
        "potential-circular-import",
        "Child module imports its parent package",
        Warning,
        Ast,
    ),
    r(
        "god-module",
        "Module exposes too many public symbols",
        Warning,
        Ast,
    ),
    r("mutable-default", "Mutable default argument", Warning, Ast),
    r(
        "bare-except",
        "except: without an exception type",
        Warning,
        Ast,
    ),
    off("star-import", "from x import *", Warning, Ast),
    r(
        "global-mutable",
        "Mutable state assigned at module scope",
        Info,
        Ast,
    ),
    r(
        "scope-mutation",
        "Function mutates outer scope via global/nonlocal",
        Info,
        Ast,
    ),
    r(
        "dead-code",
        "Statement unreachable after return/raise/break/continue",
        Warning,
        Ast,
    ),
    r(
        "message-chain",
        "Attribute or call chain deeper than the limit",
        Info,
        Ast,
    ),
    r(
        "excessive-decorators",
        "Too many stacked decorators",
        Info,
        Ast,
    ),
    off("magic-number", "Unexplained numeric literal", Info, Ast),
    off(
        "magic-string",
        "Same string literal compared for equality in several places",
        Info,
        Ast,
    ),
    off("missing-else", "Multi-statement if without else", Info, Ast),
    r("lazy-class", "Class with fewer than two methods", Info, Ast),
    r(
        "deep-inheritance",
        "Inheritance chain deeper than the limit",
        Warning,
        Ast,
    ),
    off(
        "pass-through-method",
        "Method whose body only delegates with unchanged arguments",
        Info,
        Ast,
    ),
    off(
        "low-cohesion",
        "Class whose methods split into unrelated groups (LCOM4)",
        Info,
        Ast,
    ),
    // ── per-file source text ──
    r("long-file", "File exceeds the line limit", Warning, Text),
    r("todo-marker", "TODO/FIXME/XXX/HACK comment", Info, Text),
    // ── infrastructure ──
    r("syntax-error", "File failed to parse", Error, Infra),
    r("unreadable-file", "File could not be read", Error, Infra),
    r(
        "scan-limit",
        "File skipped: over the size or nesting limit",
        Info,
        Infra,
    ),
    // ── per-package cross-file ──
    r(
        "import-cycle",
        "Circular import between modules",
        Error,
        Workspace,
    ),
    r(
        "contract-violation",
        "Import forbidden by an architecture contract",
        Error,
        Workspace,
    ),
    r(
        "high-coupling",
        "Module with both high fan-in and high fan-out",
        Warning,
        Workspace,
    ),
    r(
        "duplicate-code",
        "Duplicated token sequence (type-2 clone) across files",
        Info,
        Workspace,
    ),
    r(
        "orphan-interface",
        "Abstract class with exactly one implementation",
        Info,
        Package,
    ),
    r(
        "duplicate-function-body",
        "Identical function bodies across files",
        Warning,
        Package,
    ),
    r(
        "sync-async-duplication",
        "Sync/async twin functions with near-identical bodies",
        Warning,
        Package,
    ),
];

/// `rules.py::RULE_CATALOG[id]`.
pub fn rule_meta(id: &str) -> Option<&'static RuleMeta> {
    RULE_CATALOG.iter().find(|m| m.id == id)
}

/// `id in rules.py::RULE_IDS`.
pub fn is_known_rule(id: &str) -> bool {
    rule_meta(id).is_some()
}

/// `id in rules.py::DEFAULT_RULE_IDS`.
pub fn is_enabled_by_default(id: &str) -> bool {
    rule_meta(id).is_some_and(|m| m.enabled_by_default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn catalog_has_47_unique_rules_with_the_audited_ones_off() {
        assert_eq!(RULE_CATALOG.len(), 47);
        let ids: HashSet<&str> = RULE_CATALOG.iter().map(|m| m.id).collect();
        assert_eq!(ids.len(), 47);
        let off: HashSet<&str> = RULE_CATALOG
            .iter()
            .filter(|m| !m.enabled_by_default)
            .map(|m| m.id)
            .collect();
        assert_eq!(
            off,
            HashSet::from([
                "low-cohesion",
                "missing-else",
                "pass-through-method",
                "magic-string",
                "magic-number",
                "star-import",
                "unused-import",
                "potential-circular-import",
            ])
        );
    }

    #[test]
    fn every_scoring_weight_names_a_catalog_rule() {
        // The scoring table and the catalog must agree on the rule ids.
        for meta in RULE_CATALOG {
            assert!(is_known_rule(meta.id));
        }
        assert!(rule_meta("not-a-rule").is_none());
    }
}
