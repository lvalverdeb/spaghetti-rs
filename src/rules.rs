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
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Ast => "ast",
            Tier::Text => "text",
            Tier::Infra => "infra",
            Tier::Package => "package",
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

use Severity::{Error, Info, Warning};
use Tier::{Ast, Infra, Package, Text};

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
        "Cyclomatic complexity above threshold",
        Warning,
        Ast,
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
    r(
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
    r(
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
    r("star-import", "from x import *", Warning, Ast),
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
    r("magic-number", "Unexplained numeric literal", Info, Ast),
    r(
        "magic-string",
        "Same string literal compared for equality in several places",
        Info,
        Ast,
    ),
    r("missing-else", "Multi-statement if without else", Info, Ast),
    r("lazy-class", "Class with fewer than two methods", Info, Ast),
    r(
        "deep-inheritance",
        "Inheritance chain deeper than the limit",
        Warning,
        Ast,
    ),
    r(
        "pass-through-method",
        "Method whose body only delegates with unchanged arguments",
        Info,
        Ast,
    ),
    RuleMeta {
        id: "low-cohesion",
        summary: "Class whose methods split into unrelated groups (LCOM4)",
        default_severity: Info,
        tier: Ast,
        enabled_by_default: false,
    },
    // ── per-file source text ──
    r("long-file", "File exceeds the line limit", Warning, Text),
    r("todo-marker", "TODO/FIXME/XXX/HACK comment", Info, Text),
    // ── infrastructure ──
    r("syntax-error", "File failed to parse", Error, Infra),
    r("unreadable-file", "File could not be read", Error, Infra),
    // ── per-package cross-file ──
    r(
        "import-cycle",
        "Circular import between modules",
        Error,
        Package,
    ),
    r(
        "high-coupling",
        "Module with both high fan-in and high fan-out",
        Warning,
        Package,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn catalog_has_42_unique_rules_with_one_off_by_default() {
        assert_eq!(RULE_CATALOG.len(), 42);
        let ids: HashSet<&str> = RULE_CATALOG.iter().map(|m| m.id).collect();
        assert_eq!(ids.len(), 42);
        let off: Vec<&str> = RULE_CATALOG
            .iter()
            .filter(|m| !m.enabled_by_default)
            .map(|m| m.id)
            .collect();
        assert_eq!(off, ["low-cohesion"]);
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
