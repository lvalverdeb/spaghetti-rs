//! Health scoring and remediation planning — mirrors `scoring.py`.

use crate::models::{Issue, RemediationStep, ScanResult, Severity, display_path};
use std::collections::HashMap;
use std::path::Path;

fn severity_weight(s: Severity) -> f64 {
    match s {
        Severity::Error => 6.0,
        Severity::Warning => 1.5,
        Severity::Info => 0.3,
    }
}

/// A rough 0-100 health score, weighted by severity and normalized per
/// 1,000 lines so larger packages aren't unfairly penalized.
pub fn compute_score(result: &ScanResult) -> (f64, &'static str) {
    if result.total_lines == 0 {
        return (100.0, "A");
    }
    let penalty: f64 = result
        .issues
        .iter()
        .map(|i| severity_weight(i.severity))
        .sum();
    let penalty_per_kloc = penalty / (result.total_lines as f64 / 1000.0);
    let score = (100.0 - penalty_per_kloc).max(0.0);
    let grade = if score >= 90.0 {
        "A"
    } else if score >= 75.0 {
        "B"
    } else if score >= 60.0 {
        "C"
    } else if score >= 40.0 {
        "D"
    } else {
        "F"
    };
    (score, grade)
}

// ── Remediation Priority ─────────────────────────────────────────────────────

fn fix_effort(rule: &str) -> f64 {
    match rule {
        "import-cycle" => 5.0,
        "layer-violation" => 4.0,
        "transport-in-library" => 4.0,
        "god-class" => 5.0,
        "god-module" => 4.0,
        "sync-async-duplication" => 3.0,
        "duplicate-function-body" => 3.0,
        "long-function" => 2.5,
        "high-complexity" => 3.0,
        "deep-nesting" => 2.0,
        "too-many-params" => 2.0,
        "boolean-flag-params" => 1.5,
        "excessive-returns" => 1.5,
        "missing-return-type" => 1.0,
        "missing-param-type" => 0.5,
        "untyped-dict" => 0.5,
        "unused-import" => 0.5,
        "star-import" => 0.5,
        "potential-circular-import" => 2.5,
        "swallowed-exception" => 1.5,
        "bare-except" => 1.0,
        "mutable-default" => 0.5,
        "scope-mutation" => 2.0,
        "global-mutable" => 1.5,
        "encapsulation-violation" => 1.0,
        "long-file" => 2.5,
        "todo-marker" => 0.5,
        "syntax-error" => 1.0,
        "dead-code" => 0.5,
        "magic-number" => 0.5,
        "missing-else" => 0.5,
        "lazy-class" => 1.5,
        "deep-inheritance" => 3.0,
        "message-chain" => 1.0,
        "excessive-decorators" => 1.0,
        "pass-through-method" => 1.0,
        "orphan-interface" => 1.5,
        _ => 1.0,
    }
}

const PRIORITY_LEVELS: &[(f64, &str, &str)] = &[
    (12.0, "P0", "CRITICAL — fix immediately"),
    (7.0, "P1", "HIGH — fix this sprint"),
    (3.0, "P2", "MEDIUM — plan for next cycle"),
    (0.0, "P3", "LOW — track in backlog"),
];

/// Priority score = severity_weight x fix_effort.
pub fn compute_priority_score(issue: &Issue) -> f64 {
    severity_weight(issue.severity) * fix_effort(issue.rule)
}

fn effort_label(effort: f64) -> &'static str {
    if effort >= 4.0 {
        "major"
    } else if effort >= 2.5 {
        "moderate"
    } else if effort >= 1.0 {
        "minor"
    } else {
        "trivial"
    }
}

fn priority_label(score: f64) -> (&'static str, &'static str) {
    for (threshold, level, desc) in PRIORITY_LEVELS {
        if score >= *threshold {
            return (level, desc);
        }
    }
    ("P3", "LOW — track in backlog")
}

/// Groups issues by rule, computes priority scores, and returns an ordered
/// list of `RemediationStep`s — mirrors `build_remediation_plan`.
pub fn build_remediation_plan(
    issues: &[&Issue],
    workspace_root: Option<&Path>,
) -> Vec<RemediationStep> {
    let mut by_rule: HashMap<&'static str, Vec<&Issue>> = HashMap::new();
    for issue in issues {
        by_rule.entry(issue.rule).or_default().push(issue);
    }

    let mut steps: Vec<RemediationStep> = Vec::new();
    for (rule, rule_issues) in by_rule {
        let effort = fix_effort(rule);
        let max_sev_issue = rule_issues
            .iter()
            .max_by(|a, b| severity_weight(a.severity).total_cmp(&severity_weight(b.severity)))
            .unwrap();
        let score = severity_weight(max_sev_issue.severity) * effort;
        let (priority, _) = priority_label(score);

        let mut files: Vec<String> = rule_issues
            .iter()
            .map(|i| display_path(&i.file, workspace_root))
            .collect();
        files.sort();
        files.dedup();

        steps.push(RemediationStep {
            priority,
            rule,
            severity: max_sev_issue.severity,
            effort: effort_label(effort),
            files,
            count: rule_issues.len(),
            description: rule_issues[0].message.clone(),
            score,
        });
    }

    steps.sort_by(|a, b| b.score.total_cmp(&a.score).then(b.count.cmp(&a.count)));
    steps
}

/// Renders a prioritized remediation plan as a text report — mirrors
/// `plan_report`.
pub fn plan_report(issues: &[&Issue], top: usize, workspace_root: Option<&Path>) -> String {
    let steps = build_remediation_plan(issues, workspace_root);
    let mut out = String::new();
    use std::fmt::Write as _;

    let _ = writeln!(out, "{}", "=".repeat(72));
    let _ = writeln!(out, "  REMEDIATION PLAN — Prioritized Fix Order");
    let _ = writeln!(out, "{}", "=".repeat(72));
    let _ = writeln!(out);

    if steps.is_empty() {
        let _ = writeln!(out, "  All clean — nothing to fix.");
        return out;
    }

    let mut by_priority: HashMap<&str, usize> = HashMap::new();
    for step in &steps {
        *by_priority.entry(step.priority).or_insert(0) += 1;
    }

    let _ = writeln!(out, "  Priority breakdown:");
    for (_, label, desc) in PRIORITY_LEVELS {
        if let Some(&count) = by_priority.get(label) {
            let _ = writeln!(out, "    {label}: {count} rule(s) — {desc}");
        }
    }
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "  {:<3} {:<4} {:<30} {:<4} {:<9} {:>6}  {:>5}",
        "#", "Pri", "Rule", "Sev", "Effort", "Issues", "Score"
    );
    let _ = writeln!(
        out,
        "  {} {} {} {} {} {}  {}",
        "─".repeat(3),
        "─".repeat(4),
        "─".repeat(30),
        "─".repeat(4),
        "─".repeat(9),
        "─".repeat(6),
        "─".repeat(5)
    );

    let shown = &steps[..steps.len().min(top)];
    for (idx, step) in shown.iter().enumerate() {
        let sev_icon = match step.severity {
            Severity::Error => "✖",
            Severity::Warning => "⚠",
            Severity::Info => "ℹ",
        };
        let mut file_preview = step
            .files
            .first()
            .cloned()
            .unwrap_or_else(|| "?".to_string());
        if step.files.len() > 1 {
            let _ = write!(file_preview, " +{}", step.files.len() - 1);
        }
        let _ = writeln!(
            out,
            "  {:<3} {:<4} {:<30} {:<4} {:<9} {:>6}  {:>5.1}",
            idx + 1,
            step.priority,
            step.rule,
            sev_icon,
            step.effort,
            step.count,
            step.score
        );
        let _ = writeln!(out, "      └─ {file_preview}");
    }

    if steps.len() > top {
        let _ = writeln!(
            out,
            "  ... and {} more rules (use --plan to see all)",
            steps.len() - top
        );
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "{}", "=".repeat(72));
    let _ = writeln!(out, "  RECOMMENDED FIX ORDER");
    let _ = writeln!(out, "{}", "=".repeat(72));
    let _ = writeln!(out);

    for (_, label, desc) in PRIORITY_LEVELS {
        let level_steps: Vec<&RemediationStep> =
            steps.iter().filter(|s| &s.priority == label).collect();
        if level_steps.is_empty() {
            continue;
        }
        let _ = writeln!(out, "  {label} — {desc}");
        for step in &level_steps {
            let plural = if step.count != 1 { "s" } else { "" };
            let _ = writeln!(
                out,
                "    • {} ({} issue{plural}, {} effort)",
                step.rule, step.count, step.effort
            );
        }
        let _ = writeln!(out);
    }

    out
}
