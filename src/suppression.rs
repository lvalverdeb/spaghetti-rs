//! Inline `# spaghetti-ignore` suppression support — mirrors `suppression.py`.

use crate::config::SUPPRESS_MARKER_RE;
use crate::models::Issue;
use std::collections::HashSet;

/// Rules suppressed for 1-indexed `line_no`, or `None` if no marker applies.
/// `Some(empty set)` means "suppress all rules on this line".
fn suppressed_rules_at(source_lines: &[&str], line_no: usize) -> Option<HashSet<String>> {
    // Python checks (line_no - 1, line_no - 2) as 0-indexed offsets, i.e. the
    // issue's own line and the line directly above it.
    for offset in [1usize, 2] {
        if line_no < offset {
            continue;
        }
        let idx = line_no - offset;
        if idx >= source_lines.len() {
            continue;
        }
        if let Some(captures) = SUPPRESS_MARKER_RE.captures(source_lines[idx]) {
            return Some(match captures.get(1) {
                None => HashSet::new(),
                Some(m) if m.as_str().trim().is_empty() => HashSet::new(),
                Some(m) => m
                    .as_str()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            });
        }
    }
    None
}

pub fn is_suppressed(issue: &Issue, source_lines: &[&str]) -> bool {
    match suppressed_rules_at(source_lines, issue.line) {
        None => false,
        Some(rules) => rules.is_empty() || rules.contains(issue.rule),
    }
}
