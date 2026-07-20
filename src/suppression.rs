//! Inline `# spaghetti-ignore` suppression support — mirrors `suppression.py`.

use crate::config::SUPPRESS_MARKER_RE;
use crate::models::Issue;
use std::collections::HashSet;

/// A parsed `# spaghetti-ignore[rule1,rule2]: reason` marker.
/// `rules.is_empty()` means "suppress all rules on this line".
#[derive(Debug, Clone)]
pub struct Suppression {
    pub rules: HashSet<String>,
    pub reason: Option<String>,
}

/// Suppression marker in effect for 1-indexed `line_no`, or `None` if none applies.
fn suppression_at(source_lines: &[&str], line_no: usize) -> Option<Suppression> {
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
            let rules = match captures.get(1) {
                None => HashSet::new(),
                Some(m) if m.as_str().trim().is_empty() => HashSet::new(),
                Some(m) => m
                    .as_str()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            };
            let reason = captures
                .get(2)
                .map(|m| m.as_str().trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            return Some(Suppression { rules, reason });
        }
    }
    None
}

/// The `Suppression` covering `issue`, or `None` if it isn't suppressed.
pub fn is_suppressed(issue: &Issue, source_lines: &[&str]) -> Option<Suppression> {
    let sup = suppression_at(source_lines, issue.line)?;
    if !sup.rules.is_empty() && !sup.rules.contains(issue.rule) {
        return None;
    }
    Some(sup)
}
