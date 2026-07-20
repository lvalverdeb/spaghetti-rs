//! Text-based (non-AST) per-file checks — mirrors `checks/text_per_file.py`.

use crate::config::{MAX_FILE_LINES, TODO_RE};
use crate::models::{Issue, Severity};
use std::path::Path;

pub fn check_long_file(source: &str, filepath: &Path, package: &str) -> Vec<Issue> {
    let count = source.lines().count();
    if count > MAX_FILE_LINES {
        vec![Issue {
            file: filepath.to_path_buf(),
            line: 1,
            severity: Severity::Warning,
            rule: "long-file",
            message: format!("File is {count} lines (max {MAX_FILE_LINES})"),
            package: package.to_string(),
            reason: None,
        }]
    } else {
        Vec::new()
    }
}

pub fn check_todo_markers(source: &str, filepath: &Path, package: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (i, line) in source.lines().enumerate() {
        if let Some(captures) = TODO_RE.captures(line) {
            let marker = &captures[1];
            let trimmed = line.trim();
            let snippet = if trimmed.chars().count() > 90 {
                let head: String = trimmed.chars().take(87).collect();
                format!("{head}...")
            } else {
                trimmed.to_string()
            };
            issues.push(Issue {
                file: filepath.to_path_buf(),
                line: i + 1,
                severity: Severity::Info,
                rule: "todo-marker",
                message: format!("{marker} marker: {snippet}"),
                package: package.to_string(),
                reason: None,
            });
        }
    }
    issues
}
