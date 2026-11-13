//! Text-based (non-AST) per-file checks — mirrors `checks/text_per_file.py`.

use crate::config::{TODO_RE, thresholds};
use crate::models::{Issue, Severity};
use crate::pyast::{py_splitlines, py_strip};
use std::path::Path;

pub fn check_long_file(source: &str, filepath: &Path, package: &str) -> Vec<Issue> {
    let max_file_lines = thresholds().max_file_lines;
    let count = py_splitlines(source).len();
    if count > max_file_lines {
        vec![Issue::new(
            filepath,
            1,
            Severity::Warning,
            "long-file",
            package,
            format!("File is {count} lines (max {max_file_lines})"),
        )]
    } else {
        Vec::new()
    }
}

pub fn check_todo_markers(source: &str, filepath: &Path, package: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (i, line) in py_splitlines(source).into_iter().enumerate() {
        if let Some(captures) = TODO_RE.captures(line) {
            let marker = &captures[1];
            let trimmed = py_strip(line);
            let snippet = if trimmed.chars().count() > 90 {
                let head: String = trimmed.chars().take(87).collect();
                format!("{head}...")
            } else {
                trimmed.to_string()
            };
            issues.push(Issue::new(
                filepath,
                i + 1,
                Severity::Info,
                "todo-marker",
                package,
                format!("{marker} marker: {snippet}"),
            ));
        }
    }
    issues
}
