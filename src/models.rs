//! Core data models — mirrors `spaghetti/models.py`.

use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Issue {
    pub file: PathBuf,
    pub line: usize,
    pub severity: Severity,
    pub rule: &'static str,
    pub message: String,
    pub package: String,
    /// Human-supplied justification from a `# spaghetti-ignore: ...` marker.
    /// Only ever set on issues that ended up in `ScanResult::ignored`.
    pub reason: Option<String>,
}

/// Workspace-relative path when possible, absolute otherwise — mirrors
/// `models.py::_display_path`.
pub fn display_path(path: &Path, workspace_root: Option<&Path>) -> String {
    if let Some(root) = workspace_root
        && let Ok(rel) = path.strip_prefix(root)
    {
        return rel.display().to_string();
    }
    path.display().to_string()
}

/// Parameter Object bundling `scan_package`'s tunable knobs — mirrors
/// `models.py::ScanConfig`. Extracted so `scan_package`'s call sites share
/// one shape instead of four separate values threaded through in parallel.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub exclude: Vec<String>,
    pub min_duplicate_lines: usize,
    pub twin_similarity: f64,
    pub recursive: bool,
}

/// A single prioritized remediation action — mirrors `models.py`'s
/// `RemediationStep`.
#[derive(Debug, Clone)]
pub struct RemediationStep {
    pub priority: &'static str,
    pub rule: &'static str,
    pub severity: Severity,
    pub effort: &'static str,
    pub files: Vec<String>,
    pub count: usize,
    pub description: String,
    pub score: f64,
}

#[derive(Debug, Default)]
pub struct ScanResult {
    pub issues: Vec<Issue>,
    pub files_scanned: usize,
    pub functions_scanned: usize,
    pub total_lines: usize,
    pub suppressed: usize,
    /// Issues suppressed by an inline `# spaghetti-ignore` marker, kept (rather
    /// than discarded) so callers can audit *why* something was waived — each
    /// entry's `reason` is the text after the marker's `:`, or `None` if the
    /// marker didn't give one.
    pub ignored: Vec<Issue>,
}

impl ScanResult {
    pub fn error_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| i.severity == Severity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| i.severity == Severity::Warning)
            .count()
    }

    pub fn info_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| i.severity == Severity::Info)
            .count()
    }

    pub fn extend(&mut self, other: ScanResult) {
        self.issues.extend(other.issues);
        self.files_scanned += other.files_scanned;
        self.functions_scanned += other.functions_scanned;
        self.total_lines += other.total_lines;
        self.suppressed += other.suppressed;
        self.ignored.extend(other.ignored);
    }
}
