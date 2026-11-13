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
    /// 1-based character column of the finding's start, when the rule knows
    /// it. Checks record the raw byte column (what the parser reports);
    /// `scanner::scan_package` rewrites it to a character column centrally
    /// — mirrors `detector._normalize_columns`.
    pub column: Option<usize>,
    pub end_line: Option<usize>,
    /// 1-based character column just past the finding's end (exclusive).
    pub end_column: Option<usize>,
    /// Stable identity across line shifts and re-runs — see
    /// `scanner::assign_fingerprints` (mirrors `detector._assign_fingerprints`).
    pub fingerprint: String,
    /// Human-supplied justification from a `# spaghetti-ignore: ...` marker.
    /// Only ever set on issues that ended up in `ScanResult::ignored`.
    pub reason: Option<String>,
}

impl Issue {
    /// An issue with no precise location (`column`/`end_*` all `None`) and
    /// no fingerprint yet — the shape every check produces before
    /// `scan_package` assigns fingerprints. Rules that know their node's
    /// span fill the location fields in afterwards.
    pub fn new(
        file: &Path,
        line: usize,
        severity: Severity,
        rule: &'static str,
        package: &str,
        message: String,
    ) -> Self {
        Issue {
            file: file.to_path_buf(),
            line,
            severity,
            rule,
            message,
            package: package.to_string(),
            column: None,
            end_line: None,
            end_column: None,
            fingerprint: String::new(),
            reason: None,
        }
    }
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

    /// Fold `other` into this result (the all-packages total) — mirrors
    /// `ScanResult.extend`. Borrows, so the per-package results stay intact
    /// for the per-package scorecard/JSON stats.
    pub fn extend(&mut self, other: &ScanResult) {
        self.issues.extend(other.issues.iter().cloned());
        self.files_scanned += other.files_scanned;
        self.functions_scanned += other.functions_scanned;
        self.total_lines += other.total_lines;
        self.suppressed += other.suppressed;
        self.ignored.extend(other.ignored.iter().cloned());
    }
}
