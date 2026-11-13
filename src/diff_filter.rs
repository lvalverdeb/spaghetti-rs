//! Changed-lines mode (`--diff-base REF`): report only findings that touch
//! lines added or modified relative to a git ref — mirrors
//! `spaghetti/diff_filter.py`.
//!
//! This is the "new code" gate: a legacy repo can enforce rules on every pull
//! request without first paying down the existing backlog. Package-level
//! findings attributed to an unchanged file (an `import-cycle` reported on
//! `__init__.py`, say) are hidden like any other; the summary says how many
//! findings the filter hid so that is never silent.

use crate::models::Issue;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

static HUNK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@").unwrap());

/// git could not produce the diff (not a repo, unknown ref, git missing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffError(pub String);

impl fmt::Display for DiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DiffError {}

fn git(cwd: &Path, args: &[&str]) -> Result<String, DiffError> {
    // core.quotePath=false: otherwise a non-ASCII path appears in the diff
    // header quoted and octal-escaped and never matches a scanned file.
    let output = Command::new("git")
        .args(["-c", "core.quotePath=false"])
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                DiffError("git executable not found".to_string())
            } else {
                DiffError(e.to_string())
            }
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(DiffError(if stderr.is_empty() {
            format!("git {} failed", args.join(" "))
        } else {
            stderr
        }));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Absolute path → set of 1-based line numbers added or modified since
/// `base_ref`. Compares `base_ref` to the working tree (staged and unstaged
/// edits included), which is what a pre-commit hook or a PR check wants.
pub fn changed_lines(
    base_ref: &str,
    cwd: &Path,
) -> Result<HashMap<PathBuf, HashSet<usize>>, DiffError> {
    let toplevel = git(cwd, &["rev-parse", "--show-toplevel"])?;
    let toplevel = PathBuf::from(toplevel.trim());
    let toplevel = toplevel.canonicalize().unwrap_or(toplevel);
    let diff = git(
        cwd,
        &[
            "diff",
            "-U0",
            "--no-color",
            "--diff-filter=AMR",
            base_ref,
            "--",
        ],
    )?;
    Ok(parse_unified_diff(&diff, &toplevel))
}

pub fn parse_unified_diff(diff: &str, toplevel: &Path) -> HashMap<PathBuf, HashSet<usize>> {
    let mut changed: HashMap<PathBuf, HashSet<usize>> = HashMap::new();
    let mut current: Option<PathBuf> = None;
    // Split on "\n" only, trailing "\r" stripped, exactly like the Python
    // original: paths may contain U+2028 and other separators.
    for line in diff.split('\n') {
        let line = line.trim_end_matches('\r');
        if let Some(target) = line.strip_prefix("+++ ") {
            // git appends "\t" after a path that contains whitespace.
            let target = target.trim_end_matches('\t');
            if target == "/dev/null" {
                current = None;
                continue;
            }
            let target = target.strip_prefix("b/").unwrap_or(target);
            let path = toplevel.join(target);
            let path = path.canonicalize().unwrap_or(path);
            changed.entry(path.clone()).or_default();
            current = Some(path);
        } else if let Some(path) = &current
            && let Some(m) = HUNK_RE.captures(line)
        {
            let start: usize = m[1].parse().unwrap_or(0);
            let count: usize = m
                .get(2)
                .map(|c| c.as_str().parse().unwrap_or(0))
                .unwrap_or(1);
            changed
                .entry(path.clone())
                .or_default()
                .extend(start..start + count);
        }
    }
    changed
}

#[derive(Debug, Default)]
pub struct DiffSplit {
    pub kept: Vec<Issue>,
    pub hidden: usize,
}

pub fn restrict_to_changed(
    issues: Vec<Issue>,
    changed: &HashMap<PathBuf, HashSet<usize>>,
) -> DiffSplit {
    let total = issues.len();
    let kept: Vec<Issue> = issues
        .into_iter()
        .filter(|issue| {
            let file = issue
                .file
                .canonicalize()
                .unwrap_or_else(|_| issue.file.clone());
            let Some(lines) = changed.get(&file) else {
                return false;
            };
            let end = issue.end_line.unwrap_or(issue.line);
            (issue.line..=end).any(|n| lines.contains(&n))
        })
        .collect();
    DiffSplit {
        hidden: total - kept.len(),
        kept,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;

    const DIFF: &str = "diff --git a/src/m.py b/src/m.py
index 1..2 100644
--- a/src/m.py
+++ b/src/m.py
@@ -3,0 +4,2 @@ def f():
+    x = 1
+    y = 2
@@ -10 +12 @@
-old
+new
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1,3 +0,0 @@
-a
-b
-c
diff --git a/added.py b/added.py
new file mode 100644
--- /dev/null
+++ b/added.py
@@ -0,0 +1 @@
+z = 1
";

    #[test]
    fn changed_lines_sees_non_ascii_paths() {
        let repo = std::env::temp_dir().join(format!("spaghetti_rs_diff_{}", std::process::id()));
        std::fs::remove_dir_all(&repo).ok();
        std::fs::create_dir_all(repo.join("pkg")).unwrap();
        let repo = repo.canonicalize().unwrap();
        let git = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .args(["-c", "user.email=t@example.com", "-c", "user.name=t"])
                    .args(args)
                    .current_dir(&repo)
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        };
        git(&["init", "-q"]);
        let target = repo.join("pkg/caf\u{e9}  x.py");
        std::fs::write(&target, "a = 1\n").unwrap();
        git(&["add", "-A"]);
        git(&["commit", "-qm", "init"]);
        std::fs::write(&target, "a = 1\nb = 2\n").unwrap();
        let changed = changed_lines("HEAD", &repo.join("pkg")).unwrap();
        std::fs::remove_dir_all(&repo).ok();
        let expected: HashMap<PathBuf, HashSet<usize>> =
            [(target, HashSet::from([2]))].into_iter().collect();
        assert_eq!(changed, expected);
    }

    #[test]
    fn parse_unified_diff_collects_added_and_modified_lines() {
        let top = Path::new("/nonexistent/top");
        let changed = parse_unified_diff(DIFF, top);
        assert_eq!(changed[&top.join("src/m.py")], HashSet::from([4, 5, 12]));
        assert_eq!(changed[&top.join("added.py")], HashSet::from([1]));
        assert!(!changed.contains_key(&top.join("gone.py")));
    }

    fn issue(path: &Path, line: usize, end_line: Option<usize>) -> Issue {
        let mut i = Issue::new(path, line, Severity::Info, "r", "p", "m".into());
        i.end_line = end_line;
        i
    }

    #[test]
    fn restrict_keeps_findings_whose_span_touches_a_changed_line() {
        let m = PathBuf::from("/nonexistent/m.py");
        let other = PathBuf::from("/nonexistent/other.py");
        let changed = HashMap::from([(m.clone(), HashSet::from([10, 11]))]);
        let issues = vec![
            issue(&m, 10, None),
            issue(&m, 5, Some(12)),
            issue(&m, 20, None),
            issue(&other, 10, None),
        ];
        let split = restrict_to_changed(issues, &changed);
        assert_eq!(
            split.kept.iter().map(|i| i.line).collect::<Vec<_>>(),
            [10, 5]
        );
        assert_eq!(split.hidden, 2);
    }

    #[test]
    fn changed_lines_reports_git_failures() {
        let not_a_repo = std::env::temp_dir();
        // temp_dir itself may be inside a repo on some machines; a bad ref
        // fails either way.
        assert!(changed_lines("definitely-not-a-ref-0xdeadbeef", &not_a_repo).is_err());
    }
}
