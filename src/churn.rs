//! Change frequency from git history, and the health × churn hotspot ranking
//! (CodeScene's core idea) — mirrors `spaghetti/churn.py`. A file that is
//! both tangled and actively edited is where remediation effort pays off; a
//! tangled file nobody touches can wait.

use crate::json::py_round;
use crate::settings::resolve_lenient;
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};

/// git is missing, the path is not a repository, or git failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChurnError(pub String);

impl fmt::Display for ChurnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ChurnError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Churn {
    pub commits: usize,
    pub authors: usize,
}

fn git(cwd: &Path, args: &[&str]) -> Result<String, ChurnError> {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ChurnError("git executable not found".to_string())
            } else {
                ChurnError(e.to_string())
            }
        })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(ChurnError(if stderr.is_empty() {
            format!("git {} failed", args.join(" "))
        } else {
            stderr
        }));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Commits and distinct authors touching each file under `roots` in the last
/// `months` months. Keys are resolved absolute paths, in first-seen order.
/// Every root must be inside one git work tree.
pub fn file_churn(roots: &[PathBuf], months: i64) -> Result<IndexMap<PathBuf, Churn>, ChurnError> {
    let Some(first) = roots.first() else {
        return Ok(IndexMap::new());
    };
    let toplevel = resolve_lenient(Path::new(
        git(first, &["rev-parse", "--show-toplevel"])?.trim(),
    ));
    let since = format!("--since={months} months ago");
    let resolved_roots: Vec<String> = roots
        .iter()
        .map(|r| resolve_lenient(r).display().to_string())
        .collect();
    let mut args: Vec<&str> = vec!["log", &since, "--name-only", "--format=%x00%an", "--"];
    args.extend(resolved_roots.iter().map(String::as_str));
    let log = git(&toplevel, &args)?;

    let mut commits: IndexMap<PathBuf, usize> = IndexMap::new();
    let mut authors: HashMap<PathBuf, HashSet<String>> = HashMap::new();
    let mut resolved: HashMap<&str, PathBuf> = HashMap::new();
    let mut author = "";
    for line in py_splitlines(&log) {
        if let Some(name) = line.strip_prefix('\0') {
            author = name;
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let path = resolved
            .entry(line)
            .or_insert_with(|| resolve_lenient(&toplevel.join(line)))
            .clone();
        *commits.entry(path.clone()).or_insert(0) += 1;
        authors.entry(path).or_default().insert(author.to_string());
    }
    Ok(commits
        .into_iter()
        .map(|(p, c)| {
            let a = authors.get(&p).map_or(0, HashSet::len);
            (
                p,
                Churn {
                    commits: c,
                    authors: a,
                },
            )
        })
        .collect())
}

/// `str.splitlines()` for git's output (`\n`, `\r\n`, `\r`).
fn py_splitlines(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n')
        .flat_map(|l| l.strip_suffix('\r').unwrap_or(l).split('\r'))
}

/// Multiplier in [1, 2] applied to a finding's priority: 1 for an untouched
/// file, 2 for the most-edited file in the window, log-scaled in between so a
/// handful of commits already counts and the long tail is compressed.
/// Relative to the repository's own maximum, so an active codebase does not
/// see every finding promoted to P0.
pub fn churn_factor(churn: Option<&Churn>, max_commits: usize) -> f64 {
    match churn {
        Some(c) if c.commits > 0 && max_commits > 0 => {
            1.0 + (1.0 + c.commits as f64).log2() / (1.0 + max_commits as f64).log2()
        }
        _ => 1.0,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hotspot {
    pub file: String,
    pub penalty: f64,
    pub commits: usize,
    pub authors: usize,
    /// penalty × churn_factor — the health × change-frequency product.
    pub score: f64,
}

/// Files with findings, ranked by penalty × churn factor. Files with no
/// findings are never hotspots however often they change.
pub fn rank_hotspots(
    penalties: &IndexMap<PathBuf, f64>,
    churn: &IndexMap<PathBuf, Churn>,
    display: &HashMap<PathBuf, String>,
) -> Vec<Hotspot> {
    let max_commits = churn.values().map(|c| c.commits).max().unwrap_or(0);
    let mut spots: Vec<Hotspot> = penalties
        .iter()
        .filter(|(_, p)| **p > 0.0)
        .map(|(path, penalty)| {
            let c = churn.get(path);
            Hotspot {
                file: display[path].clone(),
                penalty: py_round(*penalty, 1),
                commits: c.map_or(0, |c| c.commits),
                authors: c.map_or(0, |c| c.authors),
                score: py_round(penalty * churn_factor(c, max_commits), 1),
            }
        })
        .collect();
    spots.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| b.penalty.total_cmp(&a.penalty))
            .then_with(|| a.file.cmp(&b.file))
    });
    spots
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn churn_factor_is_log_scaled_between_one_and_two() {
        let c = |n| Churn {
            commits: n,
            authors: 1,
        };
        assert_eq!(churn_factor(None, 10), 1.0);
        assert_eq!(churn_factor(Some(&c(0)), 10), 1.0);
        assert_eq!(churn_factor(Some(&c(5)), 0), 1.0);
        assert_eq!(churn_factor(Some(&c(10)), 10), 2.0);
        let mid = churn_factor(Some(&c(3)), 10);
        assert!(mid > 1.0 && mid < 2.0);
        assert_eq!(mid, 1.0 + 2.0 / 11f64.log2());
    }

    #[test]
    fn rank_hotspots_orders_by_score_then_penalty_then_path() {
        let a = PathBuf::from("/r/a.py");
        let b = PathBuf::from("/r/b.py");
        let quiet = PathBuf::from("/r/quiet.py");
        let clean = PathBuf::from("/r/clean.py");
        let penalties: IndexMap<PathBuf, f64> = [
            (a.clone(), 6.0),
            (b.clone(), 6.0),
            (quiet.clone(), 9.0),
            (clean.clone(), 0.0),
        ]
        .into_iter()
        .collect();
        let churn: IndexMap<PathBuf, Churn> = [
            (
                a.clone(),
                Churn {
                    commits: 7,
                    authors: 2,
                },
            ),
            (
                b.clone(),
                Churn {
                    commits: 1,
                    authors: 1,
                },
            ),
            (
                clean.clone(),
                Churn {
                    commits: 50,
                    authors: 3,
                },
            ),
        ]
        .into_iter()
        .collect();
        let display: HashMap<PathBuf, String> = penalties
            .keys()
            .map(|p| {
                (
                    p.clone(),
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                )
            })
            .collect();
        let spots = rank_hotspots(&penalties, &churn, &display);
        let names: Vec<&str> = spots.iter().map(|h| h.file.as_str()).collect();
        // a.py: 6 × (1 + log2(8)/log2(51)) = 9.17 outranks the untouched 9.0.
        assert_eq!(names, ["a.py", "quiet.py", "b.py"]);
        assert_eq!(spots[0].score, 9.2);
        assert_eq!(spots[0].commits, 7);
        assert_eq!(spots[1].score, 9.0);
    }
}
