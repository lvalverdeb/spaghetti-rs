//! Self-contained HTML report: scorecard, trend sparklines from the snapshot
//! store, hotspot ranking, per-file findings — mirrors
//! `spaghetti/html_report.py` markup for markup. One file, inline CSS, no
//! script, no server, no account — open it or attach it to a PR.

use crate::churn::Hotspot;
use crate::config::LINES_PER_KLOC;
use crate::json::py_float_repr;
use crate::models::{Issue, ScanResult, display_path};
use crate::scoring::{compute_score, file_penalties};
use crate::snapshots::{Comparison, Snapshot};
use indexmap::IndexMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const CSS: &str = include_str!("html_report.css");

/// `html.escape(s)` (quote=True).
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

fn grade_badge(grade: &str) -> String {
    let g = escape(grade);
    format!("<span class=\"grade\" style=\"background:var(--{g})\">{g}</span>")
}

/// Polyline of 0-100 scores; a single value draws a dot.
fn sparkline(values: &[f64]) -> String {
    const WIDTH: f64 = 140.0;
    const HEIGHT: f64 = 28.0;
    if values.is_empty() {
        return String::new();
    }
    let n = values.len();
    let pts: Vec<(String, String)> = values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let frac = if n > 1 {
                i as f64 / (n - 1) as f64
            } else {
                0.5
            };
            let x = 2.0 + (WIDTH - 4.0) * frac;
            let y = 2.0 + (HEIGHT - 4.0) * (1.0 - v.clamp(0.0, 100.0) / 100.0);
            (format!("{x:.1}"), format!("{y:.1}"))
        })
        .collect();
    let body = if n > 1 {
        let joined: Vec<String> = pts.iter().map(|(x, y)| format!("{x},{y}")).collect();
        format!(
            "<polyline fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\" points=\"{}\"/>",
            joined.join(" ")
        )
    } else {
        format!(
            "<circle cx=\"{}\" cy=\"{}\" r=\"2\" fill=\"currentColor\"/>",
            pts[0].0, pts[0].1
        )
    };
    format!(
        "<svg class=\"spark\" width=\"140\" height=\"28\" viewBox=\"0 0 140 28\" \
         role=\"img\" aria-label=\"{n} snapshot(s)\">{body}</svg>"
    )
}

fn scorecard(
    packages: &[String],
    per_package: &IndexMap<String, ScanResult>,
    total: &ScanResult,
    history: &[&Snapshot],
) -> String {
    let mut rows = String::new();
    let entries = packages
        .iter()
        .map(|name| (name.as_str(), &per_package[name.as_str()]))
        .chain(std::iter::once(("OVERALL", total)));
    for (name, result) in entries {
        let (score, grade) = compute_score(result);
        let key = if name == "OVERALL" { "*" } else { name };
        let mut series: Vec<f64> = history
            .iter()
            .filter_map(|s| s.scores.get(key).copied())
            .collect();
        series.push(crate::json::py_round(score, 1));
        let mi = match result.maintainability_index() {
            None => "\u{2014}".to_string(),
            Some(mi) => format!("{mi:.1}"),
        };
        let spark = if history.is_empty() {
            String::new()
        } else {
            sparkline(&series)
        };
        let _ = write!(
            rows,
            "<tr><td><code>{}</code></td><td>{}</td>\
             <td class=\"num\">{score:.1}</td><td class=\"num\">{}</td>\
             <td class=\"num\">{:.1}</td>\
             <td class=\"num\">{}</td>\
             <td class=\"num sev-error\">{}</td>\
             <td class=\"num sev-warning\">{}</td>\
             <td class=\"num sev-info\">{}</td>\
             <td class=\"num\">{mi}</td>\
             <td>{spark}</td></tr>",
            escape(name),
            grade_badge(grade),
            result.files_scanned,
            result.total_lines as f64 / LINES_PER_KLOC,
            result.issues.len(),
            result.error_count(),
            result.warning_count(),
            result.info_count(),
        );
    }
    format!(
        "<table><thead><tr><th>Package</th><th>Grade</th><th class=num>Score</th><th class=num>Files</th>\
         <th class=num>KLOC</th><th class=num>Findings</th><th class=num>Err</th><th class=num>Warn</th>\
         <th class=num>Info</th><th class=num>MI</th><th>Trend</th></tr></thead><tbody>{rows}</tbody></table>"
    )
}

fn comparison(comp: &Comparison) -> String {
    let delta = comp.score_delta();
    let cls = if delta >= 0.0 {
        "delta-up"
    } else {
        "delta-down"
    };
    let sign = if delta >= 0.0 { "+" } else { "" };
    let mut out = format!(
        "<p class=\"note\">Compared to <code>{}</code>: score \
         {:.1} \u{2192} {:.1} (<span class=\"{cls}\">{sign}{}</span>), \
         {} introduced, {} fixed, {} file(s) worse.</p>",
        escape(&comp.against.label()),
        comp.score_before,
        comp.score_after,
        py_float_repr(delta),
        comp.introduced.len(),
        comp.fixed.len(),
        comp.files_worse.len()
    );
    if !comp.introduced.is_empty() {
        out.push_str("<h3>Introduced</h3><ul>");
        for i in &comp.introduced {
            let _ = write!(
                out,
                "<li><span class=\"sev-{sev}\">{sev}</span> \
                 <code>{}:{}</code> <code>{}</code> \u{2014} {}</li>",
                escape(&i.file),
                i.line,
                escape(&i.rule),
                escape(&i.message),
                sev = escape(&i.severity),
            );
        }
        out.push_str("</ul>");
    }
    if !comp.fixed.is_empty() {
        out.push_str("<h3>Fixed</h3><ul>");
        for f in &comp.fixed {
            let _ = write!(
                out,
                "<li><code>{}</code> <code>{}</code> \u{2014} {}</li>",
                escape(&f.file),
                escape(&f.rule),
                escape(&f.message)
            );
        }
        out.push_str("</ul>");
    }
    out
}

fn hotspots(spots: &[Hotspot], months: i64, top: usize) -> String {
    if spots.is_empty() {
        return "<p class=meta>No hotspots: no file with findings was touched in the window.</p>"
            .to_string();
    }
    let mut rows = String::new();
    for h in spots.iter().take(top) {
        let _ = write!(
            rows,
            "<tr><td><code>{}</code></td><td class=num>{:.1}</td>\
             <td class=num>{}</td><td class=num>{}</td><td class=num>{:.1}</td></tr>",
            escape(&h.file),
            h.penalty,
            h.commits,
            h.authors,
            h.score
        );
    }
    format!(
        "<p class=meta>Health penalty \u{d7} change frequency over the last {months} months. \
         Files here are both tangled and actively edited \u{2014} fix these first.</p>\
         <table><thead><tr><th>File</th><th class=num>Penalty</th><th class=num>Commits</th>\
         <th class=num>Authors</th><th class=num>Hotspot</th></tr></thead><tbody>{rows}</tbody></table>"
    )
}

fn findings(issues: &[&Issue], workspace_root: Option<&Path>) -> String {
    let mut by_file: IndexMap<&PathBuf, Vec<&Issue>> = IndexMap::new();
    for issue in issues {
        by_file.entry(&issue.file).or_default().push(issue);
    }
    let penalties = file_penalties(issues.iter().copied());
    let mut paths: Vec<(&PathBuf, f64, String)> = by_file
        .keys()
        .map(|p| (*p, penalties[*p], display_path(p, workspace_root)))
        .collect();
    paths.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.2.cmp(&b.2)));
    let mut blocks = String::new();
    for (path, penalty, shown) in paths {
        let mut file_issues = by_file[path].clone();
        file_issues.sort_by(|a, b| a.line.cmp(&b.line).then_with(|| a.rule.cmp(b.rule)));
        let mut rows = String::new();
        for i in &file_issues {
            let sev = escape(i.severity.as_str());
            let _ = write!(
                rows,
                "<tr><td class=num>{}</td><td class=\"sev-{sev}\">{sev}</td>\
                 <td><code>{}</code></td><td>{}</td></tr>",
                i.line,
                escape(i.rule),
                escape(&i.message)
            );
        }
        let _ = write!(
            blocks,
            "<details><summary><code>{}</code> \u{2014} {} \
             finding(s), penalty {penalty:.1}</summary><table><thead><tr><th class=num>Line</th>\
             <th>Severity</th><th>Rule</th><th>Message</th></tr></thead><tbody>{rows}</tbody></table></details>",
            escape(&shown),
            file_issues.len()
        );
    }
    if blocks.is_empty() {
        "<p>No findings.</p>".to_string()
    } else {
        blocks
    }
}

fn rule_summary(issues: &[&Issue]) -> String {
    let mut counts: IndexMap<&str, usize> = IndexMap::new();
    for i in issues {
        *counts.entry(i.rule).or_insert(0) += 1;
    }
    let mut sorted: Vec<(&str, usize)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let mut rows = String::new();
    for (rule, n) in sorted {
        let _ = write!(
            rows,
            "<tr><td><code>{}</code></td><td class=num>{n}</td></tr>",
            escape(rule)
        );
    }
    format!(
        "<table><thead><tr><th>Rule</th><th class=num>Findings</th></tr></thead><tbody>{rows}</tbody></table>"
    )
}

/// Everything `build_html` renders — mirrors the keyword arguments of
/// `html_report.py::build_html`.
pub struct HtmlInput<'a> {
    pub packages: &'a [String],
    pub per_package: &'a IndexMap<String, ScanResult>,
    pub total: &'a ScanResult,
    pub issues: &'a [&'a Issue],
    pub tool_version: &'a str,
    pub sha: Option<&'a str>,
    pub generated_at: &'a str,
    pub notes: &'a [String],
    pub history: &'a [&'a Snapshot],
    pub comparison: Option<&'a Comparison>,
    pub hotspots: Option<&'a [Hotspot]>,
    pub hotspot_months: i64,
    pub top: usize,
    pub workspace_root: Option<&'a Path>,
}

pub fn build_html(input: &HtmlInput<'_>) -> String {
    let (score, grade) = compute_score(input.total);
    let mut sections = String::new();
    let _ = write!(
        sections,
        "<h1>spaghetti report {} {score:.1}</h1>",
        grade_badge(grade)
    );
    let _ = write!(
        sections,
        "<p class=\"meta\">spaghetti {} \u{b7} {}",
        escape(input.tool_version),
        escape(input.generated_at)
    );
    if let Some(sha) = input.sha.filter(|s| !s.is_empty()) {
        let short: String = sha.chars().take(12).collect();
        let _ = write!(sections, " \u{b7} <code>{}</code>", escape(&short));
    }
    sections.push_str("</p>");
    for n in input.notes {
        let _ = write!(sections, "<p class=\"note\">{}</p>", escape(n));
    }
    sections.push_str("<h2>Scorecard</h2>");
    sections.push_str(&scorecard(
        input.packages,
        input.per_package,
        input.total,
        input.history,
    ));
    if let Some(comp) = input.comparison {
        sections.push_str("<h2>Change</h2>");
        sections.push_str(&comparison(comp));
    }
    if let Some(spots) = input.hotspots {
        sections.push_str("<h2>Hotspots</h2>");
        sections.push_str(&hotspots(spots, input.hotspot_months, input.top));
    }
    let _ = write!(sections, "<h2>Findings ({})</h2>", input.issues.len());
    sections.push_str(&findings(input.issues, input.workspace_root));
    sections.push_str("<h2>By rule</h2>");
    sections.push_str(&rule_summary(input.issues));
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>spaghetti report \u{2014} {} {score:.1}</title>\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><style>{CSS}</style></head>\
         <body>{sections}</body></html>\n",
        escape(grade)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_matches_python_html_escape() {
        assert_eq!(
            escape("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#x27;&amp;&#x27;&lt;/a&gt;"
        );
    }

    #[test]
    fn sparkline_single_value_is_a_dot_and_series_a_polyline() {
        assert_eq!(
            sparkline(&[50.0]),
            "<svg class=\"spark\" width=\"140\" height=\"28\" viewBox=\"0 0 140 28\" role=\"img\" \
             aria-label=\"1 snapshot(s)\"><circle cx=\"70.0\" cy=\"14.0\" r=\"2\" fill=\"currentColor\"/></svg>"
        );
        assert!(sparkline(&[100.0, 0.0, 120.0]).contains("points=\"2.0,2.0 70.0,26.0 138.0,2.0\""));
        assert_eq!(sparkline(&[]), "");
    }

    #[test]
    fn empty_report_is_one_self_contained_document() {
        let total = ScanResult::default();
        let per_package = IndexMap::new();
        let html = build_html(&HtmlInput {
            packages: &[],
            per_package: &per_package,
            total: &total,
            issues: &[],
            tool_version: "9",
            sha: Some("0123456789abcdef"),
            generated_at: "t",
            notes: &["a < b".to_string()],
            history: &[],
            comparison: None,
            hotspots: Some(&[]),
            hotspot_months: 6,
            top: 5,
            workspace_root: None,
        });
        assert!(html.starts_with("<!DOCTYPE html>\n<html lang=\"en\">"));
        assert!(html.ends_with("</body></html>\n"));
        assert!(html.contains("<code>0123456789ab</code>"));
        assert!(html.contains("<p class=\"note\">a &lt; b</p>"));
        assert!(html.contains("No hotspots"));
        assert!(html.contains("<p>No findings.</p>"));
        assert!(!html.contains("<script"));
    }
}
