//! Where CPython gives up and rustpython does not.
//!
//! The Python port reads every file with `read_text()` and parses it with
//! `ast.parse`; its checks are recursive Python functions. So a few inputs
//! that rustpython parses happily never reach a check there:
//!
//! * the tokenizer rejects a NUL byte, a leading U+FEFF (a BOM survives
//!   `read_text(encoding="utf-8")` and is an invalid character to the
//!   parser), more than 200 nested brackets ("too many nested parentheses")
//!   and a hundredth indentation level ("too many levels of indentation") —
//!   all `syntax-error` in Python, mirrored by [`cpython_rejects`];
//! * a tree nested deeply enough raises `RecursionError` inside the checks,
//!   which the Python scanner turns into a `scan-limit` finding. The exact
//!   point depends on which recursive check is deepest for the shape at
//!   hand (one frame per level for the module-wide walks, two per
//!   expression level inside a function for cognitive complexity), so
//!   [`exceeds_nesting_limit`] models that cost and is calibrated against
//!   CPython 3.13's default recursion limit on the shapes in
//!   `tests/edge_cases.rs`; it is approximate for other shapes, but every
//!   file it flags is far past anything hand-written.
//!
//! The Rust checks themselves are iterative where depth is unbounded, and
//! the scanner runs on threads with large stacks (`crate::SCAN_STACK_BYTES`),
//! so nothing here is needed to avoid a crash — only to report what Python
//! reports.

use crate::pyast::Node;
use rustpython_ast::{Expr, Stmt};

/// CPython's tokenizer limit on open brackets (`MAXLEVEL`).
const MAX_BRACKET_LEVEL: usize = 200;
/// CPython's tokenizer limit on indentation levels (`MAXINDENT`).
const MAX_INDENT: usize = 100;
/// Modelled Python stack cost at which the checks hit the recursion limit.
const NESTING_COST_LIMIT: usize = 985;

/// True if CPython's tokenizer would reject `source` (see module docs).
pub fn cpython_rejects(source: &str) -> bool {
    if source.starts_with('\u{feff}') || source.contains('\0') {
        return true;
    }
    let s: Vec<char> = source.chars().collect();
    let mut i = 0;
    let mut level = 0usize;
    let mut indents: Vec<usize> = vec![0];
    let mut line_start = true;
    let mut continued = false;
    while i < s.len() {
        if line_start {
            line_start = false;
            if level == 0 && !continued {
                let mut col = 0;
                while i < s.len() {
                    match s[i] {
                        ' ' => col += 1,
                        '\t' => col = (col / 8 + 1) * 8,
                        '\x0c' => col = 0,
                        _ => break,
                    }
                    i += 1;
                }
                let blank = i >= s.len() || matches!(s[i], '\n' | '\r' | '#' | '\\');
                if !blank {
                    let top = *indents.last().unwrap_or(&0);
                    if col > top {
                        if indents.len() >= MAX_INDENT {
                            return true;
                        }
                        indents.push(col);
                    } else {
                        while indents.len() > 1 && col < *indents.last().unwrap_or(&0) {
                            indents.pop();
                        }
                    }
                }
            }
            continued = false;
            continue;
        }
        match s[i] {
            '#' => {
                while i < s.len() && s[i] != '\n' && s[i] != '\r' {
                    i += 1;
                }
            }
            '\'' | '"' => {
                let q = s[i];
                let triple = i + 2 < s.len() && s[i + 1] == q && s[i + 2] == q;
                i += if triple { 3 } else { 1 };
                while i < s.len() {
                    if s[i] == '\\' {
                        i += 2;
                        continue;
                    }
                    if s[i] == q && (!triple || (i + 2 < s.len() && s[i + 1] == q && s[i + 2] == q))
                    {
                        i += if triple { 3 } else { 1 };
                        break;
                    }
                    if !triple && (s[i] == '\n' || s[i] == '\r') {
                        break; // unterminated: the parser reports it
                    }
                    i += 1;
                }
                continue;
            }
            '(' | '[' | '{' => {
                if level >= MAX_BRACKET_LEVEL {
                    return true;
                }
                level += 1;
            }
            ')' | ']' | '}' => level = level.saturating_sub(1),
            '\\' if matches!(s.get(i + 1), Some('\n' | '\r')) => {
                continued = true;
            }
            '\n' => line_start = true,
            '\r' if s.get(i + 1) != Some(&'\n') => line_start = true,
            _ => {}
        }
        i += 1;
    }
    false
}

fn has_ctx(node: Node<'_>) -> bool {
    matches!(
        node,
        Node::Expr(
            Expr::Name(_)
                | Expr::Attribute(_)
                | Expr::Subscript(_)
                | Expr::Starred(_)
                | Expr::List(_)
                | Expr::Tuple(_)
        )
    )
}

fn is_def(node: Node<'_>) -> bool {
    matches!(
        node,
        Node::Stmt(Stmt::FunctionDef(_) | Stmt::AsyncFunctionDef(_))
    )
}

/// True if Python's checks would hit `RecursionError` on this module (see
/// module docs for the cost model).
pub fn exceeds_nesting_limit(body: &[Stmt]) -> bool {
    let weight = |node: Node<'_>, inside_function: bool| -> usize {
        if inside_function {
            2
        } else if is_def(node) {
            0
        } else {
            1
        }
    };
    let mut stack: Vec<(Node<'_>, usize, bool)> = body
        .iter()
        .map(|s| (Node::Stmt(s), weight(Node::Stmt(s), false), false))
        .collect();
    while let Some((node, cost, inside)) = stack.pop() {
        let leaf_cost = cost + usize::from(!inside && has_ctx(node));
        if leaf_cost >= NESTING_COST_LIMIT {
            return true;
        }
        let child_inside = inside || is_def(node);
        for child in node.children() {
            stack.push((child, cost + weight(child, child_inside), child_inside));
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{cpython_rejects, exceeds_nesting_limit};
    use rustpython_ast::Mod;

    fn deep(source: &str) -> bool {
        let Mod::Module(m) =
            rustpython_parser::parse(source, rustpython_parser::Mode::Module, "<t>").unwrap()
        else {
            unreachable!()
        };
        exceeds_nesting_limit(&m.body)
    }

    // Boundaries measured with the Python CLI (CPython 3.13, default
    // recursion limit): last length without and first with `scan-limit`.
    #[test]
    fn nesting_limit_matches_cpython_at_the_calibration_points() {
        let attr = |n: usize| format!("x = a{}\n", ".b".repeat(n));
        assert!(!deep(&attr(981)) && deep(&attr(982)));
        let binop = |n: usize| format!("x = {}\n", vec!["1"; n].join(" + "));
        assert!(!deep(&binop(983)) && deep(&binop(984)));
        let lambdas = |n: usize| format!("{}0\n", "lambda: ".repeat(n));
        assert!(!deep(&lambdas(982)) && deep(&lambdas(983)));
        let in_def = |n: usize| format!("def f():\n    return a{}\n", ".b".repeat(n));
        assert!(!deep(&in_def(490)) && deep(&in_def(491)));
    }

    #[test]
    fn tokenizer_limits_match_cpython() {
        let brackets = |n: usize| format!("x = {}{}\n", "[".repeat(n), "]".repeat(n));
        assert!(!cpython_rejects(&brackets(200)) && cpython_rejects(&brackets(201)));
        let indents = |n: usize| {
            let mut s: String = (0..n)
                .map(|i| format!("{}if x:\n", "    ".repeat(i)))
                .collect();
            s.push_str(&format!("{}pass\n", "    ".repeat(n)));
            s
        };
        assert!(!cpython_rejects(&indents(99)) && cpython_rejects(&indents(100)));
        assert!(cpython_rejects("\u{feff}import os\n"));
        assert!(cpython_rejects("x = '\0'\n"));
        assert!(!cpython_rejects(
            "x = '[[[(' # ((((\ny = \"\"\"\n{{{\n\"\"\"\n"
        ));
    }
}
