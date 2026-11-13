//! CPython 3.12+ source positions for the parts of an f-string.
//!
//! Since PEP 701, `ast.parse` gives every `Constant` and `FormattedValue`
//! inside a `JoinedStr` its own location (a literal chunk starts at its
//! first character, a replacement field at its `{`, a format spec at its
//! `:`). rustpython-ast 0.4 gives every part the whole string's range, so
//! anything that reports a line from those nodes — the clone detector's
//! token lines, in practice — would be off by the lines a triple-quoted
//! f-string spans. This module re-scans the literal's source text and
//! recovers CPython's start offsets; when the scan and the parser disagree
//! about the number of parts (an exotic literal), the parser's positions are
//! kept, which is no worse than before.

use crate::pyast::Node;
use rustpython_ast::text_size::TextSize;
use rustpython_ast::{Expr, Ranged, Stmt};
use std::collections::HashMap;

/// A part of a `JoinedStr` as the scanner sees it.
#[derive(Debug)]
enum Part {
    /// A literal chunk (merged across implicitly concatenated tokens).
    Literal(usize),
    /// A replacement field starting at `{`, with its format spec (the
    /// offset of `:` and the spec's own parts), if any.
    Field(usize, Option<(usize, Vec<Part>)>),
}

/// Start offsets of f-string parts, keyed by the part expression's address.
#[derive(Default)]
pub struct FStringStarts(HashMap<usize, TextSize>);

impl FStringStarts {
    /// Collect corrected start offsets for every `JoinedStr` part in `body`.
    pub fn new(body: &[Stmt], source: &str) -> Self {
        let mut starts = FStringStarts::default();
        let mut format_specs: Vec<usize> = Vec::new();
        let mut stack: Vec<Node<'_>> = body.iter().map(Node::Stmt).collect();
        let mut joined: Vec<&Expr> = Vec::new();
        while let Some(node) = stack.pop() {
            if let Node::Expr(e) = node {
                match e {
                    Expr::JoinedStr(_) => joined.push(e),
                    Expr::FormattedValue(f) => {
                        if let Some(spec) = &f.format_spec {
                            format_specs.push(addr(spec));
                        }
                    }
                    _ => {}
                }
            }
            stack.extend(node.children());
        }
        for e in joined {
            if format_specs.contains(&addr(e)) {
                continue;
            }
            let range = e.range();
            let (lo, hi) = (usize::from(range.start()), usize::from(range.end()));
            let Some(text) = source.get(lo..hi) else {
                continue;
            };
            if let Some(parts) = scan_literal(text.as_bytes()) {
                starts.assign(e, &parts, lo);
            }
        }
        starts
    }

    /// The CPython start offset for `expr` if it is an f-string part.
    pub fn get(&self, expr: &Expr) -> Option<TextSize> {
        self.0.get(&addr(expr)).copied()
    }

    fn assign(&mut self, joined: &Expr, parts: &[Part], base: usize) {
        let Expr::JoinedStr(j) = joined else {
            return;
        };
        if j.values.len() != parts.len() {
            return;
        }
        for (value, part) in j.values.iter().zip(parts) {
            match (value, part) {
                (Expr::Constant(_), Part::Literal(at)) => {
                    self.0.insert(addr(value), offset(base + at));
                }
                (Expr::FormattedValue(f), Part::Field(at, spec)) => {
                    self.0.insert(addr(value), offset(base + at));
                    if let (Some(spec_expr), Some((spec_at, spec_parts))) = (&f.format_spec, spec) {
                        self.0.insert(addr(spec_expr), offset(base + spec_at));
                        self.assign(spec_expr, spec_parts, base);
                    }
                }
                _ => return,
            }
        }
    }
}

fn addr(e: &Expr) -> usize {
    e as *const Expr as usize
}

fn offset(at: usize) -> TextSize {
    TextSize::try_from(at).unwrap_or_default()
}

/// Scan the source of a (possibly implicitly concatenated) string literal
/// into CPython's `JoinedStr` parts. `None` if the text is not understood.
fn scan_literal(s: &[u8]) -> Option<Vec<Part>> {
    let mut parts = Vec::new();
    let mut pending: Option<usize> = None;
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b' ' | b'\t' | b'\n' | b'\r' | b'\x0c' | b'(' | b')' => i += 1,
            b'\\' => i += 1, // explicit line continuation between tokens
            b'#' => {
                while i < s.len() && s[i] != b'\n' {
                    i += 1;
                }
            }
            _ => {
                let prefix_start = i;
                while i < s.len() && s[i].is_ascii_alphabetic() {
                    i += 1;
                }
                let prefix = &s[prefix_start..i];
                let is_f = prefix.iter().any(|c| matches!(c, b'f' | b'F'));
                let is_raw = prefix.iter().any(|c| matches!(c, b'r' | b'R'));
                let quote = *s.get(i)?;
                if quote != b'"' && quote != b'\'' {
                    return None;
                }
                let triple = s.len() >= i + 3 && s[i + 1] == quote && s[i + 2] == quote;
                let qlen = if triple { 3 } else { 1 };
                i += qlen;
                let end = if is_f {
                    scan_fbody(s, i, quote, triple, is_raw, &mut parts, &mut pending)?
                } else {
                    let close = find_close(s, i, quote, triple)?;
                    if close > i && pending.is_none() {
                        pending = Some(i);
                    }
                    close
                };
                i = end + qlen;
            }
        }
    }
    if let Some(p) = pending {
        parts.push(Part::Literal(p));
    }
    Some(parts)
}

fn is_close(s: &[u8], i: usize, quote: u8, triple: bool) -> bool {
    if triple {
        s.len() >= i + 3 && s[i] == quote && s[i + 1] == quote && s[i + 2] == quote
    } else {
        s.get(i) == Some(&quote)
    }
}

/// Offset of the closing quote of a plain string body starting at `i`.
fn find_close(s: &[u8], mut i: usize, quote: u8, triple: bool) -> Option<usize> {
    while i < s.len() {
        if s[i] == b'\\' {
            i += 2;
            continue;
        }
        if is_close(s, i, quote, triple) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Scan an f-string body from `i`; returns the offset of its closing quote.
fn scan_fbody(
    s: &[u8],
    mut i: usize,
    quote: u8,
    triple: bool,
    is_raw: bool,
    parts: &mut Vec<Part>,
    pending: &mut Option<usize>,
) -> Option<usize> {
    while i < s.len() {
        if is_close(s, i, quote, triple) {
            return Some(i);
        }
        match s[i] {
            b'{' if s.get(i + 1) == Some(&b'{') => {
                pending.get_or_insert(i);
                i += 2;
            }
            b'}' if s.get(i + 1) == Some(&b'}') => {
                pending.get_or_insert(i);
                i += 2;
            }
            b'{' => {
                if let Some(p) = pending.take() {
                    parts.push(Part::Literal(p));
                }
                let (end, spec, debug) = scan_field(s, i, quote, triple)?;
                if debug {
                    // `{x=}`: CPython emits the expression text as a literal
                    // ahead of the field, starting right after the `{`.
                    parts.push(Part::Literal(i + 1));
                }
                parts.push(Part::Field(i, spec));
                i = end + 1;
            }
            b'\\' if !is_raw => {
                pending.get_or_insert(i);
                i += 2;
            }
            _ => {
                pending.get_or_insert(i);
                i += 1;
            }
        }
    }
    None
}

/// Scan a replacement field whose `{` is at `start`. Returns the offset of
/// its closing `}`, its format spec, and whether it is a `{x=}` field.
#[allow(clippy::type_complexity)]
fn scan_field(
    s: &[u8],
    start: usize,
    quote: u8,
    triple: bool,
) -> Option<(usize, Option<(usize, Vec<Part>)>, bool)> {
    let mut i = start + 1;
    let mut depth = 0usize;
    let mut debug = false;
    while i < s.len() {
        let c = s[i];
        match c {
            b'\'' | b'"' => {
                // A string inside the expression (a different quote, or
                // the same one under PEP 701).
                let t = s.len() >= i + 3 && s[i + 1] == c && s[i + 2] == c;
                let q = if t { 3 } else { 1 };
                let close = find_close(s, i + q, c, t)?;
                i = close + q;
                continue;
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            b'}' if depth > 0 => depth -= 1,
            b'}' => return Some((i, None, debug)),
            b'=' if depth == 0 => {
                let prev = s[i - 1];
                let next = s.get(i + 1).copied();
                if !matches!(prev, b'=' | b'!' | b'<' | b'>') && next != Some(b'=') {
                    debug = true;
                }
            }
            b'!' if depth == 0 && s.get(i + 1) != Some(&b'=') => {
                // Conversion: `!r`, then `}` or a format spec.
                i += 2;
                while i < s.len() && s[i].is_ascii_whitespace() {
                    i += 1;
                }
                if s.get(i) == Some(&b':') {
                    let (end, spec) = scan_spec(s, i, quote, triple)?;
                    return Some((end, Some(spec), debug));
                }
                continue;
            }
            b':' if depth == 0 => {
                let (end, spec) = scan_spec(s, i, quote, triple)?;
                return Some((end, Some(spec), debug));
            }
            b'#' => return None,
            _ => {
                if c != b' ' && c != b'\t' && c != b'\n' && c != b'\r' && debug {
                    debug = false;
                }
            }
        }
        i += 1;
    }
    None
}

/// Scan a format spec starting at its `:`; returns the offset of the
/// field's closing `}` and (spec start, spec parts).
fn scan_spec(
    s: &[u8],
    colon: usize,
    quote: u8,
    triple: bool,
) -> Option<(usize, (usize, Vec<Part>))> {
    let mut parts = Vec::new();
    let mut pending: Option<usize> = None;
    let mut i = colon + 1;
    while i < s.len() {
        if is_close(s, i, quote, triple) {
            return None;
        }
        match s[i] {
            b'{' => {
                if let Some(p) = pending.take() {
                    parts.push(Part::Literal(p));
                }
                let (end, spec, _) = scan_field(s, i, quote, triple)?;
                parts.push(Part::Field(i, spec));
                i = end + 1;
            }
            b'}' => {
                if let Some(p) = pending.take() {
                    parts.push(Part::Literal(p));
                }
                return Some((i, (colon, parts)));
            }
            _ => {
                pending.get_or_insert(i);
                i += 1;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::FStringStarts;
    use crate::ast_helpers::LineIndex;
    use crate::pyast::Node;
    use rustpython_ast::{Expr, Mod};

    fn part_lines(src: &str) -> Vec<(String, usize)> {
        let Mod::Module(m) =
            rustpython_parser::parse(src, rustpython_parser::Mode::Module, "<t>").unwrap()
        else {
            unreachable!()
        };
        let starts = FStringStarts::new(&m.body, src);
        let index = LineIndex::new(src);
        let mut out = Vec::new();
        let mut stack: Vec<Node<'_>> = m.body.iter().map(Node::Stmt).collect();
        while let Some(node) = stack.pop() {
            if let Node::Expr(Expr::JoinedStr(j)) = node {
                for v in &j.values {
                    if let Some(at) = starts.get(v) {
                        out.push((Node::Expr(v).py_name().to_string(), index.line_number(at)));
                    }
                }
            }
            stack.extend(node.children());
        }
        out.sort();
        out
    }

    #[test]
    fn triple_quoted_parts_get_their_own_lines() {
        // Expected lines from CPython 3.13's `ast.parse` of the same source.
        let src = "x = f\"\"\"a\n{b}\nc{d!r:>{w}}\ne\"\"\"\n";
        assert_eq!(
            part_lines(src),
            vec![
                ("Constant".into(), 1),
                ("Constant".into(), 2),
                ("Constant".into(), 3),
                ("Constant".into(), 3),
                ("FormattedValue".into(), 2),
                ("FormattedValue".into(), 3),
                ("FormattedValue".into(), 3),
            ]
        );
    }

    #[test]
    fn concatenated_literals_merge_into_one_part() {
        let src = "y = (f\"q\"\n  \"r\" f\"{z}\")\n";
        assert_eq!(
            part_lines(src),
            vec![("Constant".into(), 1), ("FormattedValue".into(), 2)]
        );
    }
}
