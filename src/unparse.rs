//! A port of CPython 3.13's `ast.unparse` (`Lib/ast.py`, class `_Unparser`)
//! over rustpython's AST.
//!
//! `sync-async-duplication` reports `difflib.SequenceMatcher` similarity of
//! the two functions' `ast.unparse` text, so every character this renderer
//! produces differently from CPython moves the reported percentage (and can
//! move a pair across the threshold). rustpython's own `Display for Expr`
//! follows the C unparser (`Python/ast_unparse.c`, the one behind
//! `from __future__ import annotations`), whose parenthesisation differs
//! from `Lib/ast.py`'s — e.g. `ast.unparse` writes `a or (b and (not c))`
//! because `visit_BoolOp` raises the precedence for every further operand.
//! So this is a method-by-method transliteration instead: same precedence
//! table, same `fill`/`maybe_newline` layout (no trailing newline, a blank
//! line before a nested `def`/`class`), same string-literal quoting
//! (`repr()` with `str.isprintable`, docstrings and f-strings via
//! `_str_literal_helper`), same float spelling (`repr`, infinities as
//! `1e309`).

use crate::py_printable::is_printable;
use rustpython_ast::{
    Arguments, BoolOp, CmpOp, Comprehension, ConversionFlag, ExceptHandler, Expr, Keyword,
    MatchCase, Operator, Pattern, Ranged, Stmt, TypeParam, UnaryOp, WithItem,
};

/// `_Precedence` — `BOR` is `EXPR`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Prec {
    NamedExpr = 1,
    Tuple,
    Yield,
    Test,
    Or,
    And,
    Not,
    Cmp,
    Expr,
    Bxor,
    Band,
    Shift,
    Arith,
    Term,
    Factor,
    Power,
    Await,
    Atom,
}

impl Prec {
    const BOR: Prec = Prec::Expr;

    fn next(self) -> Prec {
        use Prec::*;
        match self {
            NamedExpr => Tuple,
            Tuple => Yield,
            Yield => Test,
            Test => Or,
            Or => And,
            And => Not,
            Not => Cmp,
            Cmp => Expr,
            Expr => Bxor,
            Bxor => Band,
            Band => Shift,
            Shift => Arith,
            Arith => Term,
            Term => Factor,
            Factor => Power,
            Power => Await,
            Await | Atom => Atom,
        }
    }
}

const MULTI_QUOTES: [&str; 2] = ["\"\"\"", "'''"];
const ALL_QUOTES: [&str; 4] = ["'", "\"", "\"\"\"", "'''"];
const INFSTR: &str = "1e309";

/// `ast.unparse(node)` for a statement (a whole `def` included). `source`
/// is the module text the statement was parsed from: rustpython stores a
/// lone surrogate escape (`"\ud800"`) as U+FFFD, so such literals are
/// re-decoded from their source to spell them the way `repr` does.
pub fn unparse_function(stmt: &Stmt, source: &str) -> String {
    let mut u = Unparser {
        source,
        ..Unparser::default()
    };
    u.stmt(stmt);
    u.out
}

/// `ast.unparse(node)` for an expression.
pub fn unparse_expr(expr: &Expr) -> String {
    let mut u = Unparser::default();
    u.expr(expr, Prec::Test);
    u.out
}

/// Python's `repr(s)` for a `str`.
pub fn py_repr_str(s: &str) -> String {
    let cps: Vec<u32> = s.chars().map(|c| c as u32).collect();
    py_repr_codepoints(&cps)
}

/// `repr()` of a Python string given as code points (which, unlike a Rust
/// `str`, may hold lone surrogates).
fn py_repr_codepoints(s: &[u32]) -> String {
    let has = |c: char| s.contains(&(c as u32));
    let quote = if has('\'') && !has('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for &cp in s {
        match char::from_u32(cp) {
            Some('\\') => out.push_str("\\\\"),
            Some('\t') => out.push_str("\\t"),
            Some('\n') => out.push_str("\\n"),
            Some('\r') => out.push_str("\\r"),
            Some(c) if c == quote => {
                out.push('\\');
                out.push(c);
            }
            Some(c) if is_printable(c) => out.push(c),
            _ => push_hex_escape_cp(&mut out, cp),
        }
    }
    out.push(quote);
    out
}

/// The value of the string literal(s) spelled by `segment` as code points,
/// or `None` for anything but plain (non-f, non-bytes) string tokens, or an
/// escape this decoder does not handle (`\N{...}`).
fn decode_str_literal(segment: &str) -> Option<Vec<u32>> {
    let s: Vec<char> = segment.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            ' ' | '\t' | '\n' | '\r' | '\x0c' | '(' | ')' | '\\' => i += 1,
            '#' => {
                while i < s.len() && s[i] != '\n' {
                    i += 1;
                }
            }
            _ => {
                let start = i;
                while i < s.len() && s[i].is_ascii_alphabetic() {
                    i += 1;
                }
                let prefix: String = s[start..i].iter().collect::<String>().to_ascii_lowercase();
                if prefix.contains('b') || prefix.contains('f') {
                    return None;
                }
                let raw = prefix.contains('r');
                let quote = *s.get(i)?;
                if quote != '\'' && quote != '"' {
                    return None;
                }
                let triple = i + 2 < s.len() && s[i + 1] == quote && s[i + 2] == quote;
                let q = if triple { 3 } else { 1 };
                i += q;
                loop {
                    let c = *s.get(i)?;
                    if c == quote
                        && (!triple
                            || (s.get(i + 1) == Some(&quote) && s.get(i + 2) == Some(&quote)))
                    {
                        i += q;
                        break;
                    }
                    if c == '\r' {
                        out.push('\n' as u32);
                        i += if s.get(i + 1) == Some(&'\n') { 2 } else { 1 };
                        continue;
                    }
                    if c != '\\' {
                        out.push(c as u32);
                        i += 1;
                        continue;
                    }
                    let n = *s.get(i + 1)?;
                    if raw {
                        out.push('\\' as u32);
                        if n == '\r' || n == '\n' {
                            i += 1;
                        } else {
                            out.push(n as u32);
                            i += 2;
                        }
                        continue;
                    }
                    i += 2;
                    let hex = |len: usize, at: usize| -> Option<u32> {
                        let digits: String = s.get(at..at + len)?.iter().collect();
                        u32::from_str_radix(&digits, 16).ok()
                    };
                    match n {
                        '\n' => {}
                        '\r' => {
                            if s.get(i) == Some(&'\n') {
                                i += 1;
                            }
                        }
                        '\\' | '\'' | '"' => out.push(n as u32),
                        'a' => out.push(7),
                        'b' => out.push(8),
                        'f' => out.push(0x0c),
                        'n' => out.push(0x0a),
                        'r' => out.push(0x0d),
                        't' => out.push(0x09),
                        'v' => out.push(0x0b),
                        'x' => {
                            out.push(hex(2, i)?);
                            i += 2;
                        }
                        'u' => {
                            out.push(hex(4, i)?);
                            i += 4;
                        }
                        'U' => {
                            out.push(hex(8, i)?);
                            i += 8;
                        }
                        '0'..='7' => {
                            let mut v = n.to_digit(8)?;
                            for _ in 0..2 {
                                match s.get(i).and_then(|c| c.to_digit(8)) {
                                    Some(d) => {
                                        v = v * 8 + d;
                                        i += 1;
                                    }
                                    None => break,
                                }
                            }
                            out.push(v);
                        }
                        'N' => return None,
                        other => {
                            out.push('\\' as u32);
                            out.push(other as u32);
                        }
                    }
                }
            }
        }
    }
    Some(out)
}

/// `\xhh`, `\uhhhh` or `\Uhhhhhhhh` — how `repr` and `unicode_escape` spell
/// a non-printable character.
fn push_hex_escape(out: &mut String, c: char) {
    push_hex_escape_cp(out, c as u32);
}

fn push_hex_escape_cp(out: &mut String, cp: u32) {
    if cp < 0x100 {
        out.push_str(&format!("\\x{cp:02x}"));
    } else if cp < 0x10000 {
        out.push_str(&format!("\\u{cp:04x}"));
    } else {
        out.push_str(&format!("\\U{cp:08x}"));
    }
}

/// `c.encode("unicode_escape").decode("ascii")` for a backslash or a
/// non-printable character.
fn push_unicode_escape(out: &mut String, c: char) {
    match c {
        '\\' => out.push_str("\\\\"),
        '\t' => out.push_str("\\t"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        c => push_hex_escape(out, c),
    }
}

/// Python's `repr(b)` for a `bytes`.
fn py_repr_bytes(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::from("b");
    out.push(quote as char);
    for &byte in b {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            q if q == quote => {
                out.push('\\');
                out.push(q as char);
            }
            0x20..=0x7e => out.push(byte as char),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push(quote as char);
    out
}

/// Python's `repr(float)` (`'r'` format: shortest round-trip digits, fixed
/// notation for `-4 < decpt <= 16`, else exponent with at least two digits).
/// `add_dot_0` is false only inside a complex number's repr.
fn py_float_repr(f: f64, add_dot_0: bool) -> String {
    if f.is_nan() {
        return "nan".to_string();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    // Rust's shortest round-trip digits break ties upward; Python's repr
    // takes the shortest length and then the *closest* (half-even) digits of
    // that length, which exact `{:.Ne}` formatting reproduces.
    let shortest = format!("{:e}", f.abs());
    let n_digits = shortest
        .split_once('e')
        .map_or(1, |(m, _)| m.chars().filter(char::is_ascii_digit).count());
    let sci = format!("{:.*e}", n_digits.saturating_sub(1), f.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let sign = if f.is_sign_negative() { "-" } else { "" };
    if f == 0.0 {
        return format!("{sign}0{}", if add_dot_0 { ".0" } else { "" });
    }
    let decpt = exp + 1;
    let n = digits.len() as i32;
    let body = if decpt <= -4 || decpt > 16 {
        let mut m = digits[..1].to_string();
        if n > 1 {
            m.push('.');
            m.push_str(&digits[1..]);
        }
        let e = decpt - 1;
        format!("{m}e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs())
    } else if decpt <= 0 {
        format!("0.{}{digits}", "0".repeat((-decpt) as usize))
    } else if decpt >= n {
        format!(
            "{digits}{}{}",
            "0".repeat((decpt - n) as usize),
            if add_dot_0 { ".0" } else { "" }
        )
    } else {
        format!(
            "{}.{}",
            &digits[..decpt as usize],
            &digits[decpt as usize..]
        )
    };
    format!("{sign}{body}")
}

/// `repr(complex)`.
fn py_complex_repr(real: f64, imag: f64) -> String {
    if real == 0.0 && real.is_sign_positive() {
        format!("{}j", py_float_repr(imag, false))
    } else {
        let im = py_float_repr(imag, false);
        let sign = if im.starts_with('-') { "" } else { "+" };
        format!("({}{sign}{im}j)", py_float_repr(real, false))
    }
}

/// `_str_literal_helper`: the escaped body and the quote types it may use.
fn str_literal_helper(
    string: &str,
    quote_types: &[&'static str],
    escape_special_whitespace: bool,
) -> (String, Vec<&'static str>) {
    let mut escaped = String::with_capacity(string.len());
    for c in string.chars() {
        if !escape_special_whitespace && (c == '\n' || c == '\t') {
            escaped.push(c);
        } else if c == '\\' || !is_printable(c) {
            push_unicode_escape(&mut escaped, c);
        } else {
            escaped.push(c);
        }
    }
    let mut possible: Vec<&'static str> = quote_types.to_vec();
    if escaped.contains('\n') {
        possible.retain(|q| MULTI_QUOTES.contains(q));
    }
    possible.retain(|q| !escaped.contains(q));
    if possible.is_empty() {
        // Fall back to repr, preferring a quote type that starts with the
        // character repr picked.
        let r = py_repr_str(string);
        let first = &r[..1];
        let quote = quote_types
            .iter()
            .find(|q| q.contains(first))
            .copied()
            .unwrap_or(if first == "'" { "'" } else { "\"" });
        return (r[1..r.len() - 1].to_string(), vec![quote]);
    }
    if let Some(last) = escaped.chars().last() {
        // Stable sort: quotes whose first character differs from the text's
        // last character come first.
        possible.sort_by_key(|q| q.starts_with(last));
        if possible[0].starts_with(last) {
            escaped.pop();
            escaped.push('\\');
            escaped.push(last);
        }
    }
    (escaped, possible)
}

#[derive(Default)]
struct Unparser<'s> {
    out: String,
    indent: usize,
    in_try_star: bool,
    source: &'s str,
}

impl Unparser<'_> {
    fn write(&mut self, s: &str) {
        self.out.push_str(s);
    }

    fn maybe_newline(&mut self) {
        if !self.out.is_empty() {
            self.out.push('\n');
        }
    }

    fn fill(&mut self, text: &str) {
        self.maybe_newline();
        for _ in 0..self.indent {
            self.out.push_str("    ");
        }
        self.out.push_str(text);
    }

    fn block(&mut self, body: &[Stmt]) {
        self.write(":");
        self.indent += 1;
        self.stmts(body);
        self.indent -= 1;
    }

    fn stmts(&mut self, body: &[Stmt]) {
        for s in body {
            self.stmt(s);
        }
    }

    /// `_write_docstring_and_traverse_body`.
    fn scoped_body(&mut self, body: &[Stmt]) {
        self.write(":");
        self.indent += 1;
        match body.first() {
            Some(Stmt::Expr(e))
                if matches!(e.value.as_ref(), Expr::Constant(c)
                    if matches!(c.value, rustpython_ast::Constant::Str(_))) =>
            {
                let Expr::Constant(c) = e.value.as_ref() else {
                    unreachable!()
                };
                let rustpython_ast::Constant::Str(doc) = &c.value else {
                    unreachable!()
                };
                self.fill("");
                if c.kind.as_deref() == Some("u") {
                    self.write("u");
                }
                let (s, quotes) = str_literal_helper(doc, &MULTI_QUOTES, false);
                self.write(quotes[0]);
                self.write(&s);
                self.write(quotes[0]);
                self.stmts(&body[1..]);
            }
            _ => self.stmts(body),
        }
        self.indent -= 1;
    }

    fn type_params(&mut self, params: &[TypeParam]) {
        if params.is_empty() {
            return;
        }
        self.write("[");
        for (i, p) in params.iter().enumerate() {
            if i > 0 {
                self.write(", ");
            }
            match p {
                TypeParam::TypeVar(v) => {
                    self.write(v.name.as_str());
                    if let Some(bound) = &v.bound {
                        self.write(": ");
                        self.expr(bound, Prec::Test);
                    }
                }
                TypeParam::ParamSpec(p) => {
                    self.write("**");
                    self.write(p.name.as_str());
                }
                TypeParam::TypeVarTuple(t) => {
                    self.write("*");
                    self.write(t.name.as_str());
                }
            }
        }
        self.write("]");
    }

    fn decorators(&mut self, decorators: &[Expr]) {
        for d in decorators {
            self.fill("@");
            self.expr(d, Prec::Test);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn function(
        &mut self,
        keyword: &str,
        name: &str,
        decorators: &[Expr],
        type_params: &[TypeParam],
        args: &Arguments,
        returns: Option<&Expr>,
        body: &[Stmt],
    ) {
        self.maybe_newline();
        self.decorators(decorators);
        self.fill(&format!("{keyword} {name}"));
        self.type_params(type_params);
        self.write("(");
        self.arguments(args);
        self.write(")");
        if let Some(r) = returns {
            self.write(" -> ");
            self.expr(r, Prec::Test);
        }
        self.scoped_body(body);
    }

    fn handler(&mut self, h: &ExceptHandler) {
        let ExceptHandler::ExceptHandler(h) = h;
        self.fill(if self.in_try_star {
            "except*"
        } else {
            "except"
        });
        if let Some(t) = &h.type_ {
            self.write(" ");
            self.expr(t, Prec::Test);
        }
        if let Some(n) = &h.name {
            self.write(" as ");
            self.write(n.as_str());
        }
        self.block(&h.body);
    }

    #[allow(clippy::too_many_arguments)]
    fn try_stmt(
        &mut self,
        star: bool,
        body: &[Stmt],
        handlers: &[ExceptHandler],
        orelse: &[Stmt],
        finalbody: &[Stmt],
    ) {
        let prev = self.in_try_star;
        self.in_try_star = star;
        self.fill("try");
        self.block(body);
        for h in handlers {
            self.handler(h);
        }
        if !orelse.is_empty() {
            self.fill("else");
            self.block(orelse);
        }
        if !finalbody.is_empty() {
            self.fill("finally");
            self.block(finalbody);
        }
        self.in_try_star = prev;
    }

    fn for_stmt(
        &mut self,
        keyword: &str,
        target: &Expr,
        iter: &Expr,
        body: &[Stmt],
        orelse: &[Stmt],
    ) {
        self.fill(keyword);
        self.expr(target, Prec::Tuple);
        self.write(" in ");
        self.expr(iter, Prec::Test);
        self.block(body);
        if !orelse.is_empty() {
            self.fill("else");
            self.block(orelse);
        }
    }

    fn with_stmt(&mut self, keyword: &str, items: &[WithItem], body: &[Stmt]) {
        self.fill(keyword);
        for (i, item) in items.iter().enumerate() {
            if i > 0 {
                self.write(", ");
            }
            self.expr(&item.context_expr, Prec::Test);
            if let Some(v) = &item.optional_vars {
                self.write(" as ");
                self.expr(v, Prec::Test);
            }
        }
        self.block(body);
    }

    fn stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::FunctionDef(f) => self.function(
                "def",
                f.name.as_str(),
                &f.decorator_list,
                &f.type_params,
                &f.args,
                f.returns.as_deref(),
                &f.body,
            ),
            Stmt::AsyncFunctionDef(f) => self.function(
                "async def",
                f.name.as_str(),
                &f.decorator_list,
                &f.type_params,
                &f.args,
                f.returns.as_deref(),
                &f.body,
            ),
            Stmt::ClassDef(c) => {
                self.maybe_newline();
                self.decorators(&c.decorator_list);
                self.fill(&format!("class {}", c.name));
                self.type_params(&c.type_params);
                if !c.bases.is_empty() || !c.keywords.is_empty() {
                    self.write("(");
                    let mut comma = false;
                    for b in &c.bases {
                        if comma {
                            self.write(", ");
                        }
                        comma = true;
                        self.expr(b, Prec::Test);
                    }
                    for k in &c.keywords {
                        if comma {
                            self.write(", ");
                        }
                        comma = true;
                        self.keyword(k);
                    }
                    self.write(")");
                }
                self.scoped_body(&c.body);
            }
            Stmt::Return(r) => {
                self.fill("return");
                if let Some(v) = &r.value {
                    self.write(" ");
                    self.expr(v, Prec::Test);
                }
            }
            Stmt::Delete(d) => {
                self.fill("del ");
                self.interleave_exprs(&d.targets, Prec::Test);
            }
            Stmt::Assign(a) => {
                self.fill("");
                for t in &a.targets {
                    self.expr(t, Prec::Tuple);
                    self.write(" = ");
                }
                self.expr(&a.value, Prec::Test);
            }
            Stmt::TypeAlias(t) => {
                self.fill("type ");
                self.expr(&t.name, Prec::Test);
                self.type_params(&t.type_params);
                self.write(" = ");
                self.expr(&t.value, Prec::Test);
            }
            Stmt::AugAssign(a) => {
                self.fill("");
                self.expr(&a.target, Prec::Test);
                self.write(&format!(" {}= ", binop(&a.op).0));
                self.expr(&a.value, Prec::Test);
            }
            Stmt::AnnAssign(a) => {
                self.fill("");
                // rustpython sets `simple` even for `(x): int`; CPython does
                // not, so read the parenthesis off the positions.
                let parenthesized = a.range.start() < a.target.range().start();
                let parens =
                    (!a.simple || parenthesized) && matches!(a.target.as_ref(), Expr::Name(_));
                if parens {
                    self.write("(");
                }
                self.expr(&a.target, Prec::Test);
                if parens {
                    self.write(")");
                }
                self.write(": ");
                self.expr(&a.annotation, Prec::Test);
                if let Some(v) = &a.value {
                    self.write(" = ");
                    self.expr(v, Prec::Test);
                }
            }
            Stmt::For(f) => self.for_stmt("for ", &f.target, &f.iter, &f.body, &f.orelse),
            Stmt::AsyncFor(f) => {
                self.for_stmt("async for ", &f.target, &f.iter, &f.body, &f.orelse)
            }
            Stmt::While(w) => {
                self.fill("while ");
                self.expr(&w.test, Prec::Test);
                self.block(&w.body);
                if !w.orelse.is_empty() {
                    self.fill("else");
                    self.block(&w.orelse);
                }
            }
            Stmt::If(i) => {
                self.fill("if ");
                self.expr(&i.test, Prec::Test);
                self.block(&i.body);
                // Collapse nested ifs into equivalent elifs.
                let mut orelse = &i.orelse;
                while orelse.len() == 1 {
                    let Stmt::If(inner) = &orelse[0] else {
                        break;
                    };
                    self.fill("elif ");
                    self.expr(&inner.test, Prec::Test);
                    self.block(&inner.body);
                    orelse = &inner.orelse;
                }
                if !orelse.is_empty() {
                    self.fill("else");
                    self.block(orelse);
                }
            }
            Stmt::With(w) => self.with_stmt("with ", &w.items, &w.body),
            Stmt::AsyncWith(w) => self.with_stmt("async with ", &w.items, &w.body),
            Stmt::Match(m) => {
                self.fill("match ");
                self.expr(&m.subject, Prec::Test);
                self.write(":");
                self.indent += 1;
                for case in &m.cases {
                    self.match_case(case);
                }
                self.indent -= 1;
            }
            Stmt::Raise(r) => {
                self.fill("raise");
                if let Some(e) = &r.exc {
                    self.write(" ");
                    self.expr(e, Prec::Test);
                    if let Some(c) = &r.cause {
                        self.write(" from ");
                        self.expr(c, Prec::Test);
                    }
                }
            }
            Stmt::Try(t) => self.try_stmt(false, &t.body, &t.handlers, &t.orelse, &t.finalbody),
            Stmt::TryStar(t) => self.try_stmt(true, &t.body, &t.handlers, &t.orelse, &t.finalbody),
            Stmt::Assert(a) => {
                self.fill("assert ");
                self.expr(&a.test, Prec::Test);
                if let Some(m) = &a.msg {
                    self.write(", ");
                    self.expr(m, Prec::Test);
                }
            }
            Stmt::Import(i) => {
                self.fill("import ");
                self.aliases(&i.names);
            }
            Stmt::ImportFrom(i) => {
                self.fill("from ");
                let level = i.level.as_ref().map_or(0, |l| l.to_u32());
                self.write(&".".repeat(level as usize));
                if let Some(m) = &i.module {
                    self.write(m.as_str());
                }
                self.write(" import ");
                self.aliases(&i.names);
            }
            Stmt::Global(g) => {
                self.fill("global ");
                let names: Vec<&str> = g.names.iter().map(|n| n.as_str()).collect();
                self.write(&names.join(", "));
            }
            Stmt::Nonlocal(n) => {
                self.fill("nonlocal ");
                let names: Vec<&str> = n.names.iter().map(|n| n.as_str()).collect();
                self.write(&names.join(", "));
            }
            Stmt::Expr(e) => {
                self.fill("");
                self.expr(&e.value, Prec::Yield);
            }
            Stmt::Pass(_) => self.fill("pass"),
            Stmt::Break(_) => self.fill("break"),
            Stmt::Continue(_) => self.fill("continue"),
        }
    }

    fn aliases(&mut self, names: &[rustpython_ast::Alias]) {
        for (i, a) in names.iter().enumerate() {
            if i > 0 {
                self.write(", ");
            }
            self.write(a.name.as_str());
            if let Some(asname) = &a.asname {
                self.write(" as ");
                self.write(asname.as_str());
            }
        }
    }

    fn match_case(&mut self, case: &MatchCase) {
        self.fill("case ");
        self.pattern(&case.pattern, Prec::Test);
        if let Some(g) = &case.guard {
            self.write(" if ");
            self.expr(g, Prec::Test);
        }
        self.block(&case.body);
    }

    fn pattern(&mut self, p: &Pattern, prec: Prec) {
        match p {
            Pattern::MatchValue(v) => self.expr(&v.value, Prec::Test),
            Pattern::MatchSingleton(s) => self.constant(&s.value, None),
            Pattern::MatchSequence(s) => {
                self.write("[");
                for (i, p) in s.patterns.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.pattern(p, Prec::Test);
                }
                self.write("]");
            }
            Pattern::MatchStar(s) => {
                self.write("*");
                self.write(s.name.as_ref().map_or("_", |n| n.as_str()));
            }
            Pattern::MatchMapping(m) => {
                self.write("{");
                for (i, (k, p)) in m.keys.iter().zip(&m.patterns).enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.expr(k, Prec::Test);
                    self.write(": ");
                    self.pattern(p, Prec::Test);
                }
                if let Some(rest) = &m.rest {
                    if !m.keys.is_empty() {
                        self.write(", ");
                    }
                    self.write("**");
                    self.write(rest.as_str());
                }
                self.write("}");
            }
            Pattern::MatchClass(c) => {
                self.expr(&c.cls, Prec::Atom);
                self.write("(");
                for (i, p) in c.patterns.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.pattern(p, Prec::Test);
                }
                if !c.kwd_attrs.is_empty() {
                    if !c.patterns.is_empty() {
                        self.write(", ");
                    }
                    for (i, (a, p)) in c.kwd_attrs.iter().zip(&c.kwd_patterns).enumerate() {
                        if i > 0 {
                            self.write(", ");
                        }
                        self.write(a.as_str());
                        self.write("=");
                        self.pattern(p, Prec::Test);
                    }
                }
                self.write(")");
            }
            Pattern::MatchAs(a) => match (&a.name, &a.pattern) {
                (None, _) => self.write("_"),
                (Some(n), None) => self.write(n.as_str()),
                (Some(n), Some(inner)) => {
                    let parens = prec > Prec::Test;
                    if parens {
                        self.write("(");
                    }
                    self.pattern(inner, Prec::BOR);
                    self.write(" as ");
                    self.write(n.as_str());
                    if parens {
                        self.write(")");
                    }
                }
            },
            Pattern::MatchOr(o) => {
                let parens = prec > Prec::BOR;
                if parens {
                    self.write("(");
                }
                for (i, p) in o.patterns.iter().enumerate() {
                    if i > 0 {
                        self.write(" | ");
                    }
                    self.pattern(p, Prec::BOR.next());
                }
                if parens {
                    self.write(")");
                }
            }
        }
    }

    fn arguments(&mut self, args: &Arguments) {
        let mut first = true;
        let n_posonly = args.posonlyargs.len();
        for (index, a) in args.posonlyargs.iter().chain(&args.args).enumerate() {
            if first {
                first = false;
            } else {
                self.write(", ");
            }
            self.arg(&a.def);
            if let Some(d) = &a.default {
                self.write("=");
                self.expr(d, Prec::Test);
            }
            if index + 1 == n_posonly {
                self.write(", /");
            }
        }
        if args.vararg.is_some() || !args.kwonlyargs.is_empty() {
            if first {
                first = false;
            } else {
                self.write(", ");
            }
            self.write("*");
            if let Some(v) = &args.vararg {
                self.write(v.arg.as_str());
                if let Some(ann) = &v.annotation {
                    self.write(": ");
                    self.expr(ann, Prec::Test);
                }
            }
        }
        for a in &args.kwonlyargs {
            self.write(", ");
            self.arg(&a.def);
            if let Some(d) = &a.default {
                self.write("=");
                self.expr(d, Prec::Test);
            }
        }
        if let Some(k) = &args.kwarg {
            if !first {
                self.write(", ");
            }
            self.write("**");
            self.write(k.arg.as_str());
            if let Some(ann) = &k.annotation {
                self.write(": ");
                self.expr(ann, Prec::Test);
            }
        }
    }

    fn arg(&mut self, a: &rustpython_ast::Arg) {
        self.write(a.arg.as_str());
        if let Some(ann) = &a.annotation {
            self.write(": ");
            self.expr(ann, Prec::Test);
        }
    }

    fn keyword(&mut self, k: &Keyword) {
        match &k.arg {
            None => self.write("**"),
            Some(a) => {
                self.write(a.as_str());
                self.write("=");
            }
        }
        self.expr(&k.value, Prec::Test);
    }

    fn interleave_exprs(&mut self, exprs: &[Expr], prec: Prec) {
        for (i, e) in exprs.iter().enumerate() {
            if i > 0 {
                self.write(", ");
            }
            self.expr(e, prec);
        }
    }

    /// `items_view`: a single item gets a trailing comma.
    fn items_view(&mut self, exprs: &[Expr]) {
        if exprs.len() == 1 {
            self.expr(&exprs[0], Prec::Test);
            self.write(",");
        } else {
            self.interleave_exprs(exprs, Prec::Test);
        }
    }

    fn comprehension(&mut self, g: &Comprehension) {
        self.write(if g.is_async { " async for " } else { " for " });
        self.expr(&g.target, Prec::Tuple);
        self.write(" in ");
        self.expr(&g.iter, Prec::Test.next());
        for cond in &g.ifs {
            self.write(" if ");
            self.expr(cond, Prec::Test.next());
        }
    }

    fn constant(&mut self, value: &rustpython_ast::Constant, kind: Option<&str>) {
        use rustpython_ast::Constant as C;
        match value {
            C::Ellipsis => self.write("..."),
            C::Tuple(items) => {
                self.write("(");
                if items.len() == 1 {
                    self.write_constant(&items[0]);
                    self.write(",");
                } else {
                    for (i, c) in items.iter().enumerate() {
                        if i > 0 {
                            self.write(", ");
                        }
                        self.write_constant(c);
                    }
                }
                self.write(")");
            }
            _ => {
                if kind == Some("u") {
                    self.write("u");
                }
                self.write_constant(value);
            }
        }
    }

    /// `_write_constant`.
    fn write_constant(&mut self, value: &rustpython_ast::Constant) {
        use rustpython_ast::Constant as C;
        let text = match value {
            C::None => "None".to_string(),
            C::Bool(true) => "True".to_string(),
            C::Bool(false) => "False".to_string(),
            C::Str(s) => py_repr_str(s),
            C::Bytes(b) => py_repr_bytes(b),
            C::Int(i) => i.to_string(),
            C::Float(f) => py_float_repr(*f, true)
                .replace("inf", INFSTR)
                .replace("nan", &format!("({INFSTR}-{INFSTR})")),
            C::Complex { real, imag } => py_complex_repr(*real, *imag)
                .replace("inf", INFSTR)
                .replace("nan", &format!("({INFSTR}-{INFSTR})")),
            C::Ellipsis => "Ellipsis".to_string(),
            C::Tuple(_) => {
                self.constant(value, None);
                return;
            }
        };
        self.write(&text);
    }

    /// `repr(value)` with lone surrogates restored from the literal's source,
    /// when the source decodes to exactly `value` modulo U+FFFD.
    fn recovered_str_repr(
        &self,
        value: &str,
        range: rustpython_ast::text_size::TextRange,
    ) -> Option<String> {
        let segment = self
            .source
            .get(usize::from(range.start())..usize::from(range.end()))?;
        let decoded = decode_str_literal(segment)?;
        let lossy: Vec<u32> = decoded
            .iter()
            .map(|&cp| {
                if (0xD800..0xE000).contains(&cp) {
                    0xFFFD
                } else {
                    cp
                }
            })
            .collect();
        let expected: Vec<u32> = value.chars().map(|c| c as u32).collect();
        (lossy == expected).then(|| py_repr_codepoints(&decoded))
    }

    fn joined_str(&mut self, values: &[Expr]) {
        self.write("f");
        let parts: Vec<(String, bool)> = values
            .iter()
            .map(|v| {
                let mut inner = Unparser {
                    source: self.source,
                    ..Unparser::default()
                };
                inner.fstring_inner(v, false);
                (inner.out, matches!(v, Expr::Constant(_)))
            })
            .collect();
        let mut new_parts: Vec<String> = Vec::new();
        let mut quote_types: Vec<&'static str> = ALL_QUOTES.to_vec();
        let mut fallback_to_repr = false;
        for (value, is_constant) in &parts {
            if *is_constant {
                let (value, new_quote_types) = str_literal_helper(value, &quote_types, true);
                if new_quote_types.iter().all(|q| !quote_types.contains(q)) {
                    fallback_to_repr = true;
                    break;
                }
                quote_types = new_quote_types;
                new_parts.push(value);
            } else {
                if value.contains('\n') {
                    quote_types.retain(|q| MULTI_QUOTES.contains(q));
                }
                let new_quote_types: Vec<&'static str> = quote_types
                    .iter()
                    .copied()
                    .filter(|q| !value.contains(q))
                    .collect();
                if !new_quote_types.is_empty() {
                    quote_types = new_quote_types;
                }
                new_parts.push(value.clone());
            }
        }
        if fallback_to_repr {
            quote_types = vec!["'''"];
            new_parts.clear();
            for (value, is_constant) in &parts {
                if *is_constant {
                    let r = py_repr_str(&format!("\"{value}"));
                    // `repr('"' + value)` is single-quoted; drop `'"` and `'`.
                    new_parts.push(r[2..r.len() - 1].to_string());
                } else {
                    new_parts.push(value.clone());
                }
            }
        }
        let quote = quote_types.first().copied().unwrap_or("'");
        self.write(quote);
        self.write(&new_parts.concat());
        self.write(quote);
    }

    /// `_write_fstring_inner`.
    fn fstring_inner(&mut self, node: &Expr, is_format_spec: bool) {
        match node {
            Expr::JoinedStr(j) => {
                for v in &j.values {
                    self.fstring_inner(v, is_format_spec);
                }
            }
            Expr::Constant(c) => {
                if let rustpython_ast::Constant::Str(s) = &c.value {
                    let mut value = s.replace('{', "{{").replace('}', "}}");
                    if is_format_spec {
                        value = value
                            .replace('\\', "\\\\")
                            .replace('\'', "\\'")
                            .replace('"', "\\\"")
                            .replace('\n', "\\n");
                    }
                    self.write(&value);
                }
            }
            Expr::FormattedValue(f) => self.formatted_value(f),
            other => self.expr(other, Prec::Test),
        }
    }

    fn formatted_value(&mut self, f: &rustpython_ast::ExprFormattedValue) {
        self.write("{");
        let mut inner = Unparser {
            source: self.source,
            ..Unparser::default()
        };
        inner.expr(&f.value, Prec::Test.next());
        if inner.out.starts_with('{') {
            self.write(" ");
        }
        self.write(&inner.out);
        match f.conversion {
            ConversionFlag::None => {}
            ConversionFlag::Str => self.write("!s"),
            ConversionFlag::Ascii => self.write("!a"),
            ConversionFlag::Repr => self.write("!r"),
        }
        if let Some(spec) = &f.format_spec {
            self.write(":");
            self.fstring_inner(spec, true);
        }
        self.write("}");
    }

    fn open(&mut self, cond: bool) {
        if cond {
            self.write("(");
        }
    }

    fn close(&mut self, cond: bool) {
        if cond {
            self.write(")");
        }
    }

    /// Traverse `e` with `prec` as its `get_precedence` value (the precedence
    /// its parent set, `TEST` when the parent set none).
    fn expr(&mut self, e: &Expr, prec: Prec) {
        match e {
            Expr::BoolOp(b) => {
                let (op, mut op_prec) = match b.op {
                    BoolOp::And => (" and ", Prec::And),
                    BoolOp::Or => (" or ", Prec::Or),
                };
                let parens = prec > op_prec;
                self.open(parens);
                for (i, v) in b.values.iter().enumerate() {
                    if i > 0 {
                        self.write(op);
                    }
                    op_prec = op_prec.next();
                    self.expr(v, op_prec);
                }
                self.close(parens);
            }
            Expr::NamedExpr(n) => {
                let parens = prec > Prec::NamedExpr;
                self.open(parens);
                self.expr(&n.target, Prec::Atom);
                self.write(" := ");
                self.expr(&n.value, Prec::Atom);
                self.close(parens);
            }
            Expr::BinOp(b) => {
                let (op, op_prec) = binop(&b.op);
                let parens = prec > op_prec;
                self.open(parens);
                let (lp, rp) = if op == "**" {
                    (op_prec.next(), op_prec)
                } else {
                    (op_prec, op_prec.next())
                };
                self.expr(&b.left, lp);
                self.write(&format!(" {op} "));
                self.expr(&b.right, rp);
                self.close(parens);
            }
            Expr::UnaryOp(u) => {
                let (op, op_prec) = match u.op {
                    UnaryOp::Invert => ("~", Prec::Factor),
                    UnaryOp::Not => ("not", Prec::Not),
                    UnaryOp::UAdd => ("+", Prec::Factor),
                    UnaryOp::USub => ("-", Prec::Factor),
                };
                let parens = prec > op_prec;
                self.open(parens);
                self.write(op);
                if op_prec != Prec::Factor {
                    self.write(" ");
                }
                self.expr(&u.operand, op_prec);
                self.close(parens);
            }
            Expr::Lambda(l) => {
                let parens = prec > Prec::Test;
                self.open(parens);
                self.write("lambda");
                let mut args = Unparser {
                    source: self.source,
                    ..Unparser::default()
                };
                args.arguments(&l.args);
                if !args.out.is_empty() {
                    self.write(" ");
                    self.write(&args.out);
                }
                self.write(": ");
                self.expr(&l.body, Prec::Test);
                self.close(parens);
            }
            Expr::IfExp(i) => {
                let parens = prec > Prec::Test;
                self.open(parens);
                self.expr(&i.body, Prec::Test.next());
                self.write(" if ");
                self.expr(&i.test, Prec::Test.next());
                self.write(" else ");
                self.expr(&i.orelse, Prec::Test);
                self.close(parens);
            }
            Expr::Dict(d) => {
                self.write("{");
                for (i, (k, v)) in d.keys.iter().zip(&d.values).enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    match k {
                        None => {
                            self.write("**");
                            self.expr(v, Prec::Expr);
                        }
                        Some(k) => {
                            self.expr(k, Prec::Test);
                            self.write(": ");
                            self.expr(v, Prec::Test);
                        }
                    }
                }
                self.write("}");
            }
            Expr::Set(s) => {
                if s.elts.is_empty() {
                    self.write("{*()}");
                } else {
                    self.write("{");
                    self.interleave_exprs(&s.elts, Prec::Test);
                    self.write("}");
                }
            }
            Expr::ListComp(c) => {
                self.write("[");
                self.expr(&c.elt, Prec::Test);
                for g in &c.generators {
                    self.comprehension(g);
                }
                self.write("]");
            }
            Expr::SetComp(c) => {
                self.write("{");
                self.expr(&c.elt, Prec::Test);
                for g in &c.generators {
                    self.comprehension(g);
                }
                self.write("}");
            }
            Expr::DictComp(c) => {
                self.write("{");
                self.expr(&c.key, Prec::Test);
                self.write(": ");
                self.expr(&c.value, Prec::Test);
                for g in &c.generators {
                    self.comprehension(g);
                }
                self.write("}");
            }
            Expr::GeneratorExp(c) => {
                self.write("(");
                self.expr(&c.elt, Prec::Test);
                for g in &c.generators {
                    self.comprehension(g);
                }
                self.write(")");
            }
            Expr::Await(a) => {
                let parens = prec > Prec::Await;
                self.open(parens);
                self.write("await ");
                self.expr(&a.value, Prec::Atom);
                self.close(parens);
            }
            Expr::Yield(y) => {
                let parens = prec > Prec::Yield;
                self.open(parens);
                self.write("yield");
                if let Some(v) = &y.value {
                    self.write(" ");
                    self.expr(v, Prec::Atom);
                }
                self.close(parens);
            }
            Expr::YieldFrom(y) => {
                let parens = prec > Prec::Yield;
                self.open(parens);
                self.write("yield from ");
                self.expr(&y.value, Prec::Atom);
                self.close(parens);
            }
            Expr::Compare(c) => {
                let parens = prec > Prec::Cmp;
                self.open(parens);
                self.expr(&c.left, Prec::Cmp.next());
                for (op, right) in c.ops.iter().zip(&c.comparators) {
                    self.write(" ");
                    self.write(cmpop(op));
                    self.write(" ");
                    self.expr(right, Prec::Cmp.next());
                }
                self.close(parens);
            }
            Expr::Call(c) => {
                self.expr(&c.func, Prec::Atom);
                self.write("(");
                let mut comma = false;
                for a in &c.args {
                    if comma {
                        self.write(", ");
                    }
                    comma = true;
                    self.expr(a, Prec::Test);
                }
                for k in &c.keywords {
                    if comma {
                        self.write(", ");
                    }
                    comma = true;
                    self.keyword(k);
                }
                self.write(")");
            }
            Expr::FormattedValue(f) => self.formatted_value(f),
            Expr::JoinedStr(j) => self.joined_str(&j.values),
            Expr::Constant(c) => match &c.value {
                rustpython_ast::Constant::Str(v) if v.contains('\u{fffd}') => {
                    if c.kind.as_deref() == Some("u") {
                        self.write("u");
                    }
                    let text = self
                        .recovered_str_repr(v, c.range)
                        .unwrap_or_else(|| py_repr_str(v));
                    self.write(&text);
                }
                _ => self.constant(&c.value, c.kind.as_deref()),
            },
            Expr::Attribute(a) => {
                self.expr(&a.value, Prec::Atom);
                if let Expr::Constant(c) = a.value.as_ref()
                    && matches!(c.value, rustpython_ast::Constant::Int(_))
                {
                    self.write(" ");
                }
                self.write(".");
                self.write(a.attr.as_str());
            }
            Expr::Subscript(s) => {
                self.expr(&s.value, Prec::Atom);
                self.write("[");
                match s.slice.as_ref() {
                    Expr::Tuple(t) if !t.elts.is_empty() => self.items_view(&t.elts),
                    // CPython parses `x[*a]` as a one-element tuple slice;
                    // rustpython keeps the bare `Starred`.
                    starred @ Expr::Starred(_) => {
                        self.expr(starred, Prec::Test);
                        self.write(",");
                    }
                    other => self.expr(other, Prec::Test),
                }
                self.write("]");
            }
            Expr::Starred(s) => {
                self.write("*");
                self.expr(&s.value, Prec::Expr);
            }
            Expr::Name(n) => self.write(n.id.as_str()),
            Expr::List(l) => {
                self.write("[");
                self.interleave_exprs(&l.elts, Prec::Test);
                self.write("]");
            }
            Expr::Tuple(t) => {
                let parens = t.elts.is_empty() || prec > Prec::Tuple;
                self.open(parens);
                self.items_view(&t.elts);
                self.close(parens);
            }
            Expr::Slice(s) => {
                if let Some(l) = &s.lower {
                    self.expr(l, Prec::Test);
                }
                self.write(":");
                if let Some(u) = &s.upper {
                    self.expr(u, Prec::Test);
                }
                if let Some(st) = &s.step {
                    self.write(":");
                    self.expr(st, Prec::Test);
                }
            }
        }
    }
}

fn binop(op: &Operator) -> (&'static str, Prec) {
    match op {
        Operator::Add => ("+", Prec::Arith),
        Operator::Sub => ("-", Prec::Arith),
        Operator::Mult => ("*", Prec::Term),
        Operator::MatMult => ("@", Prec::Term),
        Operator::Div => ("/", Prec::Term),
        Operator::Mod => ("%", Prec::Term),
        Operator::LShift => ("<<", Prec::Shift),
        Operator::RShift => (">>", Prec::Shift),
        Operator::BitOr => ("|", Prec::BOR),
        Operator::BitXor => ("^", Prec::Bxor),
        Operator::BitAnd => ("&", Prec::Band),
        Operator::FloorDiv => ("//", Prec::Term),
        Operator::Pow => ("**", Prec::Power),
    }
}

fn cmpop(op: &CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "==",
        CmpOp::NotEq => "!=",
        CmpOp::Lt => "<",
        CmpOp::LtE => "<=",
        CmpOp::Gt => ">",
        CmpOp::GtE => ">=",
        CmpOp::Is => "is",
        CmpOp::IsNot => "is not",
        CmpOp::In => "in",
        CmpOp::NotIn => "not in",
    }
}

#[cfg(test)]
mod tests {
    use super::{py_float_repr, py_repr_str, unparse_function};
    use rustpython_ast::Mod;

    fn unparse_first(src: &str) -> String {
        let Mod::Module(m) =
            rustpython_parser::parse(src, rustpython_parser::Mode::Module, "<t>").unwrap()
        else {
            unreachable!()
        };
        unparse_function(&m.body[0], src)
    }

    // Expected strings are `ast.unparse(ast.parse(src).body[0])` on CPython 3.13.

    #[test]
    fn boolop_operands_get_increasing_precedence() {
        assert_eq!(
            unparse_first("if a != b or c and not d(e, ''):\n    pass\n"),
            "if a != b or (c and (not d(e, ''))):\n    pass"
        );
    }

    #[test]
    fn layout_matches_lib_ast() {
        let src = "@dec\ndef f(a, /, b=1, *c, d, **e) -> int:\n    \"\"\"Doc.\"\"\"\n    def g():\n        return a, b\n    try:\n        x = yield\n    except (A, B) as err:\n        raise X from err\n    if a:\n        pass\n    elif b:\n        pass\n    else:\n        del a, b\n";
        assert_eq!(
            unparse_first(src),
            "@dec\ndef f(a, /, b=1, *c, d, **e) -> int:\n    \"\"\"Doc.\"\"\"\n\n    def g():\n        return (a, b)\n    try:\n        x = (yield)\n    except (A, B) as err:\n        raise X from err\n    if a:\n        pass\n    elif b:\n        pass\n    else:\n        del a, b"
        );
    }

    #[test]
    fn literals_follow_repr() {
        assert_eq!(py_repr_str("it's"), "\"it's\"");
        assert_eq!(py_repr_str("a\u{a0}b\n"), "'a\\xa0b\\n'");
        assert_eq!(py_float_repr(1e16, true), "1e+16");
        assert_eq!(py_float_repr(1e-5, true), "1e-05");
        assert_eq!(py_float_repr(0.0001, true), "0.0001");
        assert_eq!(py_float_repr(123.0, true), "123.0");
        assert_eq!(py_float_repr(1.5e300, true), "1.5e+300");
        assert_eq!(
            py_float_repr("2001599834386887.25".parse().unwrap(), true),
            "2001599834386887.2"
        );
        assert_eq!(
            unparse_first("x = f\"{a!r:>{w}} {{b}}\" + 3 .real + 1e400\n"),
            "x = f'{a!r:>{w}} {{b}}' + 3 .real + 1e309"
        );
    }
}
