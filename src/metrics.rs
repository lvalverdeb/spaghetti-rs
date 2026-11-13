//! Published code metrics — mirrors `spaghetti/metrics.py`: McCabe cyclomatic
//! complexity as `radon cc` counts it, SonarSource cognitive complexity,
//! Halstead volume and the SEI/Radon Maintainability Index.
//!
//! Every function is pure and defined by an exact counting rule; the Python
//! port computes the same numbers, so the two binaries' reports agree.

use crate::ast_helpers::LineIndex;
use crate::pyast::{
    Node, for_each_descendant, py_boolop_name, py_cmpop_name, py_operator_name, py_splitlines,
    py_strip, py_unaryop_name,
};
use rustpython_ast::{Constant, Expr, Pattern, Ranged, Stmt};
use std::collections::HashSet;

// ── Cyclomatic complexity (McCabe, as counted by `radon cc`) ─────────────────

fn is_wildcard_case(case: &rustpython_ast::MatchCase) -> bool {
    matches!(&case.pattern, Pattern::MatchAs(a) if a.pattern.is_none())
}

/// Radon's rules: `if`/`elif`/ternary +1; `for`/`while` +1 plus 1 for an
/// `else`; each `except` +1 plus 1 for `try/else`; `and`/`or` chains
/// +(operands - 1); each comprehension `for` clause +1 plus its `if`s;
/// `assert` +1; `match` + arms, minus one when a catch-all arm exists.
/// `with` and `lambda` do not count; nested defs are separate units.
fn decision_points(node: Node<'_>) -> i64 {
    match node {
        Node::Stmt(Stmt::If(_)) | Node::Expr(Expr::IfExp(_)) | Node::Stmt(Stmt::Assert(_)) => 1,
        Node::Stmt(Stmt::For(f)) => 1 + i64::from(!f.orelse.is_empty()),
        Node::Stmt(Stmt::AsyncFor(f)) => 1 + i64::from(!f.orelse.is_empty()),
        Node::Stmt(Stmt::While(w)) => 1 + i64::from(!w.orelse.is_empty()),
        Node::Stmt(Stmt::Try(t)) => t.handlers.len() as i64 + i64::from(!t.orelse.is_empty()),
        Node::Stmt(Stmt::TryStar(t)) => t.handlers.len() as i64 + i64::from(!t.orelse.is_empty()),
        Node::Expr(Expr::BoolOp(b)) => b.values.len() as i64 - 1,
        Node::Comprehension(c) => 1 + c.ifs.len() as i64,
        Node::Stmt(Stmt::Match(m)) => {
            let wildcard = m.cases.iter().any(is_wildcard_case);
            (m.cases.len() as i64 - i64::from(wildcard)).max(0)
        }
        _ => 0,
    }
}

/// Pre-order walk of `node`'s children that does not descend into nested
/// function or class definitions (lambdas are expressions and are
/// descended), nor into `assert` statements (Radon counts the assert and
/// stops there) — mirrors `_iter_own_scope`.
fn iter_own_scope<'a>(node: Node<'a>, f: &mut impl FnMut(Node<'a>)) {
    for child in node.children() {
        f(child);
        if !child.is_scope_def() && !matches!(child, Node::Stmt(Stmt::Assert(_))) {
            iter_own_scope(child, f);
        }
    }
}

/// `stmt` itself, then its own-scope descendants — mirrors `_walk_stmt`.
fn walk_stmt<'a>(stmt: &'a Stmt, f: &mut impl FnMut(Node<'a>)) {
    let node = Node::Stmt(stmt);
    f(node);
    if !node.is_scope_def() && !matches!(stmt, Stmt::Assert(_)) {
        iter_own_scope(node, f);
    }
}

fn own_decisions(stmts: &[Stmt]) -> i64 {
    let mut total = 0;
    for stmt in stmts {
        walk_stmt(stmt, &mut |node| total += decision_points(node));
    }
    total
}

/// McCabe complexity of one function body, identical to `radon cc`. Nested
/// functions and classes are their own units and do not contribute.
pub fn cyclomatic_complexity(body: &[Stmt]) -> i64 {
    1 + own_decisions(body)
}

/// Function and class definitions reachable from `stmts` without entering
/// another definition (so a class under `if TYPE_CHECKING:` is found).
fn scope_defs(stmts: &[Stmt]) -> Vec<&Stmt> {
    let mut defs = Vec::new();
    for stmt in stmts {
        walk_stmt(stmt, &mut |node| {
            if let Node::Stmt(s) = node
                && node.is_scope_def()
            {
                defs.push(s);
            }
        });
    }
    defs
}

/// Radon's module `total_complexity` (the MI input): 1 + module-level
/// decision points + each module-level function's own decision points + for
/// each module-level class its body-level decision points plus, per method,
/// 1 + the method's own decision points.
pub fn module_cyclomatic_total(body: &[Stmt]) -> i64 {
    let mut total = 1 + own_decisions(body);
    for def in scope_defs(body) {
        match def {
            Stmt::FunctionDef(f) => total += own_decisions(&f.body),
            Stmt::AsyncFunctionDef(f) => total += own_decisions(&f.body),
            Stmt::ClassDef(c) => {
                total += own_decisions(&c.body);
                for member in scope_defs(&c.body) {
                    match member {
                        Stmt::FunctionDef(m) => total += 1 + own_decisions(&m.body),
                        Stmt::AsyncFunctionDef(m) => total += 1 + own_decisions(&m.body),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    total
}

// ── Cognitive complexity (SonarSource, 2018 specification) ────────────────────

/// Walks one function. Structural increments (+1 + nesting) for `if`,
/// ternary, `match`, `for`, `while` and `except`; hybrid increments (+1, no
/// nesting) for `elif` and `else`; +1 per boolean-operator sequence; +1 per
/// direct recursive call. Nested functions and lambdas raise the nesting
/// level without incrementing. Shorthand structures (`with`, `assert`,
/// comprehensions, `return`, `break`) add nothing.
struct Cognitive<'a> {
    name: &'a str,
    total: i64,
}

impl<'a> Cognitive<'a> {
    fn body(&mut self, stmts: &[Stmt], nesting: i64) {
        for stmt in stmts {
            self.stmt(stmt, nesting);
        }
    }

    fn stmt(&mut self, node: &Stmt, nesting: i64) {
        match node {
            Stmt::If(i) => {
                self.total += 1 + nesting;
                self.expr(&i.test, nesting);
                self.body(&i.body, nesting + 1);
                self.else_chain(&i.orelse, nesting);
            }
            Stmt::For(f) => self.loop_(&f.iter, &f.body, &f.orelse, nesting),
            Stmt::AsyncFor(f) => self.loop_(&f.iter, &f.body, &f.orelse, nesting),
            Stmt::While(w) => self.loop_(&w.test, &w.body, &w.orelse, nesting),
            Stmt::Try(t) => self.try_(&t.body, &t.handlers, &t.orelse, &t.finalbody, nesting),
            Stmt::TryStar(t) => self.try_(&t.body, &t.handlers, &t.orelse, &t.finalbody, nesting),
            Stmt::Match(m) => {
                self.total += 1 + nesting;
                self.expr(&m.subject, nesting);
                for case in &m.cases {
                    if let Some(guard) = &case.guard {
                        self.expr(guard, nesting + 1);
                    }
                    self.body(&case.body, nesting + 1);
                }
            }
            Stmt::FunctionDef(f) => self.body(&f.body, nesting + 1),
            Stmt::AsyncFunctionDef(f) => self.body(&f.body, nesting + 1),
            Stmt::ClassDef(_) => {} // a class body is its own unit
            other => self.generic(Node::Stmt(other), nesting),
        }
    }

    fn else_chain(&mut self, orelse: &[Stmt], nesting: i64) {
        if orelse.is_empty() {
            return;
        }
        self.total += 1; // elif / else: hybrid increment, no nesting penalty
        if let [Stmt::If(elif)] = orelse {
            self.expr(&elif.test, nesting);
            self.body(&elif.body, nesting + 1);
            self.else_chain(&elif.orelse, nesting);
        } else {
            self.body(orelse, nesting + 1);
        }
    }

    fn loop_(&mut self, head: &Expr, body: &[Stmt], orelse: &[Stmt], nesting: i64) {
        self.total += 1 + nesting;
        self.expr(head, nesting);
        self.body(body, nesting + 1);
        if !orelse.is_empty() {
            self.total += 1;
            self.body(orelse, nesting + 1);
        }
    }

    fn try_(
        &mut self,
        body: &[Stmt],
        handlers: &[rustpython_ast::ExceptHandler],
        orelse: &[Stmt],
        finalbody: &[Stmt],
        nesting: i64,
    ) {
        self.body(body, nesting);
        for handler in handlers {
            let rustpython_ast::ExceptHandler::ExceptHandler(h) = handler;
            self.total += 1 + nesting;
            self.body(&h.body, nesting + 1);
        }
        self.body(orelse, nesting);
        self.body(finalbody, nesting);
    }

    /// Statement-side generic traversal: expression children go through
    /// `expr`, statement children through `stmt`, everything else
    /// (with-items, keywords, handlers, ...) is walked for the same.
    fn generic(&mut self, node: Node<'_>, nesting: i64) {
        for child in node.children() {
            match child {
                Node::Expr(e) => self.expr(e, nesting),
                Node::Stmt(s) => self.stmt(s, nesting),
                other => self.generic(other, nesting),
            }
        }
    }

    fn expr(&mut self, node: &Expr, nesting: i64) {
        match node {
            Expr::BoolOp(b) => {
                self.total += 1;
                for value in &b.values {
                    self.expr(value, nesting);
                }
            }
            Expr::IfExp(i) => {
                self.total += 1 + nesting;
                self.expr(&i.test, nesting);
                self.expr(&i.body, nesting + 1);
                self.expr(&i.orelse, nesting + 1);
            }
            Expr::Lambda(l) => self.expr(&l.body, nesting + 1),
            Expr::Call(c) => {
                if self.is_recursive_call(c) {
                    self.total += 1;
                }
                self.generic_expr(Node::Expr(node), nesting);
            }
            other => self.generic_expr(Node::Expr(other), nesting),
        }
    }

    fn generic_expr(&mut self, node: Node<'_>, nesting: i64) {
        for child in node.children() {
            match child {
                Node::Expr(e) => self.expr(e, nesting),
                other => self.generic_expr(other, nesting), // comprehension clauses, keywords
            }
        }
    }

    fn is_recursive_call(&self, call: &rustpython_ast::ExprCall) -> bool {
        match call.func.as_ref() {
            Expr::Name(n) => n.id.as_str() == self.name,
            Expr::Attribute(a) => {
                a.attr.as_str() == self.name
                    && matches!(a.value.as_ref(), Expr::Name(v) if matches!(v.id.as_str(), "self" | "cls"))
            }
            _ => false,
        }
    }
}

/// Sonar cognitive complexity of one function (`name`, `body`), nested
/// functions included.
pub fn cognitive_complexity(name: &str, body: &[Stmt]) -> i64 {
    let mut walker = Cognitive { name, total: 0 };
    walker.body(body, 0);
    walker.total
}

// ── Halstead volume (Radon's operator/operand rules) ─────────────────────────

/// What `_operand_key` returns, with Python's equality folded in: `1`,
/// `1.0` and `True` are one operand, `"1"` another, `b"1"` a third; any
/// other expression is distinct per occurrence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum OperandKey {
    Str(String),
    Bytes(Vec<u8>),
    /// Any number equal to an integer, as its exact decimal digits.
    Integer(String),
    Float(u64),
    Complex(u64, u64),
    None,
    Ellipsis,
    Tuple(Vec<OperandKey>),
    Unique(usize),
}

fn integral_digits(f: f64) -> Option<String> {
    if f.is_finite() && f.fract() == 0.0 {
        Some(if f == 0.0 {
            "0".to_string()
        } else {
            format!("{f:.0}")
        })
    } else {
        None
    }
}

fn constant_key(value: &Constant) -> OperandKey {
    match value {
        Constant::Str(s) => OperandKey::Str(s.clone()),
        Constant::Bytes(b) => OperandKey::Bytes(b.clone()),
        Constant::Int(i) => OperandKey::Integer(i.to_string()),
        Constant::Bool(b) => OperandKey::Integer(if *b { "1" } else { "0" }.to_string()),
        Constant::Float(f) => match integral_digits(*f) {
            Some(digits) => OperandKey::Integer(digits),
            None => OperandKey::Float(f.to_bits()),
        },
        Constant::Complex { real, imag } if *imag == 0.0 => match integral_digits(*real) {
            Some(digits) => OperandKey::Integer(digits),
            None => OperandKey::Float(real.to_bits()),
        },
        Constant::Complex { real, imag } => OperandKey::Complex(real.to_bits(), imag.to_bits()),
        Constant::None => OperandKey::None,
        Constant::Ellipsis => OperandKey::Ellipsis,
        Constant::Tuple(items) => OperandKey::Tuple(items.iter().map(constant_key).collect()),
    }
}

struct Halstead<'a> {
    operators: usize,
    operands: usize,
    distinct_operators: HashSet<&'static str>,
    distinct_operands: HashSet<(Option<&'a str>, OperandKey)>,
    next_unique: usize,
}

impl<'a> Halstead<'a> {
    fn operand_key(&mut self, node: &Expr) -> OperandKey {
        match node {
            Expr::Name(n) => OperandKey::Str(n.id.to_string()),
            Expr::Attribute(a) => OperandKey::Str(a.attr.to_string()),
            Expr::Constant(c) => constant_key(&c.value),
            _ => {
                self.next_unique += 1;
                OperandKey::Unique(self.next_unique)
            }
        }
    }

    fn count(&mut self, context: Option<&'a str>, ops: &[&'static str], opnds: &[&Expr]) {
        self.operators += ops.len();
        self.operands += opnds.len();
        self.distinct_operators.extend(ops.iter().copied());
        for operand in opnds {
            let key = self.operand_key(operand);
            self.distinct_operands.insert((context, key));
        }
    }

    fn visit(&mut self, node: Node<'a>, context: Option<&'a str>) {
        // Radon visits a function's body only: annotations, defaults and
        // decorators contribute nothing.
        match node {
            Node::Stmt(Stmt::FunctionDef(f)) => {
                for stmt in &f.body {
                    self.visit(Node::Stmt(stmt), Some(f.name.as_str()));
                }
                return;
            }
            Node::Stmt(Stmt::AsyncFunctionDef(f)) => {
                for stmt in &f.body {
                    self.visit(Node::Stmt(stmt), Some(f.name.as_str()));
                }
                return;
            }
            Node::Expr(Expr::BinOp(b)) => {
                self.count(context, &[py_operator_name(&b.op)], &[&b.left, &b.right]);
            }
            Node::Expr(Expr::UnaryOp(u)) => {
                self.count(context, &[py_unaryop_name(&u.op)], &[&u.operand]);
            }
            Node::Expr(Expr::BoolOp(b)) => {
                let values: Vec<&Expr> = b.values.iter().collect();
                self.count(context, &[py_boolop_name(&b.op)], &values);
            }
            Node::Stmt(Stmt::AugAssign(a)) => {
                self.count(context, &[py_operator_name(&a.op)], &[&a.target, &a.value]);
            }
            Node::Expr(Expr::Compare(c)) => {
                let ops: Vec<&'static str> = c.ops.iter().map(py_cmpop_name).collect();
                let mut opnds: Vec<&Expr> = c.comparators.iter().collect();
                opnds.push(&c.left);
                self.count(context, &ops, &opnds);
            }
            _ => {}
        }
        for child in node.children() {
            self.visit(child, context);
        }
    }
}

/// `N * log2(h)` over the whole module, with operators = binary, unary,
/// boolean, augmented-assignment and comparison operators and operands =
/// their direct operands (Radon's `HalsteadVisitor`, reproduced exactly).
/// Operands are distinct per enclosing function name, as Radon keys them.
pub fn halstead_volume(body: &[Stmt]) -> f64 {
    let mut h = Halstead {
        operators: 0,
        operands: 0,
        distinct_operators: HashSet::new(),
        distinct_operands: HashSet::new(),
        next_unique: 0,
    };
    for stmt in body {
        h.visit(Node::Stmt(stmt), None);
    }
    let vocabulary = h.distinct_operators.len() + h.distinct_operands.len();
    if vocabulary == 0 {
        return 0.0;
    }
    (h.operators + h.operands) as f64 * (vocabulary as f64).log2()
}

// ── Maintainability Index (SEI formula, Radon's normalisation) ───────────────

/// Logical lines the way `radon raw` counts them: one per statement, plus
/// one for each header line that is not itself a statement — decorators,
/// `else:`, `except ...:`, `finally:` and `case ...:`.
fn logical_lines(body: &[Stmt]) -> usize {
    let mut count = 0usize;
    let mut tally = |node: Node<'_>| {
        let Node::Stmt(stmt) = node else {
            return;
        };
        count += 1;
        match stmt {
            Stmt::FunctionDef(f) => count += f.decorator_list.len(),
            Stmt::AsyncFunctionDef(f) => count += f.decorator_list.len(),
            Stmt::ClassDef(c) => count += c.decorator_list.len(),
            Stmt::If(i) => {
                if !i.orelse.is_empty() && !matches!(i.orelse.as_slice(), [Stmt::If(_)]) {
                    count += 1;
                }
            }
            Stmt::For(f) => count += usize::from(!f.orelse.is_empty()),
            Stmt::AsyncFor(f) => count += usize::from(!f.orelse.is_empty()),
            Stmt::While(w) => count += usize::from(!w.orelse.is_empty()),
            Stmt::Try(t) => {
                count += t.handlers.len()
                    + usize::from(!t.orelse.is_empty())
                    + usize::from(!t.finalbody.is_empty());
            }
            Stmt::TryStar(t) => {
                count += t.handlers.len()
                    + usize::from(!t.orelse.is_empty())
                    + usize::from(!t.finalbody.is_empty());
            }
            Stmt::Match(m) => count += m.cases.len(),
            _ => {}
        }
    };
    for stmt in body {
        tally(Node::Stmt(stmt));
        for_each_descendant(Node::Stmt(stmt), &mut tally);
    }
    count
}

/// Lines carrying a `#` comment token, as `tokenize` reports them. A lexer
/// error ends the scan with what was collected so far, like Python's
/// `except tokenize.TokenError: pass`.
fn comment_lines(source: &str, index: &LineIndex) -> HashSet<usize> {
    let mut lines = HashSet::new();
    for item in rustpython_parser::lexer::lex(source, rustpython_parser::Mode::Module) {
        match item {
            Ok((rustpython_parser::Tok::Comment(_), range)) => {
                lines.insert(index.line_number(range.start()));
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    lines
}

/// `(lloc, sloc, comment_percent)` with Radon's conventions: sloc = physical
/// lines that are neither blank, comment-only nor part of a standalone
/// string statement; comment_percent = (lines carrying a `#` comment +
/// non-blank lines of multi-line standalone strings) / sloc * 100.
fn line_stats(source: &str, body: &[Stmt]) -> (usize, usize, f64) {
    let index = LineIndex::new(source);
    let lines = py_splitlines(source);
    let mut string_stmt_lines: HashSet<usize> = HashSet::new();
    let mut multi_lines: HashSet<usize> = HashSet::new();
    let mut note_string_stmt = |node: Node<'_>| {
        let Node::Stmt(Stmt::Expr(e)) = node else {
            return;
        };
        if !matches!(e.value.as_ref(), Expr::Constant(c) if matches!(c.value, Constant::Str(_))) {
            return;
        }
        let loc = index.node_loc(e.range());
        for n in loc.line..=loc.end_line {
            string_stmt_lines.insert(n);
            if loc.end_line > loc.line
                && lines
                    .get(n - 1)
                    .is_some_and(|text| !py_strip(text).is_empty())
            {
                multi_lines.insert(n);
            }
        }
    };
    for stmt in body {
        note_string_stmt(Node::Stmt(stmt));
        for_each_descendant(Node::Stmt(stmt), &mut note_string_stmt);
    }
    let sloc = lines
        .iter()
        .enumerate()
        .filter(|(i, text)| {
            let stripped = py_strip(text);
            !stripped.is_empty()
                && !string_stmt_lines.contains(&(i + 1))
                && !stripped.starts_with('#')
        })
        .count();
    let comments = comment_lines(source, &index).len() + multi_lines.len();
    let percent = if sloc > 0 {
        comments as f64 / sloc as f64 * 100.0
    } else {
        0.0
    };
    (logical_lines(body), sloc, percent)
}

/// 0-100, higher is more maintainable. `radon mi` ranks: A >= 20, B 10-19,
/// C < 10. Returns 100 for an empty module.
pub fn maintainability_index(body: &[Stmt], source: &str) -> f64 {
    let volume = halstead_volume(body);
    let complexity = module_cyclomatic_total(body);
    let (lloc, _sloc, comment_percent) = line_stats(source, body);
    if volume <= 0.0 || lloc == 0 {
        return 100.0; // Radon's convention for a module with no operators
    }
    let raw = 171.0 - 5.2 * volume.ln() - 0.23 * complexity as f64 - 16.2 * (lloc as f64).ln()
        + 50.0 * (2.46 * comment_percent.to_radians()).sqrt().sin();
    (raw * 100.0 / 171.0).clamp(0.0, 100.0)
}

#[cfg(test)]
mod tests {
    //! Mirrors tests/test_metrics.py.
    use super::*;
    use rustpython_ast::Mod;

    fn parse(source: &str) -> Mod {
        rustpython_parser::parse(source, rustpython_parser::Mode::Module, "f.py")
            .expect("test source must parse")
    }

    fn body(module: &Mod) -> &[Stmt] {
        match module {
            Mod::Module(m) => &m.body,
            _ => unreachable!(),
        }
    }

    fn func_cc(source: &str) -> i64 {
        let module = parse(source);
        for stmt in body(&module) {
            match stmt {
                Stmt::FunctionDef(f) => return cyclomatic_complexity(&f.body),
                Stmt::AsyncFunctionDef(f) => return cyclomatic_complexity(&f.body),
                _ => {}
            }
        }
        panic!("no function in test source");
    }

    fn func_cognitive(source: &str) -> i64 {
        let module = parse(source);
        for stmt in body(&module) {
            match stmt {
                Stmt::FunctionDef(f) => return cognitive_complexity(f.name.as_str(), &f.body),
                Stmt::AsyncFunctionDef(f) => {
                    return cognitive_complexity(f.name.as_str(), &f.body);
                }
                _ => {}
            }
        }
        panic!("no function in test source");
    }

    #[test]
    fn cyclomatic_complexity_matches_radon() {
        // Every case cross-checked against radon 6.0.1 in the Python repo.
        let cases: &[(&str, i64)] = &[
            ("def f():\n    return 1\n", 1),
            (
                "def f(x):\n    if x:\n        return 1\n    elif x > 2:\n        return 2\n    return 3\n",
                3,
            ),
            ("def f(x):\n    return 1 if x else 2\n", 2),
            (
                "def f(xs):\n    for x in xs:\n        pass\n    else:\n        pass\n",
                3,
            ),
            ("def f(xs):\n    while xs:\n        xs.pop()\n", 2),
            (
                "def f():\n    try:\n        pass\n    except A:\n        pass\n    except B:\n        pass\n    else:\n        pass\n    finally:\n        pass\n",
                4,
            ),
            ("def f(a, b, c):\n    return a and b or c\n", 3),
            ("def f(xs):\n    return [x for x in xs if x if x > 1]\n", 4),
            (
                "def f(xs, ys):\n    return {x: y for x in xs for y in ys}\n",
                3,
            ),
            ("def f(x):\n    assert x and x > 1\n", 2), // radon stops at the assert
            ("def f(x):\n    with x:\n        pass\n", 1),
            ("def f(x):\n    return (lambda y: y if y else 0)(x)\n", 2),
            (
                "def f(x):\n    match x:\n        case 1:\n            pass\n        case 2:\n            pass\n        case _:\n            pass\n",
                3,
            ),
            (
                "def f(x):\n    match x:\n        case [a]:\n            pass\n        case other:\n            pass\n",
                2,
            ),
            (
                "def f(x):\n    def g():\n        if x:\n            return 1\n    class C:\n        def m(self):\n            if x:\n                pass\n    return g\n",
                1,
            ),
        ];
        for (source, expected) in cases {
            assert_eq!(func_cc(source), *expected, "{source}");
        }
    }

    #[test]
    fn module_cyclomatic_total_counts_methods_like_radon() {
        let module = parse(
            "if X:\n    pass\ndef f(a):\n    return 1 if a else 2\nclass C:\n    def m(self):\n        pass\n    def n(self):\n        if self:\n            pass\n",
        );
        // 1 + If(1) + f(1) + C: methods m (1+0) + n (1+1)
        assert_eq!(module_cyclomatic_total(body(&module)), 1 + 1 + 1 + 1 + 2);
    }

    #[test]
    fn cognitive_simple_if_chain_is_flat() {
        assert_eq!(
            func_cognitive(
                "def f(a):\n    if a:\n        return 1\n    elif a > 2:\n        return 2\n    else:\n        return 3\n"
            ),
            3
        );
    }

    #[test]
    fn cognitive_nesting_penalises_each_level() {
        let source = "def f(xs):\n    for x in xs:\n        if x:\n            while x:\n                x -= 1\n";
        assert_eq!(func_cognitive(source), 6);
    }

    #[test]
    fn cognitive_boolean_sequences_count_once_per_operator_run() {
        assert_eq!(
            func_cognitive("def f(a, b, c, d):\n    return a and b and c\n"),
            1
        );
        assert_eq!(
            func_cognitive("def f(a, b, c, d):\n    return a and b or c and d\n"),
            3
        );
    }

    #[test]
    fn cognitive_ternary_except_and_recursion() {
        let source = "def f(n):\n    try:\n        x = 1 if n else 2\n    except ValueError:\n        return f(n - 1)\n    return x\n";
        assert_eq!(func_cognitive(source), 3);
    }

    #[test]
    fn cognitive_nested_function_adds_nesting_not_increment() {
        let source = "def f(xs):\n    def g(x):\n        if x:\n            return 1\n    return [g(x) for x in xs]\n";
        assert_eq!(func_cognitive(source), 2);
    }

    #[test]
    fn cognitive_match_and_loop_else() {
        let source = "def f(x, xs):\n    match x:\n        case 1:\n            if xs:\n                pass\n    for y in xs:\n        pass\n    else:\n        pass\n";
        assert_eq!(func_cognitive(source), 5);
    }

    #[test]
    fn halstead_volume_counts_operators_and_operands_like_radon() {
        let module = parse("def f(a, b):\n    return a + b * 2\n");
        // operators: Add, Mult (2 distinct, 2 total); operands: a, (b*2 expr), b, 2 -> 4 distinct, 4 total
        let expected = 6.0 * 6f64.log2();
        assert!((halstead_volume(body(&module)) - expected).abs() < 1e-9);
    }

    #[test]
    fn halstead_ignores_annotations_and_defaults() {
        let module = parse("def f(a: int | str = 1 + 2) -> int:\n    return a\n");
        assert_eq!(halstead_volume(body(&module)), 0.0);
    }

    #[test]
    fn halstead_folds_python_equal_constants() {
        // 1, 1.0 and True are one operand in Python's set; "1" and b"1" are not.
        let module = parse("x = 1 + 1.0 + True + '1' + b'1'\n");
        // 4 Add operators (1 distinct), 8 operands: 1/1.0/True fold, "1", b"1",
        // and the three nested BinOp expressions are each distinct.
        let expected = 12.0 * 7f64.log2();
        assert!((halstead_volume(body(&module)) - expected).abs() < 1e-9);
    }

    #[test]
    fn maintainability_index_bounds_and_ranking() {
        assert_eq!(maintainability_index(body(&parse("")), ""), 100.0);
        let trivial = "def f(a, b):\n    return a + b\n";
        let mi = maintainability_index(body(&parse(trivial)), trivial);
        assert!(60.0 < mi && mi <= 100.0, "{mi}");
        let dense: String = (0..120)
            .map(|i| {
                format!(
                    "def f{i}(a, b, c):\n    if a and b or c:\n        return a + b * c - {i}\n    return a - b / c % {i}"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(maintainability_index(body(&parse(&dense)), &dense) < 10.0);
    }

    #[test]
    fn line_stats_follow_radon_raw() {
        let source = "\"\"\"Doc\n\nstring.\"\"\"\n# comment\nx = 1  # trailing\n\ny = 2\n";
        let module = parse(source);
        let (lloc, sloc, percent) = line_stats(source, body(&module));
        // statements: docstring Expr, x, y
        assert_eq!(lloc, 3);
        // physical lines minus the docstring's 3, the comment line and the blank
        assert_eq!(sloc, 2);
        // comments: two `#` lines + two non-blank docstring lines
        assert!((percent - 200.0).abs() < 1e-9);
    }

    #[test]
    fn splitlines_matches_python() {
        assert_eq!(
            py_splitlines("a\nb\r\nc\rd\x0ce"),
            ["a", "b", "c", "d", "e"]
        );
        assert_eq!(py_splitlines("a\n"), ["a"]);
        assert_eq!(py_splitlines(""), Vec::<&str>::new());
    }
}
