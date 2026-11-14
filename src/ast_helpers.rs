//! AST utility functions — mirrors `ast_helpers.py`.
//!
//! rustpython-ast tracks byte offsets (`TextSize`/`TextRange`) rather than
//! Python's native (lineno, end_lineno), so a `LineIndex` bridges the two:
//! it's the equivalent of what Python's `ast` module gives you for free.

use crate::pyast::Node;
use rustpython_ast::text_size::{TextRange, TextSize};
use rustpython_ast::{Arguments, Expr, Ranged, Stmt};
use std::collections::VecDeque;
use std::sync::LazyLock;

pub struct LineIndex {
    /// Byte offset each line starts at; `line_starts[0] == 0`.
    line_starts: Vec<u32>,
}

impl LineIndex {
    pub fn new(source: &str) -> Self {
        let mut line_starts = vec![0u32];
        for (i, b) in source.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push((i + 1) as u32);
            }
        }
        LineIndex { line_starts }
    }

    /// 1-indexed line number containing byte offset `offset`.
    pub fn line_number(&self, offset: TextSize) -> usize {
        let offset: u32 = offset.into();
        match self.line_starts.binary_search(&offset) {
            Ok(i) => i + 1,
            Err(i) => i, // i-1 in 0-indexed terms == i in 1-indexed terms
        }
    }
}

/// A node's span in Python `ast` terms — mirrors `ast_helpers.py::_loc`
/// (plus `lineno`). Columns are 1-based *byte* columns at this point, exactly
/// like `col_offset + 1`/`end_col_offset + 1`; `scanner::scan_package`
/// rewrites them to character columns once the source lines are at hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeLoc {
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

impl LineIndex {
    /// 1-based byte column of `offset` within its line (`col_offset + 1`).
    pub fn column(&self, offset: TextSize) -> usize {
        let offset: u32 = offset.into();
        let line_start = self.line_starts[self.line_number(offset.into()) - 1];
        (offset - line_start) as usize + 1
    }

    pub fn node_loc(&self, range: TextRange) -> NodeLoc {
        NodeLoc {
            line: self.line_number(range.start()),
            column: self.column(range.start()),
            end_line: self.line_number(range.end()),
            end_column: self.column(range.end()),
        }
    }
}

/// `end_line - start_line + 1` — mirrors `ast_helpers.py::_line_count`.
pub fn line_count(index: &LineIndex, start: TextSize, end: TextSize) -> usize {
    let start_line = index.line_number(start);
    let end_line = index.line_number(end);
    end_line - start_line + 1
}

// ── Canonical structural dump (position-independent) ────────────────────────
//
// Mirrors `ast_helpers.py::_dump_stmts`, which leans on `ast.dump(s,
// annotate_fields=False)` — a structural serialization that includes every
// field (so two blocks differing only by identifier name are correctly
// "different") while omitting `lineno`/`col_offset` (so two blocks that are
// textually identical but positioned differently are correctly "the same").
//
// rustpython's AST types don't have an equivalent built-in — their `Debug`
// impl is the closest thing (it does recursively include every field,
// including identifiers/constants/operators), but it also embeds each
// node's `range: N..M` byte span, which would make two structurally
// identical blocks at different source positions compare as different.
// Stripping the `range: N..M` fragments out of the `Debug` string first,
// rather than hand-writing a field-by-field visitor across ~30 `Stmt` and
// ~50 `Expr` variants, gets the same "structural but position-independent"
// property for a fraction of the code — verified directly: two blocks with
// different identifiers correctly compare unequal, and two textually
// identical blocks at different offsets correctly compare equal, after
// stripping.
static RANGE_FIELD_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"range: \d+\.\.\d+,?\s*").unwrap());

pub fn dump_stmts(stmts: &[Stmt]) -> String {
    let raw = format!("{stmts:?}");
    RANGE_FIELD_RE.replace_all(&raw, "").into_owned()
}

// ── Function collection ──────────────────────────────────────────────────────
//
// Nearly every per-function rule starts the same way Python's does:
// `for node in ast.walk(tree): if isinstance(node, (FunctionDef,
// AsyncFunctionDef))`. One shared collection pass (found at every nesting
// level, matching `ast.walk`) avoids each check re-implementing its own
// tree walk.

/// A FunctionDef or AsyncFunctionDef, wrapped uniformly — mirrors how Python
/// code treats `(ast.FunctionDef, ast.AsyncFunctionDef)` as one tuple type.
pub struct FuncNode {
    pub stmt: Stmt,
    pub name: String,
    pub start: TextSize,
}

impl FuncNode {
    pub fn args(&self) -> &Arguments {
        match &self.stmt {
            Stmt::FunctionDef(n) => &n.args,
            Stmt::AsyncFunctionDef(n) => &n.args,
            _ => unreachable!("FuncNode only ever wraps FunctionDef/AsyncFunctionDef"),
        }
    }

    pub fn returns(&self) -> Option<&Expr> {
        match &self.stmt {
            Stmt::FunctionDef(n) => n.returns.as_deref(),
            Stmt::AsyncFunctionDef(n) => n.returns.as_deref(),
            _ => unreachable!("FuncNode only ever wraps FunctionDef/AsyncFunctionDef"),
        }
    }

    pub fn body(&self) -> &[Stmt] {
        match &self.stmt {
            Stmt::FunctionDef(n) => &n.body,
            Stmt::AsyncFunctionDef(n) => &n.body,
            _ => unreachable!("FuncNode only ever wraps FunctionDef/AsyncFunctionDef"),
        }
    }

    pub fn end(&self) -> TextSize {
        match &self.stmt {
            Stmt::FunctionDef(n) => n.range().end(),
            Stmt::AsyncFunctionDef(n) => n.range().end(),
            _ => unreachable!("FuncNode only ever wraps FunctionDef/AsyncFunctionDef"),
        }
    }

    pub fn range(&self) -> TextRange {
        TextRange::new(self.start, self.end())
    }
}

/// The nodes that can sit between a module and a `def` on the way down:
/// statements, plus the `ExceptHandler`/`match_case` wrappers that
/// `ast.walk` treats as nodes of their own (and so as an extra level).
enum StmtContainer<'a> {
    Stmt(&'a Stmt),
    Handler(&'a rustpython_ast::ExceptHandler),
    Case(&'a rustpython_ast::MatchCase),
}

impl<'a> StmtContainer<'a> {
    /// This node's statement-bearing children, in `ast.iter_child_nodes`
    /// field order. Expression children are skipped: no `def` can hide in
    /// one (a `lambda` is not a `FunctionDef`), so leaving them out doesn't
    /// change the relative order of the functions a BFS discovers.
    fn children(&self, out: &mut VecDeque<StmtContainer<'a>>) {
        fn stmts<'a>(out: &mut VecDeque<StmtContainer<'a>>, body: &'a [Stmt]) {
            out.extend(body.iter().map(StmtContainer::Stmt));
        }
        match self {
            StmtContainer::Stmt(stmt) => match stmt {
                Stmt::FunctionDef(n) => stmts(out, &n.body),
                Stmt::AsyncFunctionDef(n) => stmts(out, &n.body),
                Stmt::ClassDef(n) => stmts(out, &n.body),
                Stmt::For(n) => {
                    stmts(out, &n.body);
                    stmts(out, &n.orelse);
                }
                Stmt::AsyncFor(n) => {
                    stmts(out, &n.body);
                    stmts(out, &n.orelse);
                }
                Stmt::While(n) => {
                    stmts(out, &n.body);
                    stmts(out, &n.orelse);
                }
                Stmt::If(n) => {
                    stmts(out, &n.body);
                    stmts(out, &n.orelse);
                }
                Stmt::With(n) => stmts(out, &n.body),
                Stmt::AsyncWith(n) => stmts(out, &n.body),
                Stmt::Match(n) => out.extend(n.cases.iter().map(StmtContainer::Case)),
                Stmt::Try(n) => {
                    stmts(out, &n.body);
                    out.extend(n.handlers.iter().map(StmtContainer::Handler));
                    stmts(out, &n.orelse);
                    stmts(out, &n.finalbody);
                }
                Stmt::TryStar(n) => {
                    stmts(out, &n.body);
                    out.extend(n.handlers.iter().map(StmtContainer::Handler));
                    stmts(out, &n.orelse);
                    stmts(out, &n.finalbody);
                }
                _ => {}
            },
            StmtContainer::Handler(rustpython_ast::ExceptHandler::ExceptHandler(h)) => {
                stmts(out, &h.body)
            }
            StmtContainer::Case(c) => stmts(out, &c.body),
        }
    }
}

/// Every FunctionDef/AsyncFunctionDef in `module_body`, at any nesting level,
/// in the order `for node in ast.walk(tree): if isinstance(node, (FunctionDef,
/// AsyncFunctionDef))` yields them. `ast.walk` is breadth-first, so every
/// module-level function comes before any method or nested function, and
/// those in turn before anything nested one level deeper — this is the
/// order the per-function rules report their findings in, so it has to
/// match rather than being a depth-first visitor's.
pub fn collect_functions(module_body: &[Stmt]) -> Vec<FuncNode> {
    let mut functions = Vec::new();
    let mut queue: VecDeque<StmtContainer> = module_body.iter().map(StmtContainer::Stmt).collect();
    while let Some(node) = queue.pop_front() {
        if let StmtContainer::Stmt(stmt) = node {
            match stmt {
                Stmt::FunctionDef(n) => functions.push(FuncNode {
                    name: n.name.as_str().to_string(),
                    start: n.range().start(),
                    stmt: stmt.clone(),
                }),
                Stmt::AsyncFunctionDef(n) => functions.push(FuncNode {
                    name: n.name.as_str().to_string(),
                    start: n.range().start(),
                    stmt: stmt.clone(),
                }),
                _ => {}
            }
        }
        node.children(&mut queue);
    }
    functions
}

/// Every FunctionDef/AsyncFunctionDef paired with its nearest enclosing
/// class name (or `None` at module scope), in the pre-order of
/// `_walk_with_class_context` — that helper filtered down to the
/// function/class-name pairs `sync-async-duplication` needs.
pub fn collect_functions_with_class_context(
    module_body: &[Stmt],
) -> Vec<(Option<String>, FuncNode)> {
    let mut functions = Vec::new();
    let mut stack: Vec<(Node<'_>, Option<&str>)> = module_body
        .iter()
        .rev()
        .map(|s| (Node::Stmt(s), None))
        .collect();
    while let Some((node, class_name)) = stack.pop() {
        let mut child_class = class_name;
        match node {
            Node::Stmt(stmt @ Stmt::FunctionDef(f)) => functions.push((
                class_name.map(str::to_string),
                FuncNode {
                    name: f.name.to_string(),
                    start: f.range().start(),
                    stmt: stmt.clone(),
                },
            )),
            Node::Stmt(stmt @ Stmt::AsyncFunctionDef(f)) => functions.push((
                class_name.map(str::to_string),
                FuncNode {
                    name: f.name.to_string(),
                    start: f.range().start(),
                    stmt: stmt.clone(),
                },
            )),
            Node::Stmt(Stmt::ClassDef(c)) => child_class = Some(c.name.as_str()),
            _ => {}
        }
        stack.extend(node.children().into_iter().rev().map(|c| (c, child_class)));
    }
    functions
}

/// Mirrors `ast_helpers.py::_is_trivial_body`: true for stub-like bodies
/// (pass / docstring-only / ellipsis / bare raise) that shouldn't count as
/// meaningful duplication if repeated verbatim across a package.
pub fn is_trivial_body(body: &[Stmt]) -> bool {
    let meaningful: Vec<&Stmt> = body
        .iter()
        .filter(|s| {
            !matches!(
                s,
                Stmt::Expr(e) if matches!(e.value.as_ref(), Expr::Constant(c) if matches!(c.value, rustpython_ast::Constant::Str(_)))
            )
        })
        .collect();
    if meaningful.is_empty() {
        return true;
    }
    if meaningful.len() == 1 {
        return match meaningful[0] {
            Stmt::Pass(_) => true,
            Stmt::Expr(e) => {
                matches!(e.value.as_ref(), Expr::Constant(c) if matches!(c.value, rustpython_ast::Constant::Ellipsis))
            }
            Stmt::Raise(_) => true,
            _ => false,
        };
    }
    false
}

// ── Cyclomatic complexity ────────────────────────────────────────────────────

/// McCabe cyclomatic complexity of a function, as `radon cc` counts it —
/// see `metrics::cyclomatic_complexity`.
pub fn cyclomatic_complexity(func: &FuncNode) -> i64 {
    crate::metrics::cyclomatic_complexity(func.body())
}

// ── Nesting depth ────────────────────────────────────────────────────────────

/// Mirrors `ast_helpers.py::_NESTING_NODES`: the compound statements whose
/// body is indented one level deeper than they are. `match` and each `case`
/// both count, so a case body sits two levels inside the enclosing block.
/// `except`/`else`/`finally` bodies are siblings of the `try` body, and an
/// `elif` is a sibling of its `if`, so neither adds a level — see
/// [`child_depth`].
fn is_nesting_node(node: Node<'_>) -> bool {
    matches!(
        node,
        Node::Stmt(
            Stmt::If(_)
                | Stmt::For(_)
                | Stmt::AsyncFor(_)
                | Stmt::While(_)
                | Stmt::With(_)
                | Stmt::AsyncWith(_)
                | Stmt::Try(_)
                | Stmt::TryStar(_)
                | Stmt::Match(_)
        ) | Node::MatchCase(_)
    )
}

/// Mirrors `ast_helpers.py::_child_depth`: the nesting depth of `child`'s
/// own body given that `parent`'s body is at `current` — one deeper for a
/// compound statement, the same for an `elif` or anything else. An `elif` is
/// the sole `orelse` of its `if` *and* starts in the same column (CPython and
/// rustpython-parser both give the nested `If` the column of the `elif`
/// keyword); `else:` followed by an indented `if` has the same tree shape but
/// sits one column level deeper, which is exactly the level the reader sees.
fn child_depth(parent: Node<'_>, child: Node<'_>, current: usize, index: &LineIndex) -> usize {
    if !is_nesting_node(child) {
        return current;
    }
    if let (Node::Stmt(Stmt::If(p)), Node::Stmt(c @ Stmt::If(ci))) = (parent, child) {
        let is_elif = p.orelse.len() == 1
            && std::ptr::eq(&p.orelse[0], c)
            && index.column(ci.range.start()) == index.column(p.range.start());
        if is_elif {
            return current;
        }
    }
    current + 1
}

/// Mirrors `ast_helpers.py::_nesting_depth` on the function node: the
/// maximum block nesting depth inside it — the number of indentation levels
/// a reader must carry, counting every compound statement once. Walks the
/// CPython-shaped tree (decorators, defaults and nested defs included, the
/// way `ast.iter_child_nodes` reaches them). Iterative, so a pathological
/// file cannot overflow the stack here.
pub fn nesting_depth(func: &FuncNode, index: &LineIndex) -> usize {
    let mut max_depth = 0;
    let mut stack = vec![(Node::Stmt(&func.stmt), 0usize)];
    while let Some((node, current)) = stack.pop() {
        max_depth = max_depth.max(current);
        for child in node.children() {
            stack.push((child, child_depth(node, child, current, index)));
        }
    }
    max_depth
}

/// Mirrors `ast_helpers.py::_count_nested_returns`: `Return` statements at
/// nesting depth >= 2 (the same [`child_depth`] as [`nesting_depth`]), not
/// descending into nested defs or lambdas.
pub fn count_nested_returns(func: &FuncNode, index: &LineIndex) -> i64 {
    let mut count = 0;
    let mut stack = vec![(Node::Stmt(&func.stmt), 0usize)];
    while let Some((node, current)) = stack.pop() {
        for child in node.children() {
            if matches!(
                child,
                Node::Stmt(Stmt::FunctionDef(_) | Stmt::AsyncFunctionDef(_))
                    | Node::Expr(Expr::Lambda(_))
            ) {
                continue;
            }
            if matches!(child, Node::Stmt(Stmt::Return(_))) && current >= 2 {
                count += 1;
            }
            stack.push((child, child_depth(node, child, current, index)));
        }
    }
    count
}

// ── Misc predicates ──────────────────────────────────────────────────────────

/// Mirrors `ast_helpers.py::_is_private`.
pub fn is_private(name: &str) -> bool {
    name.starts_with('_')
}

/// Mirrors `ast_helpers.py::_is_test_function`. True for a pytest test
/// function's own name (`test_*`), not a test *file*'s helper functions —
/// `create_consented_subject` in a test file should still be checked, only
/// the bare `test_*` functions and their fixture-injected parameters are
/// pytest-convention boilerplate.
pub fn is_test_function(name: &str) -> bool {
    name.starts_with("test_")
}

/// Mirrors `ast_helpers.py::_is_test_file`. True for a pytest test module:
/// `test_*.py`/`*_test.py`, `conftest.py`, or anything under a directory
/// literally named `tests`.
pub fn is_test_file(filepath: &std::path::Path) -> bool {
    let name = filepath.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name == "conftest.py" || name.starts_with("test_") || name.ends_with("_test.py") {
        return true;
    }
    filepath
        .parent()
        .is_some_and(|parent| parent.components().any(|c| c.as_os_str() == "tests"))
}

// ── `ast.walk` over statements ───────────────────────────────────────────────

/// A node on the breadth-first frontier of `ast.walk`. Expressions never
/// contain statements, so walking statement-level nodes alone reproduces
/// the relative order `ast.walk(tree)` yields them in; `ExceptHandler` and
/// `match_case` are AST nodes of their own in Python, so they add a level
/// of depth and must be queued as such for that order to match exactly.
pub enum WalkNode<'a> {
    Stmt(&'a Stmt),
    Handler(&'a rustpython_ast::ExceptHandler),
    Case(&'a rustpython_ast::MatchCase),
}

/// Every `ClassDef` in the module in `ast.walk` (breadth-first) order.
pub fn collect_classes_bfs(module_body: &[Stmt]) -> Vec<&rustpython_ast::StmtClassDef> {
    walk_stmts_bfs(module_body)
        .into_iter()
        .filter_map(|node| match node {
            WalkNode::Stmt(Stmt::ClassDef(c)) => Some(c),
            _ => None,
        })
        .collect()
}

/// Every `ExceptHandler` in the module in `ast.walk` (breadth-first) order.
pub fn collect_except_handlers_bfs(
    module_body: &[Stmt],
) -> Vec<&rustpython_ast::ExceptHandlerExceptHandler> {
    walk_stmts_bfs(module_body)
        .into_iter()
        .filter_map(|node| match node {
            WalkNode::Handler(rustpython_ast::ExceptHandler::ExceptHandler(h)) => Some(h),
            _ => None,
        })
        .collect()
}

/// Every statement-level node under `module_body` in `ast.walk` order.
pub fn walk_stmts_bfs(module_body: &[Stmt]) -> Vec<WalkNode<'_>> {
    let mut queue: VecDeque<WalkNode<'_>> = module_body.iter().map(WalkNode::Stmt).collect();
    let mut visited = Vec::new();
    while let Some(node) = queue.pop_front() {
        let stmt = match node {
            WalkNode::Stmt(stmt) => stmt,
            WalkNode::Handler(rustpython_ast::ExceptHandler::ExceptHandler(h)) => {
                queue.extend(h.body.iter().map(WalkNode::Stmt));
                visited.push(node);
                continue;
            }
            WalkNode::Case(case) => {
                queue.extend(case.body.iter().map(WalkNode::Stmt));
                visited.push(node);
                continue;
            }
        };
        visited.push(WalkNode::Stmt(stmt));
        // Children in `_fields` order, as `ast.iter_child_nodes` yields them.
        match stmt {
            Stmt::ClassDef(c) => queue.extend(c.body.iter().map(WalkNode::Stmt)),
            Stmt::FunctionDef(f) => queue.extend(f.body.iter().map(WalkNode::Stmt)),
            Stmt::AsyncFunctionDef(f) => queue.extend(f.body.iter().map(WalkNode::Stmt)),
            Stmt::For(f) => {
                queue.extend(f.body.iter().map(WalkNode::Stmt));
                queue.extend(f.orelse.iter().map(WalkNode::Stmt));
            }
            Stmt::AsyncFor(f) => {
                queue.extend(f.body.iter().map(WalkNode::Stmt));
                queue.extend(f.orelse.iter().map(WalkNode::Stmt));
            }
            Stmt::While(w) => {
                queue.extend(w.body.iter().map(WalkNode::Stmt));
                queue.extend(w.orelse.iter().map(WalkNode::Stmt));
            }
            Stmt::If(i) => {
                queue.extend(i.body.iter().map(WalkNode::Stmt));
                queue.extend(i.orelse.iter().map(WalkNode::Stmt));
            }
            Stmt::With(w) => queue.extend(w.body.iter().map(WalkNode::Stmt)),
            Stmt::AsyncWith(w) => queue.extend(w.body.iter().map(WalkNode::Stmt)),
            Stmt::Match(m) => queue.extend(m.cases.iter().map(WalkNode::Case)),
            Stmt::Try(t) => {
                queue.extend(t.body.iter().map(WalkNode::Stmt));
                queue.extend(t.handlers.iter().map(WalkNode::Handler));
                queue.extend(t.orelse.iter().map(WalkNode::Stmt));
                queue.extend(t.finalbody.iter().map(WalkNode::Stmt));
            }
            Stmt::TryStar(t) => {
                queue.extend(t.body.iter().map(WalkNode::Stmt));
                queue.extend(t.handlers.iter().map(WalkNode::Handler));
                queue.extend(t.orelse.iter().map(WalkNode::Stmt));
                queue.extend(t.finalbody.iter().map(WalkNode::Stmt));
            }
            _ => {}
        }
    }
    visited
}

#[cfg(test)]
mod nesting_tests {
    use super::{LineIndex, collect_functions, count_nested_returns, nesting_depth};
    use rustpython_ast::Mod;

    fn first_func_metric(
        source: &str,
        metric: impl Fn(&super::FuncNode, &LineIndex) -> usize,
    ) -> usize {
        let module = rustpython_parser::parse(source, rustpython_parser::Mode::Module, "f.py")
            .expect("test source must parse");
        let Mod::Module(m) = &module else {
            unreachable!("Mode::Module parses to Mod::Module")
        };
        let funcs = collect_functions(&m.body);
        metric(&funcs[0], &LineIndex::new(source))
    }

    fn depth(body: &str) -> usize {
        first_func_metric(&format!("async def f(x):\n{body}"), nesting_depth)
    }

    /// Mirrors `test_nesting_depth_follows_indentation`.
    #[test]
    fn nesting_depth_follows_indentation() {
        // Every compound statement adds one level, including the async forms,
        // try*, match and case.
        assert_eq!(depth("    if x:\n        pass\n"), 1);
        assert_eq!(
            depth("    async for a in x:\n        async with a:\n            pass\n"),
            2
        );
        assert_eq!(
            depth("    try:\n        pass\n    except* ValueError:\n        pass\n"),
            1
        );
        assert_eq!(
            depth("    match x:\n        case 1:\n            if x:\n                pass\n"),
            3
        );
        // Siblings of a block add nothing: elif chains, except/else/finally bodies.
        assert_eq!(
            depth(
                "    if x:\n        pass\n    elif x:\n        pass\n    elif x:\n        pass\n"
            ),
            1
        );
        assert_eq!(
            depth("    if x:\n        pass\n    else:\n        if x:\n            pass\n"),
            2
        );
        assert_eq!(
            depth(
                "    try:\n        pass\n    except ValueError:\n        if x:\n            pass\n"
            ),
            2
        );
        assert_eq!(
            depth("    try:\n        pass\n    finally:\n        if x:\n            pass\n"),
            2
        );
        // Nested returns use the same depth: an except body is at the try's level.
        let returns = first_func_metric(
            "def f(x):\n    for a in x:\n        try:\n            return 1\n\
             \x20       except ValueError:\n            return 2\n        else:\n            return 3\n",
            |f, i| usize::try_from(count_nested_returns(f, i)).unwrap(),
        );
        assert_eq!(returns, 3);
    }
}
