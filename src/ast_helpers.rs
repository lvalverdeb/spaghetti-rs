//! AST utility functions — mirrors `ast_helpers.py`.
//!
//! rustpython-ast tracks byte offsets (`TextSize`/`TextRange`) rather than
//! Python's native (lineno, end_lineno), so a `LineIndex` bridges the two:
//! it's the equivalent of what Python's `ast` module gives you for free.

use rustpython_ast::text_size::{TextRange, TextSize};
use rustpython_ast::{
    Arguments, ExceptHandlerExceptHandler, Expr, Ranged, Stmt, StmtAsyncFor, StmtAsyncFunctionDef,
    StmtFor, StmtFunctionDef, StmtIf, StmtTry, StmtWhile, StmtWith, Visitor,
};
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

struct FunctionWithClassContextCollector {
    functions: Vec<(Option<String>, FuncNode)>,
    class_stack: Vec<String>,
}
impl Visitor for FunctionWithClassContextCollector {
    fn visit_stmt_class_def(&mut self, node: rustpython_ast::StmtClassDef) {
        self.class_stack.push(node.name.to_string());
        self.generic_visit_stmt_class_def(node);
        self.class_stack.pop();
    }
    fn visit_stmt_function_def(&mut self, node: StmtFunctionDef) {
        self.functions.push((
            self.class_stack.last().cloned(),
            FuncNode {
                name: node.name.as_str().to_string(),
                start: node.range().start(),
                stmt: Stmt::FunctionDef(node.clone()),
            },
        ));
        self.generic_visit_stmt_function_def(node);
    }
    fn visit_stmt_async_function_def(&mut self, node: StmtAsyncFunctionDef) {
        self.functions.push((
            self.class_stack.last().cloned(),
            FuncNode {
                name: node.name.as_str().to_string(),
                start: node.range().start(),
                stmt: Stmt::AsyncFunctionDef(node.clone()),
            },
        ));
        self.generic_visit_stmt_async_function_def(node);
    }
}

/// Every FunctionDef/AsyncFunctionDef paired with its nearest enclosing
/// class name (or `None` at module scope) — mirrors
/// `_walk_with_class_context` filtered down to just the function/class-name
/// pairs `sync-async-duplication` actually needs (that helper's general
/// "yield every node with context" shape isn't needed elsewhere yet, so
/// this collector is purpose-built rather than fully generic).
pub fn collect_functions_with_class_context(
    module_body: &[Stmt],
) -> Vec<(Option<String>, FuncNode)> {
    let mut visitor = FunctionWithClassContextCollector {
        functions: Vec::new(),
        class_stack: Vec::new(),
    };
    for stmt in module_body {
        visitor.visit_stmt(stmt.clone());
    }
    visitor.functions
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

// ── rustpython-ast Visitor gap: comprehensions are never descended into ─────
//
// `rustpython_ast::Visitor`'s generated `generic_visit_comprehension` is a
// no-op stub (confirmed by reading `gen/visitor.rs` directly — it doesn't
// walk `target`/`iter`/`ifs` at all, unlike every other `generic_visit_*`
// method, which does visit all of its node's fields). Found via a real
// conformance mismatch against this workspace's own code: two functions
// where Python's `high-complexity` fired but the Rust port didn't, both
// containing a comprehension with a multi-value `and` (`BoolOp`) inside its
// `if` filter — invisible to any visitor relying on the crate's default
// traversal. Any visitor here that needs true `ast.walk()`-equivalent
// coverage (i.e. anything that must see every expression in a function,
// not just statement-level constructs) MUST override `visit_comprehension`
// and call this helper — the crate's own default silently won't do it.
pub fn walk_comprehension_children<V: Visitor + ?Sized>(
    visitor: &mut V,
    node: rustpython_ast::Comprehension,
) {
    visitor.visit_expr(node.target);
    visitor.visit_expr(node.iter);
    for if_expr in node.ifs {
        visitor.visit_expr(if_expr);
    }
}

// ── Same gap, bigger scope: `Arguments`/`Arg` are never descended into ──────
//
// `generic_visit_arguments` and `generic_visit_arg` are *also* no-op stubs
// (as are `generic_visit_keyword`/`generic_visit_alias`/
// `generic_visit_withitem`/`generic_visit_match_case` — every "support"
// struct in this crate version, not just `Comprehension`). Confirmed by a
// second real gap: `def f(x=[i for i in range(10) if i > 5 and i < 8]):`
// — Python's checks see the magic numbers and the `and` inside that default
// value; the Rust port, before this fix, saw none of it, because
// `generic_visit_stmt_function_def`'s call to `visit_arguments` silently
// goes nowhere by default. Any visitor needing full `ast.walk()`-equivalent
// coverage must override `visit_arguments` and call this helper too.
pub fn walk_arguments_children<V: Visitor + ?Sized>(visitor: &mut V, node: Arguments) {
    for arg in node
        .posonlyargs
        .into_iter()
        .chain(node.args)
        .chain(node.kwonlyargs)
    {
        if let Some(annotation) = arg.def.annotation {
            visitor.visit_expr(*annotation);
        }
        if let Some(default) = arg.default {
            visitor.visit_expr(*default);
        }
    }
    if let Some(vararg) = node.vararg
        && let Some(annotation) = vararg.annotation
    {
        visitor.visit_expr(*annotation);
    }
    if let Some(kwarg) = node.kwarg
        && let Some(annotation) = kwarg.annotation
    {
        visitor.visit_expr(*annotation);
    }
}

// ── Same gap, third instance: `Keyword` (call keyword-arguments) ───────────
//
// Found via a real conformance mismatch: `warnings.warn(msg, RuntimeWarning,
// stacklevel=3)` (`boti/src/boti/core/logger.py:217`) — Python's
// `magic-number` sees the `3` in `stacklevel=3`; the Rust port didn't,
// because `generic_visit_expr_call` calls `self.visit_keyword(kw)` for each
// keyword argument, but `visit_keyword`'s default `generic_visit_keyword` is
// — like `Comprehension`/`Arguments` above — a no-op stub that never visits
// `.value`. Same root cause also explained a `unused-import` false positive
// (`started=perf_counter()` as a keyword argument was invisible to the
// usage scan). Any visitor needing full traversal must override
// `visit_keyword` and call this helper.
pub fn walk_keyword_children<V: Visitor + ?Sized>(visitor: &mut V, node: rustpython_ast::Keyword) {
    visitor.visit_expr(node.value);
}

// ── Same gap, fourth instance: `WithItem` (`with expr as x:`) ──────────────
//
// Not yet hit by a real conformance mismatch (found by inspection, applying
// the same lesson pre-emptively rather than waiting to trip over it): only
// `with` statement bodies are visited by default
// (`generic_visit_stmt_with`/`generic_visit_stmt_async_with` call
// `self.visit_withitem(item)`, but `visit_withitem`'s default is — same
// pattern again — a no-op). A magic number or Name usage inside a `with`
// statement's own context-manager expression (e.g. `with
// open(path, encoding="utf-8") as f:`) would be invisible without this.
/// `generic_visit_match_case` is a no-op in rustpython-ast 0.4, so a `match`
/// arm's guard and body are invisible to every visitor unless walked by
/// hand — `ast.walk` descends into them like any other statement list.
pub fn walk_match_case_children<V: Visitor + ?Sized>(
    visitor: &mut V,
    node: rustpython_ast::MatchCase,
) {
    visitor.visit_pattern(node.pattern);
    if let Some(guard) = node.guard {
        visitor.visit_expr(*guard);
    }
    for stmt in node.body {
        visitor.visit_stmt(stmt);
    }
}

pub fn walk_withitem_children<V: Visitor + ?Sized>(
    visitor: &mut V,
    node: rustpython_ast::WithItem,
) {
    visitor.visit_expr(node.context_expr);
    if let Some(vars) = node.optional_vars {
        visitor.visit_expr(*vars);
    }
}

// ── Cyclomatic complexity ────────────────────────────────────────────────────

/// McCabe cyclomatic complexity of a function, as `radon cc` counts it —
/// see `metrics::cyclomatic_complexity`.
pub fn cyclomatic_complexity(func: &FuncNode) -> i64 {
    crate::metrics::cyclomatic_complexity(func.body())
}

// ── Nesting depth ────────────────────────────────────────────────────────────
//
// Mirrors `ast_helpers.py::_nesting_depth`: also doesn't stop at nested def
// boundaries, same reasoning as complexity above.
struct NestingDepthVisitor {
    current: usize,
    max_depth: usize,
}

impl NestingDepthVisitor {
    fn descend(&mut self, f: impl FnOnce(&mut Self)) {
        self.current += 1;
        self.max_depth = self.max_depth.max(self.current);
        f(self);
        self.current -= 1;
    }
}

impl Visitor for NestingDepthVisitor {
    fn visit_stmt_if(&mut self, node: StmtIf) {
        self.descend(|v| v.generic_visit_stmt_if(node));
    }
    fn visit_stmt_while(&mut self, node: StmtWhile) {
        self.descend(|v| v.generic_visit_stmt_while(node));
    }
    fn visit_stmt_for(&mut self, node: StmtFor) {
        self.descend(|v| v.generic_visit_stmt_for(node));
    }
    fn visit_stmt_async_for(&mut self, node: StmtAsyncFor) {
        self.descend(|v| v.generic_visit_stmt_async_for(node));
    }
    fn visit_stmt_with(&mut self, node: StmtWith) {
        self.descend(|v| v.generic_visit_stmt_with(node));
    }
    fn visit_stmt_try(&mut self, node: StmtTry) {
        self.descend(|v| v.generic_visit_stmt_try(node));
    }
    fn visit_excepthandler_except_handler(&mut self, node: ExceptHandlerExceptHandler) {
        self.descend(|v| v.generic_visit_excepthandler_except_handler(node));
    }
}

/// Maximum nesting depth for a function (If/For/While/With/Try/Except).
pub fn nesting_depth(func: &FuncNode) -> usize {
    let mut visitor = NestingDepthVisitor {
        current: 0,
        max_depth: 0,
    };
    visitor.visit_stmt(func.stmt.clone());
    visitor.max_depth
}

// ── Nested return-statement count ───────────────────────────────────────────
//
// Mirrors `ast_helpers.py::_count_nested_returns`: combines
// NestingDepthVisitor's depth-tracking `descend()` with the nested
// def/lambda stop condition previously used by `count_own_returns` — a
// `Return` only counts when it occurs at depth >= 2, and returns inside a
// nested function/lambda don't count at all.
struct NestedReturnsVisitor {
    current: usize,
    count: i64,
}

impl NestedReturnsVisitor {
    fn descend(&mut self, f: impl FnOnce(&mut Self)) {
        self.current += 1;
        f(self);
        self.current -= 1;
    }
}

impl Visitor for NestedReturnsVisitor {
    fn visit_stmt_if(&mut self, node: StmtIf) {
        self.descend(|v| v.generic_visit_stmt_if(node));
    }
    fn visit_stmt_while(&mut self, node: StmtWhile) {
        self.descend(|v| v.generic_visit_stmt_while(node));
    }
    fn visit_stmt_for(&mut self, node: StmtFor) {
        self.descend(|v| v.generic_visit_stmt_for(node));
    }
    fn visit_stmt_async_for(&mut self, node: StmtAsyncFor) {
        self.descend(|v| v.generic_visit_stmt_async_for(node));
    }
    fn visit_stmt_with(&mut self, node: StmtWith) {
        self.descend(|v| v.generic_visit_stmt_with(node));
    }
    fn visit_stmt_try(&mut self, node: StmtTry) {
        self.descend(|v| v.generic_visit_stmt_try(node));
    }
    fn visit_excepthandler_except_handler(&mut self, node: ExceptHandlerExceptHandler) {
        self.descend(|v| v.generic_visit_excepthandler_except_handler(node));
    }
    fn visit_stmt_return(&mut self, node: rustpython_ast::StmtReturn) {
        if self.current >= 2 {
            self.count += 1;
        }
        self.generic_visit_stmt_return(node);
    }
    fn visit_stmt_function_def(&mut self, _node: StmtFunctionDef) {}
    fn visit_stmt_async_function_def(&mut self, _node: StmtAsyncFunctionDef) {}
    fn visit_expr_lambda(&mut self, _node: rustpython_ast::ExprLambda) {}
}

pub fn count_nested_returns(func: &FuncNode) -> i64 {
    let mut visitor = NestedReturnsVisitor {
        current: 0,
        count: 0,
    };
    match &func.stmt {
        Stmt::FunctionDef(n) => visitor.generic_visit_stmt_function_def(n.clone()),
        Stmt::AsyncFunctionDef(n) => visitor.generic_visit_stmt_async_function_def(n.clone()),
        _ => {}
    }
    visitor.count
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
