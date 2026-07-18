//! AST utility functions — mirrors `ast_helpers.py`.
//!
//! rustpython-ast tracks byte offsets (`TextSize`/`TextRange`) rather than
//! Python's native (lineno, end_lineno), so a `LineIndex` bridges the two:
//! it's the equivalent of what Python's `ast` module gives you for free.

use rustpython_ast::text_size::TextSize;
use rustpython_ast::{
    Arguments, ExceptHandlerExceptHandler, Expr, Ranged, Stmt, StmtAssert, StmtAsyncFor,
    StmtAsyncFunctionDef, StmtFor, StmtFunctionDef, StmtIf, StmtTry, StmtWhile, StmtWith, Visitor,
};
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
}

struct FunctionCollector {
    functions: Vec<FuncNode>,
}

impl Visitor for FunctionCollector {
    fn visit_stmt_function_def(&mut self, node: StmtFunctionDef) {
        self.functions.push(FuncNode {
            name: node.name.as_str().to_string(),
            start: node.range().start(),
            stmt: Stmt::FunctionDef(node.clone()),
        });
        self.generic_visit_stmt_function_def(node);
    }

    fn visit_stmt_async_function_def(&mut self, node: StmtAsyncFunctionDef) {
        self.functions.push(FuncNode {
            name: node.name.as_str().to_string(),
            start: node.range().start(),
            stmt: Stmt::AsyncFunctionDef(node.clone()),
        });
        self.generic_visit_stmt_async_function_def(node);
    }
}

/// Every FunctionDef/AsyncFunctionDef in `module_body`, at any nesting level —
/// mirrors `for node in ast.walk(tree): if isinstance(node, (FunctionDef,
/// AsyncFunctionDef))`.
pub fn collect_functions(module_body: &[Stmt]) -> Vec<FuncNode> {
    let mut visitor = FunctionCollector {
        functions: Vec::new(),
    };
    for stmt in module_body {
        visitor.visit_stmt(stmt.clone());
    }
    visitor.functions
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
//
// Mirrors `ast_helpers.py::_cyclomatic_complexity`, which walks via
// `ast.walk()` over the *whole* function node — deliberately not stopping at
// nested function/lambda boundaries (a nested def's branches count toward
// the enclosing function too), and including args/decorators/return
// annotation, not just the body. Calling `visit_stmt` on the whole node
// (rather than just iterating `body`) reproduces that exact traversal, since
// this visitor doesn't override `visit_stmt_function_def`.
struct ComplexityVisitor {
    complexity: i64,
}

impl Visitor for ComplexityVisitor {
    fn visit_arguments(&mut self, node: Arguments) {
        walk_arguments_children(self, node);
    }
    fn visit_comprehension(&mut self, node: rustpython_ast::Comprehension) {
        walk_comprehension_children(self, node);
    }
    fn visit_keyword(&mut self, node: rustpython_ast::Keyword) {
        walk_keyword_children(self, node);
    }
    fn visit_withitem(&mut self, node: rustpython_ast::WithItem) {
        walk_withitem_children(self, node);
    }
    fn visit_stmt_if(&mut self, node: StmtIf) {
        self.complexity += 1;
        self.generic_visit_stmt_if(node);
    }
    fn visit_stmt_while(&mut self, node: StmtWhile) {
        self.complexity += 1;
        self.generic_visit_stmt_while(node);
    }
    fn visit_stmt_for(&mut self, node: StmtFor) {
        self.complexity += 1;
        self.generic_visit_stmt_for(node);
    }
    fn visit_stmt_async_for(&mut self, node: StmtAsyncFor) {
        self.complexity += 1;
        self.generic_visit_stmt_async_for(node);
    }
    fn visit_excepthandler_except_handler(&mut self, node: ExceptHandlerExceptHandler) {
        self.complexity += 1;
        self.generic_visit_excepthandler_except_handler(node);
    }
    fn visit_stmt_assert(&mut self, node: StmtAssert) {
        self.complexity += 1;
        self.generic_visit_stmt_assert(node);
    }
    fn visit_expr_bool_op(&mut self, node: rustpython_ast::ExprBoolOp) {
        self.complexity += node.values.len() as i64 - 1;
        self.generic_visit_expr_bool_op(node);
    }
    fn visit_expr_list_comp(&mut self, node: rustpython_ast::ExprListComp) {
        self.complexity += 1;
        self.generic_visit_expr_list_comp(node);
    }
    fn visit_expr_set_comp(&mut self, node: rustpython_ast::ExprSetComp) {
        self.complexity += 1;
        self.generic_visit_expr_set_comp(node);
    }
    fn visit_expr_dict_comp(&mut self, node: rustpython_ast::ExprDictComp) {
        self.complexity += 1;
        self.generic_visit_expr_dict_comp(node);
    }
    fn visit_expr_generator_exp(&mut self, node: rustpython_ast::ExprGeneratorExp) {
        self.complexity += 1;
        self.generic_visit_expr_generator_exp(node);
    }
}

/// Approximate McCabe cyclomatic complexity for a function.
pub fn cyclomatic_complexity(func: &FuncNode) -> i64 {
    let mut visitor = ComplexityVisitor { complexity: 1 };
    visitor.visit_stmt(func.stmt.clone());
    visitor.complexity
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

// ── Own return-statement count ───────────────────────────────────────────────
//
// Mirrors `ast_helpers.py::_count_own_returns`: unlike complexity/nesting
// above, this one *does* stop at nested function/lambda boundaries — Python
// does so explicitly (`if isinstance(child, (FunctionDef, AsyncFunctionDef,
// Lambda)): continue`). Calling the *generic* visit method directly on the
// outer node (bypassing the no-op override below, which exists only to stop
// descent into *nested* defs found while walking) reproduces that: the outer
// function's own body is still processed normally.
struct OwnReturnsVisitor {
    count: i64,
}

impl Visitor for OwnReturnsVisitor {
    fn visit_stmt_return(&mut self, node: rustpython_ast::StmtReturn) {
        self.count += 1;
        self.generic_visit_stmt_return(node);
    }
    fn visit_stmt_function_def(&mut self, _node: StmtFunctionDef) {}
    fn visit_stmt_async_function_def(&mut self, _node: StmtAsyncFunctionDef) {}
    fn visit_expr_lambda(&mut self, _node: rustpython_ast::ExprLambda) {}
}

pub fn count_own_returns(func: &FuncNode) -> i64 {
    let mut visitor = OwnReturnsVisitor { count: 0 };
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
