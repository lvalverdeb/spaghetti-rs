//! Per-file AST-based checks. Phase 2 batches 1-3 of the port proposal's §10
//! plan. Batch 1: `high-complexity`, `missing-return-type`,
//! `missing-param-type`, `too-many-params`, `excessive-returns`,
//! `boolean-flag-params`, `deep-nesting`, `mutable-default`, `bare-except`,
//! `missing-else`. Batch 2: `unused-import`, `swallowed-exception`,
//! `star-import`, `global-mutable`, `scope-mutation`, `dead-code`,
//! `excessive-decorators`, `lazy-class`, `magic-number`, `untyped-dict`.
//! Batch 3: `duplicate-branch`, `encapsulation-violation`, `god-class`,
//! `layer-violation`, `transport-in-library`, `potential-circular-import`,
//! `god-module`, `deep-inheritance`, `pass-through-method`. (`long-function`
//! shipped in Phase 1.) Only `message-chain` remains — deferred because it
//! needs `ast.walk()`'s actual breadth-first order, not just its coverage
//! (see §7.6/§10 of the proposal).

use crate::ast_helpers::{
    LineIndex, collect_functions, count_own_returns, cyclomatic_complexity, dump_stmts, is_private,
    line_count, nesting_depth, walk_arguments_children, walk_comprehension_children,
    walk_keyword_children, walk_withitem_children,
};
use crate::config::{
    COMPLEXITY_THRESHOLD, MAX_CLASS_ATTRS, MAX_CLASS_METHODS, MAX_DECORATORS, MAX_FUNC_PARAMS,
    MAX_FUNCTION_LINES, MAX_INHERITANCE_DEPTH, MAX_NESTING_DEPTH, MAX_RETURNS, MIN_BOOLEAN_FLAGS,
    is_dunder, layer_rules,
};
use crate::models::{Issue, Severity};
use rustpython_ast::{Arguments, Constant, Expr, Mod, Ranged, Stmt, Visitor};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

fn module_body(module: &Mod) -> &[Stmt] {
    match module {
        Mod::Module(m) => &m.body,
        _ => &[],
    }
}

fn issue(
    filepath: &Path,
    line: usize,
    severity: Severity,
    rule: &'static str,
    package: &str,
    message: String,
) -> Issue {
    Issue {
        file: filepath.to_path_buf(),
        line,
        severity,
        rule,
        message,
        package: package.to_string(),
    }
}

// ── Rule: Long Functions (Phase 1) ───────────────────────────────────────────

pub fn check_long_functions(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut issues = Vec::new();
    for func in collect_functions(module_body(module)) {
        let lines = line_count(&line_index, func.start, func.end());
        if lines > MAX_FUNCTION_LINES {
            issues.push(issue(
                filepath,
                line_index.line_number(func.start),
                Severity::Warning,
                "long-function",
                package,
                format!(
                    "{}() is {lines} lines (max {MAX_FUNCTION_LINES})",
                    func.name
                ),
            ));
        }
    }
    issues
}

/// Mirrors `detector.py::scan_package`'s `functions_scanned` counter.
pub fn count_functions(module: &Mod) -> usize {
    collect_functions(module_body(module)).len()
}

// ── Rule: High Cyclomatic Complexity ─────────────────────────────────────────

pub fn check_complexity(module: &Mod, source: &str, filepath: &Path, package: &str) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut issues = Vec::new();
    for func in collect_functions(module_body(module)) {
        let cc = cyclomatic_complexity(&func);
        if cc > COMPLEXITY_THRESHOLD as i64 {
            let severity = if cc > 15 {
                Severity::Error
            } else {
                Severity::Warning
            };
            issues.push(issue(
                filepath,
                line_index.line_number(func.start),
                severity,
                "high-complexity",
                package,
                format!(
                    "{}() has complexity {cc} (max {COMPLEXITY_THRESHOLD})",
                    func.name
                ),
            ));
        }
    }
    issues
}

// ── Rule: Missing Type Hints ─────────────────────────────────────────────────
//
// Python only ever inspects `node.args.args` here — deliberately excluding
// posonlyargs, kwonlyargs, vararg, and kwarg. That's a narrower scope than
// e.g. `check_mutable_defaults` (§ below) uses, and it's intentional to
// replicate exactly, not an oversight to "fix".

pub fn check_missing_types(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut issues = Vec::new();
    for func in collect_functions(module_body(module)) {
        if is_private(&func.name) {
            continue;
        }
        let line = line_index.line_number(func.start);
        if func.returns().is_none() && func.name != "__init__" {
            issues.push(issue(
                filepath,
                line,
                Severity::Warning,
                "missing-return-type",
                package,
                format!("{}() missing return type annotation", func.name),
            ));
        }
        for arg in &func.args().args {
            let name = arg.def.arg.as_str();
            if name == "self" || name == "cls" {
                continue;
            }
            if arg.def.annotation.is_none() {
                issues.push(issue(
                    filepath,
                    line,
                    Severity::Info,
                    "missing-param-type",
                    package,
                    format!("{}(): param '{name}' missing type annotation", func.name),
                ));
            }
        }
    }
    issues
}

// ── Rule: Excessive Parameters ───────────────────────────────────────────────
//
// Same `args.args`-only scope as missing-param-type above (excludes
// posonlyargs) — matches Python's `len(node.args.args) +
// len(node.args.kwonlyargs)`.

pub fn check_excessive_params(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut issues = Vec::new();
    for func in collect_functions(module_body(module)) {
        let args = func.args();
        let mut total = args.args.len() + args.kwonlyargs.len();
        if args.vararg.is_some() {
            total += 1;
        }
        if args.kwarg.is_some() {
            total += 1;
        }
        if total > MAX_FUNC_PARAMS {
            issues.push(issue(
                filepath,
                line_index.line_number(func.start),
                Severity::Warning,
                "too-many-params",
                package,
                format!("{}() has {total} params (max {MAX_FUNC_PARAMS})", func.name),
            ));
        }
    }
    issues
}

// ── Rule: Excessive Return Points ────────────────────────────────────────────

pub fn check_excessive_returns(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut issues = Vec::new();
    for func in collect_functions(module_body(module)) {
        let n = count_own_returns(&func);
        if n > MAX_RETURNS as i64 {
            issues.push(issue(
                filepath,
                line_index.line_number(func.start),
                Severity::Info,
                "excessive-returns",
                package,
                format!(
                    "{}() has {n} return statements (max {MAX_RETURNS})",
                    func.name
                ),
            ));
        }
    }
    issues
}

// ── Rule: Boolean Flag Parameters ────────────────────────────────────────────
//
// Same `args.args`-only scope as missing-param-type/too-many-params (plus
// kwonlyargs) — excludes posonlyargs.

fn is_bool_constant(expr: &Expr) -> bool {
    matches!(expr, Expr::Constant(c) if matches!(c.value, Constant::Bool(_)))
}

pub fn check_boolean_flag_params(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut issues = Vec::new();
    for func in collect_functions(module_body(module)) {
        let args = func.args();
        let mut flags: Vec<&str> = Vec::new();
        for arg in &args.args {
            if let Some(default) = &arg.default
                && is_bool_constant(default)
            {
                flags.push(arg.def.arg.as_str());
            }
        }
        for arg in &args.kwonlyargs {
            if let Some(default) = &arg.default
                && is_bool_constant(default)
            {
                flags.push(arg.def.arg.as_str());
            }
        }
        if flags.len() >= MIN_BOOLEAN_FLAGS {
            issues.push(issue(
                filepath,
                line_index.line_number(func.start),
                Severity::Info,
                "boolean-flag-params",
                package,
                format!(
                    "{}() has {} boolean flag params ({}) — combinations multiply branching",
                    func.name,
                    flags.len(),
                    flags.join(", ")
                ),
            ));
        }
    }
    issues
}

// ── Rule: Deep Nesting ────────────────────────────────────────────────────────

pub fn check_deep_nesting(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut issues = Vec::new();
    for func in collect_functions(module_body(module)) {
        let depth = nesting_depth(&func);
        if depth > MAX_NESTING_DEPTH {
            issues.push(issue(
                filepath,
                line_index.line_number(func.start),
                Severity::Warning,
                "deep-nesting",
                package,
                format!(
                    "{}() has nesting depth {depth} (max {MAX_NESTING_DEPTH})",
                    func.name
                ),
            ));
        }
    }
    issues
}

// ── Rule: Mutable Default Arguments ──────────────────────────────────────────
//
// Unlike the three rules above, Python's `node.args.defaults` covers
// posonlyargs *and* args combined (a quirk of how Python's `ast.arguments`
// represents defaults as one flat, right-aligned list across both) — so
// this rule, faithfully ported, DOES cover posonlyargs where the others
// don't. rustpython's `ArgWithDefault` attaches each default directly, so
// posonlyargs + args + kwonlyargs are walked explicitly here.

fn is_mutable_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::List(_) | Expr::Dict(_) | Expr::Set(_))
}

pub fn check_mutable_defaults(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut issues = Vec::new();
    for func in collect_functions(module_body(module)) {
        let args = func.args();
        let has_mutable_default = args
            .posonlyargs
            .iter()
            .chain(args.args.iter())
            .chain(args.kwonlyargs.iter())
            .filter_map(|a| a.default.as_deref())
            .any(is_mutable_literal);
        if has_mutable_default {
            issues.push(issue(
                filepath,
                line_index.line_number(func.start),
                Severity::Warning,
                "mutable-default",
                package,
                format!(
                    "{}() has mutable default argument — use None instead",
                    func.name
                ),
            ));
        }
    }
    issues
}

// ── Rule: Bare Except ─────────────────────────────────────────────────────────

struct BareExceptVisitor<'a> {
    line_index: &'a LineIndex,
    filepath: &'a Path,
    package: &'a str,
    issues: Vec<Issue>,
}

impl<'a> Visitor for BareExceptVisitor<'a> {
    fn visit_excepthandler_except_handler(
        &mut self,
        node: rustpython_ast::ExceptHandlerExceptHandler,
    ) {
        if node.type_.is_none() {
            self.issues.push(issue(
                self.filepath,
                self.line_index.line_number(node.range().start()),
                Severity::Warning,
                "bare-except",
                self.package,
                "Bare except clause — catch specific exceptions instead".to_string(),
            ));
        }
        self.generic_visit_excepthandler_except_handler(node);
    }
}

pub fn check_bare_except(module: &Mod, source: &str, filepath: &Path, package: &str) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut visitor = BareExceptVisitor {
        line_index: &line_index,
        filepath,
        package,
        issues: Vec::new(),
    };
    for stmt in module_body(module) {
        visitor.visit_stmt(stmt.clone());
    }
    visitor.issues
}

// ── Rule: Missing Else ────────────────────────────────────────────────────────

struct MissingElseVisitor<'a> {
    line_index: &'a LineIndex,
    filepath: &'a Path,
    package: &'a str,
    issues: Vec<Issue>,
}

const NON_TRIVIAL_BODY_THRESHOLD: usize = 2;

impl<'a> Visitor for MissingElseVisitor<'a> {
    fn visit_stmt_if(&mut self, node: rustpython_ast::StmtIf) {
        // Skipped when the if body's last statement already terminates
        // control flow (return/raise/continue/break): the negative path is
        // either "the rest of the function" or "the next loop iteration",
        // and is not missing. Reuses is_unreachable_after from the
        // dead-code rule, which defines the same set of terminators.
        let is_terminated = node.body.last().is_some_and(is_unreachable_after);
        if node.orelse.is_empty() && node.body.len() >= NON_TRIVIAL_BODY_THRESHOLD && !is_terminated
        {
            self.issues.push(issue(
                self.filepath,
                self.line_index.line_number(node.range().start()),
                Severity::Info,
                "missing-else",
                self.package,
                format!(
                    "'if' block has {} statements but no else/elif — missing the negative path",
                    node.body.len()
                ),
            ));
        }
        self.generic_visit_stmt_if(node);
    }
}

pub fn check_missing_else(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut visitor = MissingElseVisitor {
        line_index: &line_index,
        filepath,
        package,
        issues: Vec::new(),
    };
    for stmt in module_body(module) {
        visitor.visit_stmt(stmt.clone());
    }
    visitor.issues
}

// ── Rule: Unused Imports ─────────────────────────────────────────────────────

pub fn check_unused_imports(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    if filepath.file_name().and_then(|n| n.to_str()) == Some("__init__.py") {
        return Vec::new();
    }
    let line_index = LineIndex::new(source);

    // Mirrors Python's `imported[name] = node.lineno`: a plain dict
    // assignment, so if the same name is imported twice, the *last*
    // occurrence's position wins, not the first.
    struct ImportCollector {
        imported: HashMap<String, rustpython_ast::text_size::TextSize>,
    }
    impl Visitor for ImportCollector {
        fn visit_stmt_import(&mut self, node: rustpython_ast::StmtImport) {
            let pos = node.range().start();
            for alias in &node.names {
                let name = alias
                    .asname
                    .as_ref()
                    .unwrap_or(&alias.name)
                    .as_str()
                    .split('.')
                    .next()
                    .unwrap()
                    .to_string();
                if name != "_" {
                    self.imported.insert(name, pos);
                }
            }
        }
        fn visit_stmt_import_from(&mut self, node: rustpython_ast::StmtImportFrom) {
            if node.module.as_deref() == Some("__future__") {
                return;
            }
            let pos = node.range().start();
            for alias in &node.names {
                if alias.name.as_str() == "*" {
                    continue;
                }
                let name = alias.asname.as_ref().unwrap_or(&alias.name).to_string();
                if name != "_" {
                    self.imported.insert(name, pos);
                }
            }
        }
    }

    let mut collector = ImportCollector {
        imported: HashMap::new(),
    };
    for stmt in module_body(module) {
        collector.visit_stmt(stmt.clone());
    }
    if collector.imported.is_empty() {
        return Vec::new();
    }

    struct UsageCollector {
        used: HashSet<String>,
    }
    impl Visitor for UsageCollector {
        fn visit_comprehension(&mut self, node: rustpython_ast::Comprehension) {
            walk_comprehension_children(self, node);
        }
        fn visit_arguments(&mut self, node: Arguments) {
            walk_arguments_children(self, node);
        }
        fn visit_keyword(&mut self, node: rustpython_ast::Keyword) {
            walk_keyword_children(self, node);
        }
        fn visit_withitem(&mut self, node: rustpython_ast::WithItem) {
            walk_withitem_children(self, node);
        }
        fn visit_expr_name(&mut self, node: rustpython_ast::ExprName) {
            self.used.insert(node.id.to_string());
        }
        fn visit_stmt_assign(&mut self, node: rustpython_ast::StmtAssign) {
            let is_dunder_all = node
                .targets
                .iter()
                .any(|t| matches!(t, Expr::Name(n) if n.id.as_str() == "__all__"));
            if is_dunder_all {
                let elts: Option<&[Expr]> = match node.value.as_ref() {
                    Expr::List(l) => Some(&l.elts),
                    Expr::Tuple(t) => Some(&t.elts),
                    _ => None,
                };
                if let Some(elts) = elts {
                    for elt in elts {
                        if let Expr::Constant(c) = elt
                            && let Constant::Str(s) = &c.value
                        {
                            self.used.insert(s.clone());
                        }
                    }
                }
            }
            self.generic_visit_stmt_assign(node);
        }
    }
    let mut usage = UsageCollector {
        used: HashSet::new(),
    };
    for stmt in module_body(module) {
        usage.visit_stmt(stmt.clone());
    }

    let mut entries: Vec<(&String, &rustpython_ast::text_size::TextSize)> =
        collector.imported.iter().collect();
    entries.sort_by_key(|(_, pos)| **pos);

    entries
        .into_iter()
        .filter(|(name, _)| !usage.used.contains(*name))
        .map(|(name, pos)| {
            issue(
                filepath,
                line_index.line_number(*pos),
                Severity::Warning,
                "unused-import",
                package,
                format!("'{name}' imported but never used"),
            )
        })
        .collect()
}

// ── Rule: Swallowed Exceptions ────────────────────────────────────────────────

struct SwallowedExceptionVisitor<'a> {
    line_index: &'a LineIndex,
    filepath: &'a Path,
    package: &'a str,
    issues: Vec<Issue>,
}

fn is_pass_or_ellipsis_only(body: &[Stmt]) -> bool {
    if body.len() != 1 {
        return false;
    }
    match &body[0] {
        Stmt::Pass(_) => true,
        Stmt::Expr(e) => matches!(
            e.value.as_ref(),
            Expr::Constant(c) if matches!(c.value, Constant::Ellipsis)
        ),
        _ => false,
    }
}

impl<'a> Visitor for SwallowedExceptionVisitor<'a> {
    fn visit_excepthandler_except_handler(
        &mut self,
        node: rustpython_ast::ExceptHandlerExceptHandler,
    ) {
        if is_pass_or_ellipsis_only(&node.body) {
            let exc_name = match &node.type_ {
                Some(t) => match t.as_ref() {
                    Expr::Name(n) => n.id.to_string(),
                    _ => "Exception".to_string(),
                },
                None => "Exception".to_string(),
            };
            self.issues.push(issue(
                self.filepath,
                self.line_index.line_number(node.range().start()),
                Severity::Warning,
                "swallowed-exception",
                self.package,
                format!("except {exc_name}: silently discards the error with no log/reraise"),
            ));
        }
        self.generic_visit_excepthandler_except_handler(node);
    }
}

pub fn check_swallowed_exceptions(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut visitor = SwallowedExceptionVisitor {
        line_index: &line_index,
        filepath,
        package,
        issues: Vec::new(),
    };
    for stmt in module_body(module) {
        visitor.visit_stmt(stmt.clone());
    }
    visitor.issues
}

// ── Rule: Star Imports ────────────────────────────────────────────────────────

pub fn check_star_imports(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut issues = Vec::new();
    for stmt in module_body(module) {
        collect_star_imports(stmt, &line_index, filepath, package, &mut issues);
    }
    issues
}

fn collect_star_imports(
    stmt: &Stmt,
    line_index: &LineIndex,
    filepath: &Path,
    package: &str,
    issues: &mut Vec<Issue>,
) {
    struct StarImportVisitor<'a> {
        line_index: &'a LineIndex,
        filepath: &'a Path,
        package: &'a str,
        issues: Vec<Issue>,
    }
    impl<'a> Visitor for StarImportVisitor<'a> {
        fn visit_stmt_import_from(&mut self, node: rustpython_ast::StmtImportFrom) {
            for alias in &node.names {
                if alias.name.as_str() == "*" {
                    self.issues.push(issue(
                        self.filepath,
                        self.line_index.line_number(node.range().start()),
                        Severity::Warning,
                        "star-import",
                        self.package,
                        format!(
                            "Star import from '{}' — import specific names instead",
                            node.module.as_deref().unwrap_or("")
                        ),
                    ));
                }
            }
            self.generic_visit_stmt_import_from(node);
        }
    }
    let mut visitor = StarImportVisitor {
        line_index,
        filepath,
        package,
        issues: Vec::new(),
    };
    visitor.visit_stmt(stmt.clone());
    issues.append(&mut visitor.issues);
}

// ── Rule: Global State Mutation ──────────────────────────────────────────────
//
// Mirrors Python's use of `ast.iter_child_nodes(tree)` (module-level
// children only, not a full recursive walk) — deliberately shallow.

pub fn check_global_mutations(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut issues = Vec::new();
    for stmt in module_body(module) {
        if let Stmt::Assign(assign) = stmt {
            let is_mutable_value = matches!(
                assign.value.as_ref(),
                Expr::List(_) | Expr::Dict(_) | Expr::Set(_)
            );
            if !is_mutable_value {
                continue;
            }
            for target in &assign.targets {
                if let Expr::Name(name) = target
                    && !name.id.as_str().starts_with('_')
                {
                    issues.push(issue(
                        filepath,
                        line_index.line_number(assign.range().start()),
                        Severity::Info,
                        "global-mutable",
                        package,
                        format!(
                            "Module-level mutable '{}' — consider encapsulating",
                            name.id
                        ),
                    ));
                }
            }
        }
    }
    issues
}

// ── Rule: Scope Mutation ──────────────────────────────────────────────────────
//
// Mirrors Python's `_walk_own_scope`: a DFS that stops at nested
// function/class boundaries, so an inner def's own globals/assignments
// aren't misattributed to the outer function.

#[derive(Default)]
struct OwnScopeCollector {
    global_names: HashSet<String>,
    nonlocal_names: HashSet<String>,
    assignments: Vec<(String, TextSizeShim)>,
}

// Local newtype so this file doesn't need to import rustpython's TextSize
// directly just for this one field's type name in a doc-adjacent struct.
type TextSizeShim = rustpython_ast::text_size::TextSize;

impl Visitor for OwnScopeCollector {
    fn visit_stmt_function_def(&mut self, _node: rustpython_ast::StmtFunctionDef) {}
    fn visit_stmt_async_function_def(&mut self, _node: rustpython_ast::StmtAsyncFunctionDef) {}
    fn visit_stmt_class_def(&mut self, _node: rustpython_ast::StmtClassDef) {}
    fn visit_stmt_global(&mut self, node: rustpython_ast::StmtGlobal) {
        self.global_names
            .extend(node.names.iter().map(|n| n.to_string()));
    }
    fn visit_stmt_nonlocal(&mut self, node: rustpython_ast::StmtNonlocal) {
        self.nonlocal_names
            .extend(node.names.iter().map(|n| n.to_string()));
    }
    fn visit_stmt_assign(&mut self, node: rustpython_ast::StmtAssign) {
        for t in &node.targets {
            if let Expr::Name(n) = t {
                self.assignments
                    .push((n.id.to_string(), node.range().start()));
            }
        }
        self.generic_visit_stmt_assign(node);
    }
    fn visit_stmt_aug_assign(&mut self, node: rustpython_ast::StmtAugAssign) {
        if let Expr::Name(n) = node.target.as_ref() {
            self.assignments
                .push((n.id.to_string(), node.range().start()));
        }
        self.generic_visit_stmt_aug_assign(node);
    }
}

pub fn check_scope_mutations(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut issues = Vec::new();
    for func in collect_functions(module_body(module)) {
        let mut collector = OwnScopeCollector::default();
        for stmt in func.body() {
            collector.visit_stmt(stmt.clone());
        }
        let outer_names: HashSet<&String> = collector
            .global_names
            .iter()
            .chain(collector.nonlocal_names.iter())
            .collect();
        if outer_names.is_empty() {
            continue;
        }
        if let Some((target_name, pos)) = collector
            .assignments
            .iter()
            .find(|(name, _)| outer_names.contains(name))
        {
            let mut declared_by = Vec::new();
            if collector.global_names.contains(target_name) {
                declared_by.push("global");
            }
            if collector.nonlocal_names.contains(target_name) {
                declared_by.push("nonlocal");
            }
            issues.push(issue(
                filepath,
                line_index.line_number(*pos),
                Severity::Info,
                "scope-mutation",
                package,
                format!(
                    "{}() mutates outer-scope variable '{}' via {} — shared mutable state makes control flow hard to trace",
                    func.name,
                    target_name,
                    declared_by.join("/")
                ),
            ));
        }
    }
    issues
}

// ── Rule: Dead Code ───────────────────────────────────────────────────────────
//
// Mirrors Python's two-part scan per function: (1) the function's own
// top-level body for statements after a Return/Raise/Break/Continue, and
// (2) for each of that body's direct statements, that statement's own
// body/orelse (and, only for plain `Try` — not `TryStar` — each handler's
// body), one level deep, not recursively further.

fn is_unreachable_after(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Return(_) | Stmt::Raise(_) | Stmt::Break(_) | Stmt::Continue(_)
    )
}

fn scan_body_for_dead_code(
    body: &[Stmt],
    line_index: &LineIndex,
    filepath: &Path,
    package: &str,
    issues: &mut Vec<Issue>,
) {
    for (i, stmt) in body.iter().enumerate() {
        if is_unreachable_after(stmt) {
            for next in &body[i + 1..] {
                issues.push(issue(
                    filepath,
                    line_index.line_number(next.range().start()),
                    Severity::Warning,
                    "dead-code",
                    package,
                    "statement is unreachable — previous line always terminates".to_string(),
                ));
            }
            break;
        }
    }
}

fn stmt_body_and_orelse(stmt: &Stmt) -> (Option<&[Stmt]>, Option<&[Stmt]>) {
    match stmt {
        Stmt::If(s) => (Some(&s.body), Some(&s.orelse)),
        Stmt::For(s) => (Some(&s.body), Some(&s.orelse)),
        Stmt::AsyncFor(s) => (Some(&s.body), Some(&s.orelse)),
        Stmt::While(s) => (Some(&s.body), Some(&s.orelse)),
        Stmt::Try(s) => (Some(&s.body), Some(&s.orelse)),
        Stmt::TryStar(s) => (Some(&s.body), Some(&s.orelse)),
        Stmt::With(s) => (Some(&s.body), None),
        Stmt::AsyncWith(s) => (Some(&s.body), None),
        Stmt::FunctionDef(s) => (Some(&s.body), None),
        Stmt::AsyncFunctionDef(s) => (Some(&s.body), None),
        Stmt::ClassDef(s) => (Some(&s.body), None),
        _ => (None, None),
    }
}

fn scan_stmt_for_dead_code(
    stmt: &Stmt,
    line_index: &LineIndex,
    filepath: &Path,
    package: &str,
    issues: &mut Vec<Issue>,
) {
    let (body, orelse) = stmt_body_and_orelse(stmt);
    if let Some(body) = body {
        scan_body_for_dead_code(body, line_index, filepath, package, issues);
    }
    if let Some(orelse) = orelse
        && !orelse.is_empty()
    {
        scan_body_for_dead_code(orelse, line_index, filepath, package, issues);
    }
    if let Stmt::Try(s) = stmt {
        for handler in &s.handlers {
            let rustpython_ast::ExceptHandler::ExceptHandler(h) = handler;
            scan_body_for_dead_code(&h.body, line_index, filepath, package, issues);
        }
    }
}

pub fn check_dead_code(module: &Mod, source: &str, filepath: &Path, package: &str) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut issues = Vec::new();
    for func in collect_functions(module_body(module)) {
        scan_body_for_dead_code(func.body(), &line_index, filepath, package, &mut issues);
        for stmt in func.body() {
            scan_stmt_for_dead_code(stmt, &line_index, filepath, package, &mut issues);
        }
    }
    issues
}

// ── Rule: Excessive Decorators ───────────────────────────────────────────────

pub fn check_excessive_decorators(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);

    struct DecoratorVisitor<'a> {
        line_index: &'a LineIndex,
        filepath: &'a Path,
        package: &'a str,
        issues: Vec<Issue>,
    }
    impl<'a> DecoratorVisitor<'a> {
        fn check(
            &mut self,
            kind: &str,
            name: &str,
            decorators: usize,
            start: rustpython_ast::text_size::TextSize,
        ) {
            if decorators > MAX_DECORATORS {
                self.issues.push(issue(
                    self.filepath,
                    self.line_index.line_number(start),
                    Severity::Info,
                    "excessive-decorators",
                    self.package,
                    format!(
                        "{kind} '{name}' has {decorators} decorators (max {MAX_DECORATORS}) — consider a wrapper or composition"
                    ),
                ));
            }
        }
    }
    impl<'a> Visitor for DecoratorVisitor<'a> {
        fn visit_stmt_function_def(&mut self, node: rustpython_ast::StmtFunctionDef) {
            self.check(
                "function",
                node.name.as_str(),
                node.decorator_list.len(),
                node.range().start(),
            );
            self.generic_visit_stmt_function_def(node);
        }
        fn visit_stmt_async_function_def(&mut self, node: rustpython_ast::StmtAsyncFunctionDef) {
            self.check(
                "function",
                node.name.as_str(),
                node.decorator_list.len(),
                node.range().start(),
            );
            self.generic_visit_stmt_async_function_def(node);
        }
        fn visit_stmt_class_def(&mut self, node: rustpython_ast::StmtClassDef) {
            self.check(
                "class",
                node.name.as_str(),
                node.decorator_list.len(),
                node.range().start(),
            );
            self.generic_visit_stmt_class_def(node);
        }
    }

    let mut visitor = DecoratorVisitor {
        line_index: &line_index,
        filepath,
        package,
        issues: Vec::new(),
    };
    for stmt in module_body(module) {
        visitor.visit_stmt(stmt.clone());
    }
    visitor.issues
}

// ── Rule: Lazy Class ──────────────────────────────────────────────────────────

// Base class names (matched by their final Expr::Name/Expr::Attribute
// component, not a resolved import) that already make a class a
// declarative data container — flagging them as "lazy" and suggesting
// "@dataclass" is nonsensical since they already fulfill that exact role.
const LAZY_CLASS_EXEMPT_BASE_NAMES: &[&str] = &["BaseModel", "BaseSettings"];

/// The name a decorator resolves to, e.g. "dataclass" for both `@dataclass`
/// and `@dataclass(frozen=True)`.
fn decorator_target_name(dec: &Expr) -> Option<String> {
    let target = match dec {
        Expr::Call(c) => c.func.as_ref(),
        other => other,
    };
    match target {
        Expr::Name(n) => Some(n.id.to_string()),
        Expr::Attribute(a) => Some(a.attr.to_string()),
        _ => None,
    }
}

/// True if `node` already is a declarative data container: a pydantic
/// BaseModel/BaseSettings subclass, or a @dataclass-decorated class. These
/// already satisfy check_lazy_class's own suggested remedy, so they should
/// never be flagged regardless of method count.
fn is_lazy_class_exempt(node: &rustpython_ast::StmtClassDef) -> bool {
    if base_names(&node.bases)
        .iter()
        .any(|b| LAZY_CLASS_EXEMPT_BASE_NAMES.contains(&b.as_str()))
    {
        return true;
    }
    node.decorator_list
        .iter()
        .any(|dec| decorator_target_name(dec).as_deref() == Some("dataclass"))
}

pub fn check_lazy_class(module: &Mod, source: &str, filepath: &Path, package: &str) -> Vec<Issue> {
    let line_index = LineIndex::new(source);

    struct LazyClassVisitor<'a> {
        line_index: &'a LineIndex,
        filepath: &'a Path,
        package: &'a str,
        issues: Vec<Issue>,
    }
    impl<'a> Visitor for LazyClassVisitor<'a> {
        fn visit_stmt_class_def(&mut self, node: rustpython_ast::StmtClassDef) {
            if !is_lazy_class_exempt(&node) {
                let methods = node
                    .body
                    .iter()
                    .filter(|s| matches!(s, Stmt::FunctionDef(_) | Stmt::AsyncFunctionDef(_)))
                    .count();
                if methods < 2 {
                    self.issues.push(issue(
                        self.filepath,
                        self.line_index.line_number(node.range().start()),
                        Severity::Info,
                        "lazy-class",
                        self.package,
                        format!(
                            "class '{}' has {methods} method(s) — consider a plain function or @dataclass",
                            node.name
                        ),
                    ));
                }
            }
            self.generic_visit_stmt_class_def(node);
        }
    }

    let mut visitor = LazyClassVisitor {
        line_index: &line_index,
        filepath,
        package,
        issues: Vec::new(),
    };
    for stmt in module_body(module) {
        visitor.visit_stmt(stmt.clone());
    }
    visitor.issues
}

// ── Rule: Magic Numbers ───────────────────────────────────────────────────────
//
// Mirrors Python's per-function `ast.walk(func)` scan (so, like
// high-complexity, this needs the comprehension/arguments traversal fixes),
// skipping `__init__`. A `Constant::Bool` can never match here (bools are a
// distinct rustpython variant from ints), which is behaviorally identical to
// Python's `isinstance(value, (int, float))` + `value not in {-1, 0, 1}` —
// `True`/`False` compare equal to 1/0 in Python's set too, so they're
// already always "allowed" there; the two implementations just reach that
// same answer via different type systems.

fn format_number_for_magic_check(c: &Constant) -> Option<(bool, String)> {
    match c {
        Constant::Int(i) => {
            let allowed = *i == (-1).into() || *i == 0.into() || *i == 1.into();
            Some((allowed, i.to_string()))
        }
        Constant::Float(f) => {
            let allowed = *f == -1.0 || *f == 0.0 || *f == 1.0;
            Some((allowed, format!("{f:?}")))
        }
        _ => None,
    }
}

struct MagicNumberVisitor<'a> {
    line_index: &'a LineIndex,
    filepath: &'a Path,
    package: &'a str,
    issues: Vec<Issue>,
}
impl<'a> Visitor for MagicNumberVisitor<'a> {
    fn visit_comprehension(&mut self, node: rustpython_ast::Comprehension) {
        walk_comprehension_children(self, node);
    }
    fn visit_arguments(&mut self, node: Arguments) {
        walk_arguments_children(self, node);
    }
    fn visit_keyword(&mut self, node: rustpython_ast::Keyword) {
        walk_keyword_children(self, node);
    }
    fn visit_withitem(&mut self, node: rustpython_ast::WithItem) {
        walk_withitem_children(self, node);
    }
    fn visit_expr_constant(&mut self, node: rustpython_ast::ExprConstant) {
        if let Some((allowed, repr)) = format_number_for_magic_check(&node.value)
            && !allowed
        {
            self.issues.push(issue(
                self.filepath,
                self.line_index.line_number(node.range().start()),
                Severity::Info,
                "magic-number",
                self.package,
                format!("magic number {repr} — extract to a named constant"),
            ));
        }
    }
}

pub fn check_magic_numbers(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut issues = Vec::new();
    for func in collect_functions(module_body(module)) {
        if func.name == "__init__" {
            continue;
        }
        let mut visitor = MagicNumberVisitor {
            line_index: &line_index,
            filepath,
            package,
            issues: Vec::new(),
        };
        visitor.visit_stmt(func.stmt.clone());
        issues.append(&mut visitor.issues);
    }
    issues
}

// ── Rule: Untyped Dict ────────────────────────────────────────────────────────
//
// Mirrors Python's two-stage walk: collect every annotation expression in
// the module (return annotations, param annotations, `AnnAssign`
// annotations — deliberately not `TypeAlias`, a rare Python 3.12+ form
// Python's own check only reaches via `getattr(ast, "TypeAlias", ...)`
// defensively; skipped here too), then scan each one for a bare `dict`
// (a `Name("dict")` not already inside a `dict[...]` subscript's own head).

#[derive(Default)]
struct AnnotationCollector {
    annotations: Vec<Expr>,
}
impl Visitor for AnnotationCollector {
    fn visit_stmt_function_def(&mut self, node: rustpython_ast::StmtFunctionDef) {
        if let Some(r) = &node.returns {
            self.annotations.push((**r).clone());
        }
        self.generic_visit_stmt_function_def(node);
    }
    fn visit_stmt_async_function_def(&mut self, node: rustpython_ast::StmtAsyncFunctionDef) {
        if let Some(r) = &node.returns {
            self.annotations.push((**r).clone());
        }
        self.generic_visit_stmt_async_function_def(node);
    }
    fn visit_stmt_ann_assign(&mut self, node: rustpython_ast::StmtAnnAssign) {
        self.annotations.push((*node.annotation).clone());
        self.generic_visit_stmt_ann_assign(node);
    }
    fn visit_arguments(&mut self, node: Arguments) {
        for arg in node
            .posonlyargs
            .iter()
            .chain(&node.args)
            .chain(&node.kwonlyargs)
        {
            if let Some(annotation) = &arg.def.annotation {
                self.annotations.push((**annotation).clone());
            }
        }
        if let Some(vararg) = &node.vararg
            && let Some(annotation) = &vararg.annotation
        {
            self.annotations.push((**annotation).clone());
        }
        if let Some(kwarg) = &node.kwarg
            && let Some(annotation) = &kwarg.annotation
        {
            self.annotations.push((**annotation).clone());
        }
        walk_arguments_children(self, node);
    }
    fn visit_comprehension(&mut self, node: rustpython_ast::Comprehension) {
        walk_comprehension_children(self, node);
    }
}

struct BareDictScanner<'a> {
    line_index: &'a LineIndex,
    lines: Vec<usize>,
}
impl<'a> Visitor for BareDictScanner<'a> {
    fn visit_expr_subscript(&mut self, node: rustpython_ast::ExprSubscript) {
        if let Expr::Name(n) = node.value.as_ref()
            && n.id.as_str() == "dict"
        {
            self.visit_expr(*node.slice);
            return;
        }
        self.generic_visit_expr_subscript(node);
    }
    fn visit_expr_name(&mut self, node: rustpython_ast::ExprName) {
        if node.id.as_str() == "dict" {
            self.lines
                .push(self.line_index.line_number(node.range().start()));
        }
    }
    fn visit_comprehension(&mut self, node: rustpython_ast::Comprehension) {
        walk_comprehension_children(self, node);
    }
    fn visit_arguments(&mut self, node: Arguments) {
        walk_arguments_children(self, node);
    }
}

pub fn check_untyped_dicts(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut collector = AnnotationCollector::default();
    for stmt in module_body(module) {
        collector.visit_stmt(stmt.clone());
    }

    let mut lines: Vec<usize> = Vec::new();
    for annotation in collector.annotations {
        let mut scanner = BareDictScanner {
            line_index: &line_index,
            lines: Vec::new(),
        };
        scanner.visit_expr(annotation);
        lines.extend(scanner.lines);
    }
    lines.sort_unstable();
    lines.dedup();

    lines
        .into_iter()
        .map(|line| {
            issue(
                filepath,
                line,
                Severity::Info,
                "untyped-dict",
                package,
                "Bare 'dict' used in type hint — use dict[str, Any] or similar".to_string(),
            )
        })
        .collect()
}

// ── Rule: Duplicate If/Else Branches ─────────────────────────────────────────

struct DuplicateBranchVisitor<'a> {
    line_index: &'a LineIndex,
    filepath: &'a Path,
    package: &'a str,
    issues: Vec<Issue>,
}
impl<'a> Visitor for DuplicateBranchVisitor<'a> {
    fn visit_stmt_if(&mut self, node: rustpython_ast::StmtIf) {
        let skip = node.orelse.is_empty()
            || (node.orelse.len() == 1 && matches!(node.orelse[0], Stmt::If(_)))
            || node.body.is_empty();
        if !skip && dump_stmts(&node.body) == dump_stmts(&node.orelse) {
            self.issues.push(issue(
                self.filepath,
                self.line_index.line_number(node.range().start()),
                Severity::Warning,
                "duplicate-branch",
                self.package,
                "if/else branches are structurally identical — the condition has no effect"
                    .to_string(),
            ));
        }
        self.generic_visit_stmt_if(node);
    }
}

pub fn check_duplicate_branches(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut visitor = DuplicateBranchVisitor {
        line_index: &line_index,
        filepath,
        package,
        issues: Vec::new(),
    };
    for stmt in module_body(module) {
        visitor.visit_stmt(stmt.clone());
    }
    visitor.issues
}

// ── Rule: Encapsulation Violations ───────────────────────────────────────────
//
// Mirrors Python's `_walk_with_class_context`: tracks the *nearest*
// enclosing class name (a single current value, reset on entering a nested
// class, unaffected by nested functions), checked against `self`/`cls`/the
// class's own name/`super()`.

fn is_allowed_base(base: &Expr, current_class: Option<&str>) -> bool {
    match base {
        Expr::Name(n) => {
            let id = n.id.as_str();
            id == "self" || id == "cls" || Some(id) == current_class
        }
        Expr::Call(c) => matches!(c.func.as_ref(), Expr::Name(n) if n.id.as_str() == "super"),
        _ => false,
    }
}

struct EncapsulationVisitor<'a> {
    line_index: &'a LineIndex,
    filepath: &'a Path,
    package: &'a str,
    class_stack: Vec<String>,
    issues: Vec<Issue>,
}
impl<'a> EncapsulationVisitor<'a> {
    fn current_class(&self) -> Option<&str> {
        self.class_stack.last().map(|s| s.as_str())
    }
}
impl<'a> Visitor for EncapsulationVisitor<'a> {
    fn visit_stmt_class_def(&mut self, node: rustpython_ast::StmtClassDef) {
        self.class_stack.push(node.name.to_string());
        self.generic_visit_stmt_class_def(node);
        self.class_stack.pop();
    }
    fn visit_expr_attribute(&mut self, node: rustpython_ast::ExprAttribute) {
        let attr = node.attr.as_str();
        if matches!(node.ctx, rustpython_ast::ExprContext::Load)
            && attr.starts_with('_')
            && !is_dunder(attr)
            && !is_allowed_base(&node.value, self.current_class())
        {
            self.issues.push(issue(
                self.filepath,
                self.line_index.line_number(node.range().start()),
                Severity::Info,
                "encapsulation-violation",
                self.package,
                format!("Accesses private member '.{attr}' through something other than self/cls"),
            ));
        }
        self.generic_visit_expr_attribute(node);
    }
    fn visit_expr_call(&mut self, node: rustpython_ast::ExprCall) {
        if let Expr::Name(func_name) = node.func.as_ref() {
            let fname = func_name.id.as_str();
            if (fname == "getattr" || fname == "setattr" || fname == "hasattr")
                && node.args.len() >= 2
                && let Expr::Constant(c) = &node.args[1]
                && let Constant::Str(attr_name) = &c.value
                && attr_name.starts_with('_')
                && !is_dunder(attr_name)
                && !is_allowed_base(&node.args[0], self.current_class())
            {
                self.issues.push(issue(
                    self.filepath,
                    self.line_index.line_number(node.range().start()),
                    Severity::Info,
                    "encapsulation-violation",
                    self.package,
                    format!("{fname}(..., '{attr_name}', ...) reaches into a private attribute"),
                ));
            }
        }
        self.generic_visit_expr_call(node);
    }
    fn visit_comprehension(&mut self, node: rustpython_ast::Comprehension) {
        walk_comprehension_children(self, node);
    }
    fn visit_arguments(&mut self, node: Arguments) {
        walk_arguments_children(self, node);
    }
    fn visit_keyword(&mut self, node: rustpython_ast::Keyword) {
        walk_keyword_children(self, node);
    }
    fn visit_withitem(&mut self, node: rustpython_ast::WithItem) {
        walk_withitem_children(self, node);
    }
}

pub fn check_encapsulation_violations(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut visitor = EncapsulationVisitor {
        line_index: &line_index,
        filepath,
        package,
        class_stack: Vec::new(),
        issues: Vec::new(),
    };
    for stmt in module_body(module) {
        visitor.visit_stmt(stmt.clone());
    }
    visitor.issues
}

// ── Rule: God Class ───────────────────────────────────────────────────────────

struct GodClassVisitor<'a> {
    line_index: &'a LineIndex,
    filepath: &'a Path,
    package: &'a str,
    issues: Vec<Issue>,
}
impl<'a> Visitor for GodClassVisitor<'a> {
    fn visit_stmt_class_def(&mut self, node: rustpython_ast::StmtClassDef) {
        let methods: Vec<&Stmt> = node
            .body
            .iter()
            .filter(|s| matches!(s, Stmt::FunctionDef(_) | Stmt::AsyncFunctionDef(_)))
            .collect();

        struct SelfAttrVisitor {
            attrs: HashSet<String>,
        }
        impl Visitor for SelfAttrVisitor {
            fn visit_expr_attribute(&mut self, node: rustpython_ast::ExprAttribute) {
                if matches!(node.ctx, rustpython_ast::ExprContext::Store)
                    && matches!(node.value.as_ref(), Expr::Name(n) if n.id.as_str() == "self")
                {
                    self.attrs.insert(node.attr.to_string());
                }
                self.generic_visit_expr_attribute(node);
            }
            fn visit_comprehension(&mut self, node: rustpython_ast::Comprehension) {
                walk_comprehension_children(self, node);
            }
            fn visit_arguments(&mut self, node: Arguments) {
                walk_arguments_children(self, node);
            }
            fn visit_keyword(&mut self, node: rustpython_ast::Keyword) {
                walk_keyword_children(self, node);
            }
            fn visit_withitem(&mut self, node: rustpython_ast::WithItem) {
                walk_withitem_children(self, node);
            }
        }
        let mut attr_visitor = SelfAttrVisitor {
            attrs: HashSet::new(),
        };
        for method in &methods {
            attr_visitor.visit_stmt((*method).clone());
        }

        if methods.len() > MAX_CLASS_METHODS || attr_visitor.attrs.len() > MAX_CLASS_ATTRS {
            let severity = if methods.len() as f64 > MAX_CLASS_METHODS as f64 * 1.5
                || attr_visitor.attrs.len() as f64 > MAX_CLASS_ATTRS as f64 * 1.5
            {
                Severity::Error
            } else {
                Severity::Warning
            };
            self.issues.push(issue(
                self.filepath,
                self.line_index.line_number(node.range().start()),
                severity,
                "god-class",
                self.package,
                format!(
                    "class {} has {} methods and {} attributes (max {MAX_CLASS_METHODS}/{MAX_CLASS_ATTRS}) — consider splitting responsibilities",
                    node.name,
                    methods.len(),
                    attr_visitor.attrs.len()
                ),
            ));
        }
        self.generic_visit_stmt_class_def(node);
    }
}

pub fn check_god_class(module: &Mod, source: &str, filepath: &Path, package: &str) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut visitor = GodClassVisitor {
        line_index: &line_index,
        filepath,
        package,
        issues: Vec::new(),
    };
    for stmt in module_body(module) {
        visitor.visit_stmt(stmt.clone());
    }
    visitor.issues
}

// ── Rule: Layer Violations ───────────────────────────────────────────────────
//
// Needs the package root (to compute the file's path relative to it) —
// unlike every other check so far, this one isn't part of `ALL_CHECKS`;
// `scanner.rs` calls it directly alongside the rest, passing `pkg_root`.

pub fn check_layer_violations(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
    pkg_root: &Path,
) -> Vec<Issue> {
    let rules = layer_rules(package);
    if rules.is_empty() {
        return Vec::new();
    }
    let Ok(rel_path) = filepath.strip_prefix(pkg_root) else {
        return Vec::new();
    };
    let rel_path_str = rel_path.to_string_lossy();
    let line_index = LineIndex::new(source);

    struct ImportedModuleVisitor {
        imports: Vec<(String, rustpython_ast::text_size::TextSize)>,
    }
    impl Visitor for ImportedModuleVisitor {
        fn visit_stmt_import(&mut self, node: rustpython_ast::StmtImport) {
            if let Some(alias) = node.names.first() {
                self.imports
                    .push((alias.name.to_string(), node.range().start()));
            }
        }
        fn visit_stmt_import_from(&mut self, node: rustpython_ast::StmtImportFrom) {
            if let Some(module) = &node.module {
                self.imports
                    .push((module.to_string(), node.range().start()));
            }
        }
    }
    let mut collector = ImportedModuleVisitor {
        imports: Vec::new(),
    };
    for stmt in module_body(module) {
        collector.visit_stmt(stmt.clone());
    }

    let mut issues = Vec::new();
    for (pattern, forbidden_prefixes) in rules {
        if !rel_path_str.starts_with(pattern) {
            continue;
        }
        for (imported, pos) in &collector.imports {
            if forbidden_prefixes
                .iter()
                .any(|prefix| imported.starts_with(prefix))
            {
                issues.push(issue(
                    filepath,
                    line_index.line_number(*pos),
                    Severity::Error,
                    "layer-violation",
                    package,
                    format!(
                        "Module '{rel_path_str}' imports '{imported}' — forbidden by layer rules"
                    ),
                ));
            }
        }
    }
    issues
}

// ── Rule: Transport in Library ───────────────────────────────────────────────

pub fn check_transport_in_library(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    if !matches!(package, "etl-core" | "boti" | "boti-data" | "boti-dask") {
        return Vec::new();
    }
    const TRANSPORT_MODULES: &[&str] = &["fastapi", "starlette", "httpx", "flask", "django"];
    let line_index = LineIndex::new(source);

    struct TransportVisitor<'a> {
        line_index: &'a LineIndex,
        filepath: &'a Path,
        package: &'a str,
        issues: Vec<Issue>,
    }
    impl<'a> Visitor for TransportVisitor<'a> {
        fn visit_stmt_import_from(&mut self, node: rustpython_ast::StmtImportFrom) {
            if let Some(module) = &node.module {
                let top = module.split('.').next().unwrap_or("");
                if TRANSPORT_MODULES.contains(&top) {
                    self.issues.push(issue(
                        self.filepath,
                        self.line_index.line_number(node.range().start()),
                        Severity::Error,
                        "transport-in-library",
                        self.package,
                        format!("Library imports transport module '{top}' — violates G9"),
                    ));
                }
            }
            self.generic_visit_stmt_import_from(node);
        }
    }
    let mut visitor = TransportVisitor {
        line_index: &line_index,
        filepath,
        package,
        issues: Vec::new(),
    };
    for stmt in module_body(module) {
        visitor.visit_stmt(stmt.clone());
    }
    visitor.issues
}

// ── Rule: Circular Imports (per-file heuristic) ──────────────────────────────
//
// Also needs `pkg_root` — same non-`ALL_CHECKS` treatment as
// `check_layer_violations` above.

pub fn check_circular_imports(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
    pkg_root: &Path,
) -> Vec<Issue> {
    let Ok(rel) = filepath.strip_prefix(pkg_root.parent().unwrap_or(pkg_root)) else {
        return Vec::new();
    };
    let rel = rel.with_extension("");
    let parts: Vec<String> = rel
        .iter()
        .map(|c| c.to_string_lossy().into_owned())
        .collect();
    let line_index = LineIndex::new(source);

    let mut issues = Vec::new();
    for stmt in module_body(module) {
        if let Stmt::ImportFrom(node) = stmt
            && let Some(module_name) = &node.module
        {
            let imp_parts: Vec<&str> = module_name.split('.').collect();
            if imp_parts.len() < parts.len()
                && parts.iter().take(imp_parts.len()).eq(imp_parts
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .iter())
            {
                issues.push(issue(
                        filepath,
                        line_index.line_number(node.range().start()),
                        Severity::Warning,
                        "potential-circular-import",
                        package,
                        format!(
                            "Child module imports parent '{module_name}' — potential circular dependency"
                        ),
                    ));
            }
        }
    }
    issues
}

// ── Rule: God Module ──────────────────────────────────────────────────────────
//
// Mirrors Python's use of `ast.iter_child_nodes(tree)` — module-level
// children only, deliberately shallow (same as global-mutable).

pub fn check_god_module(module: &Mod, _source: &str, filepath: &Path, package: &str) -> Vec<Issue> {
    let mut public_classes = 0;
    let mut public_funcs = 0;
    for stmt in module_body(module) {
        match stmt {
            Stmt::ClassDef(c) if !c.name.starts_with('_') => public_classes += 1,
            Stmt::FunctionDef(f) if !f.name.starts_with('_') => public_funcs += 1,
            Stmt::AsyncFunctionDef(f) if !f.name.starts_with('_') => public_funcs += 1,
            _ => {}
        }
    }
    let total = public_classes + public_funcs;
    if total > 15 {
        vec![issue(
            filepath,
            1,
            Severity::Warning,
            "god-module",
            package,
            format!(
                "Module exposes {total} public symbols ({public_classes} classes, {public_funcs} functions) — consider splitting"
            ),
        )]
    } else {
        Vec::new()
    }
}

// ── Rule: Deep Inheritance ────────────────────────────────────────────────────
//
// Mirrors Python's transitive-closure BFS over base-class names, re-scanning
// the whole file's ClassDefs for each queued name (matches by simple name,
// not fully-qualified — same as Python, which only ever compares
// `Name.id`/`Attribute.attr` strings). "Effective depth" here means the
// total count of distinct ancestor names discovered, not a literal chain
// length — an unusual metric, but it's what Python actually computes, so
// it's what gets ported.

fn base_names(bases: &[Expr]) -> Vec<String> {
    bases
        .iter()
        .filter_map(|b| match b {
            Expr::Name(n) => Some(n.id.to_string()),
            Expr::Attribute(a) => Some(a.attr.to_string()),
            _ => None,
        })
        .collect()
}

pub fn check_deep_inheritance(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);

    // Python's version uses ast.walk(tree), which finds ClassDefs at any
    // nesting level (module-level, inside functions, inside other classes),
    // not just module-level ones — mirror that with an explicit recursive
    // collection rather than relying on `collect_functions`-style tooling,
    // since this needs ClassDefs specifically, not FunctionDefs.
    fn collect_all_classes<'a>(
        stmts: &'a [Stmt],
        out: &mut Vec<(&'a str, &'a [Expr], rustpython_ast::text_size::TextSize)>,
    ) {
        for stmt in stmts {
            match stmt {
                Stmt::ClassDef(c) => {
                    out.push((c.name.as_str(), c.bases.as_slice(), c.range().start()));
                    collect_all_classes(&c.body, out);
                }
                Stmt::FunctionDef(f) => collect_all_classes(&f.body, out),
                Stmt::AsyncFunctionDef(f) => collect_all_classes(&f.body, out),
                _ => {}
            }
        }
    }
    let mut all_classes_full = Vec::new();
    collect_all_classes(module_body(module), &mut all_classes_full);

    let mut issues = Vec::new();
    for (class_name, bases, start) in &all_classes_full {
        if bases.is_empty() {
            continue;
        }
        let mut seen: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = base_names(bases).into_iter().collect();
        while let Some(name) = queue.pop_front() {
            if seen.contains(&name) || name == *class_name {
                continue;
            }
            seen.insert(name.clone());
            for (other_name, other_bases, _) in &all_classes_full {
                if *other_name == name {
                    queue.extend(base_names(other_bases));
                }
            }
        }
        let total_depth = seen.len();
        if total_depth >= MAX_INHERITANCE_DEPTH {
            issues.push(issue(
                filepath,
                line_index.line_number(*start),
                Severity::Warning,
                "deep-inheritance",
                package,
                format!(
                    "class '{class_name}' has effective inheritance depth {total_depth} (max {MAX_INHERITANCE_DEPTH}) — use composition"
                ),
            ));
        }
    }
    issues
}

// ── Rule: Message Chains ──────────────────────────────────────────────────────
//
// The one rule in this port that genuinely depends on `ast.walk()`'s actual
// traversal *order*, not just its coverage: Python scans each top-level
// statement's subtree via `ast.walk` (confirmed from CPython's source: a
// `deque`-based breadth-first walk) for the *first* Call/Attribute chain
// exceeding the threshold, then `break`s — so at most one issue per
// top-level statement, and *which* over-threshold chain gets reported (when
// a subtree has more than one) depends on BFS proximity to the statement
// root, not depth-first discovery order.
//
// Rather than hand-roll a real BFS queue over a node type this crate has no
// generic "any node" representation for, this exploits a provable
// equivalence: stable-sorting a depth-first-discovered node list by
// "distance from root" reproduces exact BFS order (verified by hand on
// small trees — whenever two nodes share a depth, DFS preorder and BFS
// agree on their relative order, because DFS visits an entire subtree
// before its next sibling, which is the same order BFS's queue processes
// same-depth nodes in). So: one DFS pass (using the same `Visitor`
// machinery as every other rule, including the comprehension/arguments/
// keyword/withitem gap-fixes from §7.6, so hidden chains are still found)
// records `(depth, chain_depth, position)` for every Call/Attribute;
// stable-sorting by `depth` then taking the first over-threshold entry
// gives the same answer `ast.walk` + `break` would.
struct MessageChainVisitor {
    current_depth: usize,
    candidates: Vec<(usize, i64, rustpython_ast::text_size::TextSize)>,
}

fn chain_depth(expr: &Expr) -> i64 {
    match expr {
        Expr::Call(c) => chain_depth(&c.func),
        Expr::Attribute(a) => 1 + chain_depth(&a.value),
        _ => 0,
    }
}

impl MessageChainVisitor {
    fn record_if_candidate(&mut self, node: &Expr) {
        if matches!(node, Expr::Call(_) | Expr::Attribute(_)) {
            self.candidates
                .push((self.current_depth, chain_depth(node), node.range().start()));
        }
    }
}

impl Visitor for MessageChainVisitor {
    fn visit_stmt(&mut self, node: Stmt) {
        self.current_depth += 1;
        self.generic_visit_stmt(node);
        self.current_depth -= 1;
    }
    fn visit_expr(&mut self, node: Expr) {
        self.record_if_candidate(&node);
        self.current_depth += 1;
        self.generic_visit_expr(node);
        self.current_depth -= 1;
    }
    fn visit_comprehension(&mut self, node: rustpython_ast::Comprehension) {
        self.current_depth += 1;
        walk_comprehension_children(self, node);
        self.current_depth -= 1;
    }
    fn visit_arguments(&mut self, node: Arguments) {
        self.current_depth += 1;
        walk_arguments_children(self, node);
        self.current_depth -= 1;
    }
    fn visit_keyword(&mut self, node: rustpython_ast::Keyword) {
        self.current_depth += 1;
        walk_keyword_children(self, node);
        self.current_depth -= 1;
    }
    fn visit_withitem(&mut self, node: rustpython_ast::WithItem) {
        self.current_depth += 1;
        walk_withitem_children(self, node);
        self.current_depth -= 1;
    }
}

pub fn check_message_chains(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut issues = Vec::new();

    for stmt in module_body(module) {
        let mut visitor = MessageChainVisitor {
            current_depth: 0,
            candidates: Vec::new(),
        };
        visitor.visit_stmt(stmt.clone());

        // Stable sort by depth == BFS order (see block comment above).
        visitor.candidates.sort_by_key(|(depth, _, _)| *depth);
        if let Some((_, depth, pos)) = visitor
            .candidates
            .iter()
            .find(|(_, chain_depth, _)| *chain_depth > crate::config::MAX_MESSAGE_CHAIN_DEPTH)
        {
            issues.push(issue(
                filepath,
                line_index.line_number(*pos),
                Severity::Info,
                "message-chain",
                package,
                format!(
                    "method/attribute chain depth {depth} exceeds {} — split into intermediate variables",
                    crate::config::MAX_MESSAGE_CHAIN_DEPTH
                ),
            ));
        }
    }
    issues
}

// ── Rule: Pass-Through Methods ───────────────────────────────────────────────
//
// `ast.unparse(call_node.func)` in Python only ever needs to render a
// Name/Attribute chain here (the delegation target) — a small dedicated
// renderer for just those two shapes stands in for a full unparser.

fn render_call_target(expr: &Expr) -> String {
    match expr {
        Expr::Name(n) => n.id.to_string(),
        Expr::Attribute(a) => format!("{}.{}", render_call_target(&a.value), a.attr),
        _ => "<expr>".to_string(),
    }
}

fn extract_call(stmt: &Stmt) -> Option<&rustpython_ast::ExprCall> {
    let value = match stmt {
        Stmt::Return(r) => r.value.as_deref()?,
        Stmt::Expr(e) => e.value.as_ref(),
        _ => return None,
    };
    match value {
        Expr::Call(c) => Some(c),
        Expr::Await(a) => match a.value.as_ref() {
            Expr::Call(c) => Some(c),
            _ => None,
        },
        _ => None,
    }
}

fn is_docstring_only(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Expr(e) if matches!(e.value.as_ref(), Expr::Constant(c) if matches!(c.value, Constant::Str(_)))
    )
}

struct PassThroughVisitor<'a> {
    line_index: &'a LineIndex,
    filepath: &'a Path,
    package: &'a str,
    issues: Vec<Issue>,
}
impl<'a> Visitor for PassThroughVisitor<'a> {
    fn visit_stmt_function_def(&mut self, node: rustpython_ast::StmtFunctionDef) {
        self.check(node.name.as_str(), &node.body, node.range().start());
        self.generic_visit_stmt_function_def(node);
    }
    fn visit_stmt_async_function_def(&mut self, node: rustpython_ast::StmtAsyncFunctionDef) {
        self.check(node.name.as_str(), &node.body, node.range().start());
        self.generic_visit_stmt_async_function_def(node);
    }
}
impl<'a> PassThroughVisitor<'a> {
    fn check(&mut self, name: &str, body: &[Stmt], start: rustpython_ast::text_size::TextSize) {
        // Python's own check here is a plain `startswith("__") and
        // endswith("__")` — not the `DUNDER_RE`-based `is_dunder` used by
        // encapsulation-violation above. Two different dunder checks in the
        // original source; replicated as-is rather than unified, since
        // unifying them would be a behavior change, not a faithful port.
        if name.starts_with("__") && name.ends_with("__") {
            return;
        }
        let meaningful: Vec<&Stmt> = body.iter().filter(|s| !is_docstring_only(s)).collect();
        if meaningful.len() != 1 {
            return;
        }
        let Some(call_node) = extract_call(meaningful[0]) else {
            return;
        };

        // Skip `super().method(...)`-style delegation — that's normal
        // inheritance plumbing, not a pass-through smell.
        if let Expr::Attribute(func_attr) = call_node.func.as_ref()
            && let Expr::Call(inner_call) = func_attr.value.as_ref()
            && matches!(inner_call.func.as_ref(), Expr::Name(n) if n.id.as_str() == "super")
        {
            return;
        }

        let args_are_pure = call_node
            .args
            .iter()
            .all(|a| matches!(a, Expr::Name(_) | Expr::Starred(_)));
        let kwargs_are_pure = call_node
            .keywords
            .iter()
            .all(|k| matches!(k.value, Expr::Name(_)));
        if args_are_pure && kwargs_are_pure {
            let target = render_call_target(&call_node.func);
            self.issues.push(issue(
                self.filepath,
                self.line_index.line_number(start),
                Severity::Info,
                "pass-through-method",
                self.package,
                format!(
                    "{name}() is a pure pass-through to '{target}()'. Consider exposing the underlying object."
                ),
            ));
        }
    }
}

pub fn check_pass_through_methods(
    module: &Mod,
    source: &str,
    filepath: &Path,
    package: &str,
) -> Vec<Issue> {
    let line_index = LineIndex::new(source);
    let mut visitor = PassThroughVisitor {
        line_index: &line_index,
        filepath,
        package,
        issues: Vec::new(),
    };
    for stmt in module_body(module) {
        visitor.visit_stmt(stmt.clone());
    }
    visitor.issues
}

// ── Registry ──────────────────────────────────────────────────────────────────

pub type FileCheck = fn(&Mod, &str, &Path, &str) -> Vec<Issue>;

pub const ALL_CHECKS: &[FileCheck] = &[
    check_long_functions,
    check_complexity,
    check_missing_types,
    check_excessive_params,
    check_excessive_returns,
    check_boolean_flag_params,
    check_deep_nesting,
    check_mutable_defaults,
    check_bare_except,
    check_missing_else,
    check_unused_imports,
    check_swallowed_exceptions,
    check_star_imports,
    check_global_mutations,
    check_scope_mutations,
    check_dead_code,
    check_excessive_decorators,
    check_lazy_class,
    check_magic_numbers,
    check_untyped_dicts,
    check_duplicate_branches,
    check_encapsulation_violations,
    check_god_class,
    check_transport_in_library,
    check_god_module,
    check_deep_inheritance,
    check_pass_through_methods,
    check_message_chains,
];

/// Checks needing the package root — not part of `ALL_CHECKS`, called
/// directly by `scanner.rs` alongside it.
pub type PkgRootCheck = fn(&Mod, &str, &Path, &str, &Path) -> Vec<Issue>;

pub const PKG_ROOT_CHECKS: &[PkgRootCheck] = &[check_layer_violations, check_circular_imports];

#[cfg(test)]
mod missing_else_tests {
    use super::check_missing_else;
    use std::path::Path;

    fn issues_for(source: &str) -> Vec<crate::models::Issue> {
        let module = rustpython_parser::parse(source, rustpython_parser::Mode::Module, "f.py")
            .expect("test source must parse");
        check_missing_else(&module, source, Path::new("f.py"), "pkg")
    }

    #[test]
    fn flags_nontrivial_if() {
        let issues = issues_for("def f():\n    if x:\n        a = 1\n        b = 2\n");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].rule, "missing-else");
    }

    #[test]
    fn allows_if_else() {
        let issues = issues_for(
            "def f():\n    if x:\n        a = 1\n        b = 2\n    else:\n        pass\n",
        );
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_single_statement_if() {
        let issues = issues_for("def f():\n    if x:\n        a = 1\n");
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_if_elif() {
        let issues = issues_for(
            "def f():\n    if x:\n        a = 1\n        b = 2\n    elif y:\n        pass\n",
        );
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_guard_clause_return() {
        let issues =
            issues_for("def f():\n    if x:\n        a = 1\n        return\n    return a\n");
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_guard_clause_raise() {
        let issues =
            issues_for("def f():\n    if x:\n        a = 1\n        raise ValueError(a)\n");
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_loop_skip_continue() {
        let issues = issues_for(
            "def f():\n    for x in y:\n        if x in seen:\n            a = 1\n            continue\n",
        );
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_loop_skip_break() {
        let issues = issues_for(
            "def f():\n    for x in y:\n        if x is done:\n            a = 1\n            break\n",
        );
        assert!(issues.is_empty());
    }

    #[test]
    fn still_flags_non_terminated_if() {
        // Sanity check: the terminator narrowing must not swallow genuine
        // hits — a 2+ statement if with no else/elif/terminator is flagged.
        let issues =
            issues_for("def f():\n    if x:\n        a = 1\n        b = 2\n    return a + b\n");
        assert_eq!(issues.len(), 1);
    }
}

#[cfg(test)]
mod lazy_class_tests {
    use super::check_lazy_class;
    use std::path::Path;

    fn issues_for(source: &str) -> Vec<crate::models::Issue> {
        let module = rustpython_parser::parse(source, rustpython_parser::Mode::Module, "f.py")
            .expect("test source must parse");
        check_lazy_class(&module, source, Path::new("f.py"), "pkg")
    }

    #[test]
    fn flags_zero_methods() {
        let issues = issues_for("class C:\n    x = 1\n");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].rule, "lazy-class");
        assert!(issues[0].message.contains("0 method"));
    }

    #[test]
    fn flags_one_method() {
        let issues = issues_for("class C:\n    def f(self):\n        pass\n");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("1 method"));
    }

    #[test]
    fn allows_two_methods() {
        let issues = issues_for(
            "class C:\n    def f(self):\n        pass\n    def g(self):\n        pass\n",
        );
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_pydantic_base_model() {
        let issues = issues_for("class C(BaseModel):\n    x: int = 1\n");
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_pydantic_base_model_qualified() {
        let issues = issues_for("class C(pydantic.BaseModel):\n    x: int = 1\n");
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_pydantic_base_settings() {
        let issues = issues_for("class C(BaseSettings):\n    x: int = 1\n");
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_dataclass_decorator() {
        let issues = issues_for("@dataclass\nclass C:\n    x: int = 1\n");
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_dataclass_decorator_with_args() {
        let issues = issues_for("@dataclass(frozen=True)\nclass C:\n    x: int = 1\n");
        assert!(issues.is_empty());
    }

    #[test]
    fn still_flags_unrelated_base() {
        // Sanity check: the pydantic/dataclass exemption must not swallow
        // genuine hits — an unrelated base class doesn't grant an exemption.
        let issues = issues_for("class C(SomeOtherBase):\n    x = 1\n");
        assert_eq!(issues.len(), 1);
    }
}
