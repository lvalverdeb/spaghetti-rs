//! Cross-file, whole-package checks — Phase 3 of the port proposal's §10
//! plan: `import-cycle`, `duplicate-function-body`, `sync-async-duplication`.
//! Mirrors `spaghetti/checks/package_level.py`.

use crate::ast_helpers::{
    FuncNode, LineIndex, collect_functions, collect_functions_with_class_context, dump_stmts,
    is_trivial_body, line_count,
};
use crate::config::{MIN_TWIN_FUNCTION_LINES, allowed_import_prefix};
use crate::models::{Issue, Severity, display_path};
use crate::similarity::sequence_matcher_ratio;
use crate::unparse::unparse_function;
use rustpython_ast::{Mod, Stmt, Visitor};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// One parsed file, as package-level checks need it: path, source (for
/// byte-offset → line-number conversion), and the parsed module.
pub struct ParsedFile {
    pub path: PathBuf,
    pub source: String,
    pub module: Mod,
}

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
        reason: None,
    }
}

// ── Import Cycles (real cycle detection via DFS) ─────────────────────────────

/// Returns `(dotted_module_name, dotted_containing_package_name)`, relative
/// to `pkg_root`'s *parent* — mirrors `_module_and_package_for`.
fn module_and_package_for(pkg_root: &Path, filepath: &Path) -> (String, String) {
    let anchor = pkg_root.parent().unwrap_or(pkg_root);
    let rel = filepath
        .strip_prefix(anchor)
        .unwrap_or(filepath)
        .with_extension("");
    let parts: Vec<String> = rel
        .iter()
        .map(|c| c.to_string_lossy().into_owned())
        .collect();
    if parts.last().map(|s| s.as_str()) == Some("__init__") {
        let module = parts[..parts.len() - 1].join(".");
        (module.clone(), module)
    } else {
        let module = parts.join(".");
        let package = if parts.len() > 1 {
            parts[..parts.len() - 1].join(".")
        } else {
            String::new()
        };
        (module, package)
    }
}

/// Resolves an `ImportFrom` to the dotted module name(s) it depends on —
/// mirrors `_import_targets`, including the relative-import (`level`) math.
fn import_targets(package: &str, node: &rustpython_ast::StmtImportFrom) -> Vec<String> {
    let level = node.level.as_ref().map(|l| l.to_usize()).unwrap_or(0);
    if level == 0 {
        return node
            .module
            .as_ref()
            .map(|m| vec![m.to_string()])
            .unwrap_or_default();
    }
    let mut pkg_parts: Vec<&str> = if package.is_empty() {
        Vec::new()
    } else {
        package.split('.').collect()
    };
    let up = level - 1;
    if up > 0 {
        if up <= pkg_parts.len() {
            pkg_parts.truncate(pkg_parts.len() - up);
        } else {
            pkg_parts.clear();
        }
    }
    let base = pkg_parts.join(".");
    if let Some(m) = &node.module {
        vec![if base.is_empty() {
            m.to_string()
        } else {
            format!("{base}.{m}")
        }]
    } else {
        node.names
            .iter()
            .map(|a| {
                if base.is_empty() {
                    a.name.to_string()
                } else {
                    format!("{base}.{}", a.name)
                }
            })
            .collect()
    }
}

fn is_type_checking_guard(test: &rustpython_ast::Expr) -> bool {
    use rustpython_ast::Expr;
    match test {
        Expr::Name(n) => n.id.as_str() == "TYPE_CHECKING",
        Expr::Attribute(a) => a.attr.as_str() == "TYPE_CHECKING",
        _ => false,
    }
}

enum ImportNode {
    Import(rustpython_ast::StmtImport),
    ImportFrom(rustpython_ast::StmtImportFrom),
}

/// Imports that actually execute at module-import time — mirrors
/// `_module_level_imports`: stops at nested function/lambda boundaries and
/// skips `if TYPE_CHECKING:` guards entirely (no recursion into either).
struct ModuleLevelImportCollector {
    imports: Vec<ImportNode>,
}
impl Visitor for ModuleLevelImportCollector {
    fn visit_stmt_function_def(&mut self, _node: rustpython_ast::StmtFunctionDef) {}
    fn visit_stmt_async_function_def(&mut self, _node: rustpython_ast::StmtAsyncFunctionDef) {}
    fn visit_expr_lambda(&mut self, _node: rustpython_ast::ExprLambda) {}
    fn visit_stmt_if(&mut self, node: rustpython_ast::StmtIf) {
        if is_type_checking_guard(&node.test) {
            return;
        }
        self.generic_visit_stmt_if(node);
    }
    fn visit_stmt_import(&mut self, node: rustpython_ast::StmtImport) {
        self.imports.push(ImportNode::Import(node));
    }
    fn visit_stmt_import_from(&mut self, node: rustpython_ast::StmtImportFrom) {
        self.imports.push(ImportNode::ImportFrom(node));
    }
}

fn module_level_imports(module_body: &[Stmt]) -> Vec<ImportNode> {
    let mut visitor = ModuleLevelImportCollector {
        imports: Vec::new(),
    };
    for stmt in module_body {
        visitor.visit_stmt(stmt.clone());
    }
    visitor.imports
}

pub fn check_import_cycles_pkg(
    pkg_name: &str,
    files: &[ParsedFile],
    pkg_root: &Path,
) -> Vec<Issue> {
    let Some(prefix) = allowed_import_prefix(pkg_name) else {
        return Vec::new();
    };
    let stem = prefix.trim_end_matches('.');

    let mut graph: HashMap<String, HashSet<String>> = HashMap::new();
    let mut file_for_module: HashMap<String, &Path> = HashMap::new();

    for f in files {
        let (mod_name, package) = module_and_package_for(pkg_root, &f.path);
        file_for_module.insert(mod_name.clone(), f.path.as_path());
        for node in module_level_imports(module_body(&f.module)) {
            match node {
                ImportNode::ImportFrom(n) => {
                    for resolved in import_targets(&package, &n) {
                        if resolved == stem || resolved.starts_with(&format!("{stem}.")) {
                            graph.entry(mod_name.clone()).or_default().insert(resolved);
                        }
                    }
                }
                ImportNode::Import(n) => {
                    for alias in &n.names {
                        let name = alias.name.as_str();
                        if name == stem || name.starts_with(&format!("{stem}.")) {
                            graph
                                .entry(mod_name.clone())
                                .or_default()
                                .insert(name.to_string());
                        }
                    }
                }
            }
        }
    }

    let mut issues = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut reported: HashSet<Vec<String>> = HashSet::new();
    // Sorted rather than raw `HashMap` iteration — Rust's hash-map order is
    // randomized per-process, which made this rule's output (which module
    // "wins" as the reported cycle's file, when adjacency order affects DFS
    // discovery) non-reproducible across runs of the same binary on the
    // same input. Found via a real repeatability check, not assumed.
    let mut module_names: Vec<String> = graph.keys().cloned().collect();
    module_names.sort();

    for start in module_names {
        if visited.contains(&start) {
            continue;
        }
        // Explicit stack-based DFS (mirrors Python's recursive version,
        // including its on_stack cycle-membership check) — avoids Rust
        // recursion-depth concerns on a real import graph.
        let mut stack: Vec<String> = vec![start.clone()];
        let mut on_stack: HashSet<String> = HashSet::from([start.clone()]);
        visited.insert(start.clone());
        let neighbors_of = |graph: &HashMap<String, HashSet<String>>, m: &str| -> Vec<String> {
            let mut v: Vec<String> = graph
                .get(m)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            v.sort();
            v
        };
        let mut frames: Vec<Vec<String>> = vec![neighbors_of(&graph, &start)];

        while let Some(frame) = frames.last_mut() {
            let Some(neighbor) = frame.pop() else {
                frames.pop();
                let done = stack.pop().unwrap();
                on_stack.remove(&done);
                continue;
            };
            if on_stack.contains(&neighbor) {
                let cycle_start = stack.iter().position(|m| m == &neighbor).unwrap();
                let mut cycle: Vec<String> = stack[cycle_start..].to_vec();
                cycle.push(neighbor.clone());
                let mut key: Vec<String> = cycle.clone();
                key.sort();
                key.dedup();
                if !reported.contains(&key) {
                    reported.insert(key);
                    if let Some(&loc) = file_for_module.get(&stack[cycle_start]) {
                        issues.push(issue(
                            loc,
                            1,
                            Severity::Error,
                            "import-cycle",
                            pkg_name,
                            format!(
                                "Circular import: {} — extract a shared abstraction (e.g. a \
                                 typing.Protocol) both sides can depend on, and inject it \
                                 instead of importing directly to break the cycle \
                                 (Dependency Inversion Principle / Dependency Injection)",
                                cycle.join(" \u{2192} ")
                            ),
                        ));
                    }
                }
            } else if !visited.contains(&neighbor) {
                visited.insert(neighbor.clone());
                stack.push(neighbor.clone());
                on_stack.insert(neighbor.clone());
                frames.push(neighbors_of(&graph, &neighbor));
            }
        }
    }

    issues
}

// ── Duplicate Function Bodies (whole-package) ────────────────────────────────

// A body needs at least this many occurrences to be a "duplicate" at all.
const MIN_DUPLICATE_OCCURRENCES: usize = 2;

pub fn check_duplicate_functions_pkg(
    pkg_name: &str,
    files: &[ParsedFile],
    min_lines: usize,
) -> Vec<Issue> {
    let mut groups: HashMap<String, Vec<(&Path, String, usize)>> = HashMap::new();

    for f in files {
        let line_index = LineIndex::new(&f.source);
        for func in collect_functions(module_body(&f.module)) {
            let lines = line_count(&line_index, func.start, func.end());
            if lines < min_lines || is_trivial_body(func.body()) {
                continue;
            }
            let key = dump_stmts(func.body());
            let line_no = line_index.line_number(func.start);
            groups
                .entry(key)
                .or_default()
                .push((f.path.as_path(), func.name.clone(), line_no));
        }
    }

    let mut issues = Vec::new();
    for (_key, mut occurrences) in groups {
        if occurrences.len() < MIN_DUPLICATE_OCCURRENCES {
            continue;
        }
        occurrences.sort_by(|a, b| (a.0.to_string_lossy(), a.2).cmp(&(b.0.to_string_lossy(), b.2)));
        let locations: Vec<String> = occurrences
            .iter()
            .map(|(fp, name, line_no)| format!("{}:{line_no} ({name})", display_path(fp, None)))
            .collect();
        let (first_fp, _, first_line) = occurrences[0];
        issues.push(issue(
            first_fp,
            first_line,
            Severity::Warning,
            "duplicate-function-body",
            pkg_name,
            format!(
                "Identical body in {} places: {}",
                occurrences.len(),
                locations.join(", ")
            ),
        ));
    }
    // `groups` is a plain `HashMap`, whose iteration order is randomized
    // per-process — without this, the resulting issue order (and thus
    // which duplicate group appears first) was non-reproducible across
    // runs of the same binary on the same input. Sorting by (file, line)
    // gives a stable, deterministic order; it doesn't need to match
    // Python's own dict-insertion-order output, just be repeatable.
    issues.sort_by_key(|a| (a.file.clone(), a.line));
    issues
}

// ── Sync/Async Twin Duplication ──────────────────────────────────────────────

/// Plausible sync/async counterpart names for `name` — mirrors
/// `_twin_candidates`. Returns a sorted `Vec`, not a `HashSet`: iteration
/// order needs to be deterministic (a `HashSet`'s isn't, across runs of the
/// same binary — found via a real repeatability check), even though the
/// candidates themselves are still deduplicated first.
fn twin_candidates(name: &str) -> Vec<String> {
    let mut candidates: HashSet<String> = [
        format!("a{name}"),
        format!("{name}_async"),
        format!("async_{name}"),
        format!("_async_{name}"),
    ]
    .into_iter()
    .collect();
    if name.starts_with('a') && name.len() > 1 {
        candidates.insert(name[1..].to_string());
    }
    if let Some(stripped) = name.strip_prefix("_async_") {
        candidates.insert(stripped.to_string());
    }
    if let Some(stripped) = name.strip_suffix("_async") {
        candidates.insert(stripped.to_string());
    }
    if let Some(stripped) = name.strip_prefix("async_") {
        candidates.insert(stripped.to_string());
    }
    if let Some(stripped) = name.strip_suffix("_sync") {
        candidates.insert(stripped.to_string());
        candidates.insert(format!("{stripped}_async"));
    }
    let mut candidates: Vec<String> = candidates.into_iter().collect();
    candidates.sort();
    candidates
}

pub fn check_sync_async_twins_pkg(
    pkg_name: &str,
    files: &[ParsedFile],
    min_ratio: f64,
) -> Vec<Issue> {
    // Insertion-ordered, matching Python's dict (insertion order = file-walk
    // order, itself sorted by `scanner.rs`) — deliberately not a plain
    // `HashMap`. `reported`'s dedup key doesn't include the file path (same
    // as Python's own `pair_key`), so when two different files each define
    // a same-named class with same-named twin methods (found for real:
    // two separate `class FrameEnricher(Protocol)` definitions, in
    // `enrichment/async_enricher.py` and `pipelines/base.py`, confirmed via
    // the conformance diff), only the file processed *first* gets reported
    // — a genuine Python quirk, not a bug to fix, but one that requires
    // matching Python's deterministic insertion order to reproduce which
    // file "wins", rather than an arbitrary hash-map iteration order.
    let mut scope_functions: indexmap::IndexMap<
        (&Path, Option<String>),
        indexmap::IndexMap<String, &FuncNode>,
    > = indexmap::IndexMap::new();
    let mut owned_funcs: Vec<(&Path, Option<String>, FuncNode)> = Vec::new();

    for f in files {
        for (class_name, func) in collect_functions_with_class_context(module_body(&f.module)) {
            owned_funcs.push((f.path.as_path(), class_name, func));
        }
    }
    for (path, class_name, func) in &owned_funcs {
        scope_functions
            .entry((*path, class_name.clone()))
            .or_default()
            .insert(func.name.clone(), func);
    }

    // Need a LineIndex per file to compute line numbers for the min-4-lines
    // filter and the reported position.
    let line_indices: HashMap<&Path, LineIndex> = files
        .iter()
        .map(|f| (f.path.as_path(), LineIndex::new(&f.source)))
        .collect();

    let mut issues = Vec::new();
    let mut reported: HashSet<Vec<(String, String)>> = HashSet::new();

    for ((filepath, class_name), by_name) in &scope_functions {
        let line_index = &line_indices[filepath];
        for (name, func) in by_name {
            let lines = line_count(line_index, func.start, func.end());
            if lines < MIN_TWIN_FUNCTION_LINES {
                continue;
            }
            for candidate in twin_candidates(name) {
                if &candidate == name {
                    continue;
                }
                let Some(other_func) = by_name.get(&candidate) else {
                    continue;
                };
                let class_key = class_name.clone().unwrap_or_default();
                let mut pair_key = vec![
                    (name.clone(), class_key.clone()),
                    (candidate.clone(), class_key),
                ];
                pair_key.sort();
                if reported.contains(&pair_key) {
                    continue;
                }
                let ratio = sequence_matcher_ratio(
                    &unparse_function(&func.stmt),
                    &unparse_function(&other_func.stmt),
                );
                if ratio >= min_ratio {
                    reported.insert(pair_key);
                    let line = line_index
                        .line_number(func.start)
                        .min(line_index.line_number(other_func.start));
                    issues.push(issue(
                        filepath,
                        line,
                        Severity::Warning,
                        "sync-async-duplication",
                        pkg_name,
                        format!(
                            "{name}() and {candidate}() are {:.0}% similar — likely copy-pasted sync/async twins; extract a shared helper for the non-blocking parts",
                            ratio * 100.0
                        ),
                    ));
                }
            }
        }
    }
    issues
}
