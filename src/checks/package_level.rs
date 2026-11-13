//! Cross-file, whole-package checks (`orphan-interface`,
//! `duplicate-function-body`, `sync-async-duplication`) plus the
//! import-resolution helpers the workspace-level graph reuses — mirrors
//! `spaghetti/checks/package_level.py`.

use crate::ast_helpers::{
    FuncNode, LineIndex, NodeLoc, collect_classes_bfs, collect_functions,
    collect_functions_with_class_context, dump_stmts, is_trivial_body, line_count,
};
use crate::config::{is_dunder, thresholds};
use crate::models::{Issue, Severity, display_path};
use crate::pyast::Node;
use crate::similarity::sequence_matcher_ratio;
use crate::unparse::unparse_function;
use indexmap::IndexMap;
use rustpython_ast::{Mod, Ranged, Stmt};
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
    Issue::new(filepath, line, severity, rule, package, message)
}

/// An issue located at a node's span — mirrors `line=node.lineno, **_loc(node)`.
fn issue_at(
    filepath: &Path,
    loc: NodeLoc,
    severity: Severity,
    rule: &'static str,
    package: &str,
    message: String,
) -> Issue {
    let mut issue = Issue::new(filepath, loc.line, severity, rule, package, message);
    issue.column = Some(loc.column);
    issue.end_line = Some(loc.end_line);
    issue.end_column = Some(loc.end_column);
    issue
}

/// Dotted prefix of the package's own modules, e.g. `"my_lib."` — mirrors
/// `package_level.py::_package_prefix`.
///
/// Derived from the registered package directory's name, which is also how
/// `module_and_package_for` names modules — so an import is intra-package
/// exactly when it starts with this.
pub(crate) fn package_prefix(pkg_root: &Path) -> String {
    let name = pkg_root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("{name}.")
}

// ── Import resolution (shared with `workspace_level`) ────────────────────────

/// Returns `(dotted_module_name, dotted_containing_package_name)`, relative
/// to `pkg_root`'s *parent* — mirrors `_module_and_package_for`.
pub(crate) fn module_and_package_for(pkg_root: &Path, filepath: &Path) -> (String, String) {
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
///
/// `from pkg import name` binds the *submodule* `pkg.name` when one exists,
/// so with `modules` (the package's known module names) the edge points at
/// that submodule rather than at `pkg`'s `__init__` — the ubiquitous
/// `__init__` re-export pattern is then not a cycle.
pub(crate) fn import_targets(
    package: &str,
    level: usize,
    module: Option<&str>,
    names: &[String],
    modules: &HashSet<String>,
) -> Vec<String> {
    let base = if level == 0 {
        module.map(str::to_string).unwrap_or_default()
    } else {
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
        let joined = pkg_parts.join(".");
        match module {
            Some(m) if joined.is_empty() => m.to_string(),
            Some(m) => format!("{joined}.{m}"),
            None => joined,
        }
    };
    if base.is_empty() {
        return names.to_vec();
    }
    let mut targets: Vec<String> = names
        .iter()
        .map(|name| {
            let candidate = format!("{base}.{name}");
            if modules.contains(&candidate) {
                candidate
            } else {
                base.clone()
            }
        })
        .collect();
    targets.sort();
    targets.dedup();
    targets
}

fn is_type_checking_guard(test: &rustpython_ast::Expr) -> bool {
    use rustpython_ast::Expr;
    match test {
        Expr::Name(n) => n.id.as_str() == "TYPE_CHECKING",
        Expr::Attribute(a) => a.attr.as_str() == "TYPE_CHECKING",
        _ => false,
    }
}

/// `if __name__ == "__main__":` — never executes when the module is imported.
/// Mirrors `_is_main_guard`: any `Compare` whose left operand is `__name__`.
fn is_main_guard(test: &rustpython_ast::Expr) -> bool {
    use rustpython_ast::Expr;
    matches!(test, Expr::Compare(c) if matches!(c.left.as_ref(), Expr::Name(n) if n.id.as_str() == "__name__"))
}

pub(crate) enum ImportNode {
    Import(rustpython_ast::StmtImport),
    ImportFrom(rustpython_ast::StmtImportFrom),
}

/// Imports that actually execute at module-import time — mirrors
/// `_module_level_imports`: stops at nested function/lambda boundaries and
/// skips `if TYPE_CHECKING:` and `if __name__ == "__main__":` guards
/// entirely (no recursion into any of them).
pub(crate) fn module_level_imports(module_body: &[Stmt]) -> Vec<ImportNode> {
    let mut found = Vec::new();
    let mut stack: Vec<Node<'_>> = module_body.iter().rev().map(Node::Stmt).collect();
    while let Some(child) = stack.pop() {
        match child {
            Node::Stmt(Stmt::FunctionDef(_) | Stmt::AsyncFunctionDef(_))
            | Node::Expr(rustpython_ast::Expr::Lambda(_)) => continue,
            Node::Stmt(Stmt::If(i))
                if is_type_checking_guard(&i.test) || is_main_guard(&i.test) =>
            {
                continue;
            }
            Node::Stmt(Stmt::Import(i)) => found.push(ImportNode::Import(i.clone())),
            Node::Stmt(Stmt::ImportFrom(i)) => found.push(ImportNode::ImportFrom(i.clone())),
            _ => {}
        }
        stack.extend(child.children().into_iter().rev());
    }
    found
}

// ── Orphan Interfaces (whole-package) ────────────────────────────────────────

/// `base.id` for a `Name`, `base.attr` for an `Attribute`, else `None` —
/// the two spellings the Python check recognises.
fn simple_name(expr: &rustpython_ast::Expr) -> Option<&str> {
    match expr {
        rustpython_ast::Expr::Name(n) => Some(n.id.as_str()),
        rustpython_ast::Expr::Attribute(a) => Some(a.attr.as_str()),
        _ => None,
    }
}

/// Detect abstract classes with exactly one concrete implementation —
/// mirrors `package_level.py::check_orphan_interfaces_pkg`.
///
/// This is a classic 'Speculative Generality' code smell. If an interface
/// only exists to be implemented by a single class, it is likely adding
/// mental overhead without providing any polymorphic value.
pub fn check_orphan_interfaces_pkg(pkg_name: &str, files: &[ParsedFile]) -> Vec<Issue> {
    // Insertion-ordered like Python's dict: a same-named interface in a
    // later file keeps the first file's position but takes its location.
    let mut interfaces: IndexMap<&str, (&Path, &rustpython_ast::StmtClassDef, &str)> =
        IndexMap::new();
    let mut implementations: HashMap<&str, Vec<&str>> = HashMap::new();

    for file in files {
        for class in collect_classes_bfs(module_body(&file.module)) {
            let mut is_abstract = false;
            for base in &class.bases {
                match simple_name(base) {
                    Some("ABC") | Some("Protocol") => is_abstract = true,
                    Some(base_name) if !base_name.is_empty() => {
                        implementations
                            .entry(base_name)
                            .or_default()
                            .push(class.name.as_str());
                    }
                    _ => {}
                }
            }
            for keyword in &class.keywords {
                if keyword
                    .arg
                    .as_ref()
                    .is_some_and(|a| a.as_str() == "metaclass")
                    && simple_name(&keyword.value) == Some("ABCMeta")
                {
                    is_abstract = true;
                }
            }
            if is_abstract {
                interfaces.insert(
                    class.name.as_str(),
                    (file.path.as_path(), class, file.source.as_str()),
                );
            }
        }
    }

    let mut issues = Vec::new();
    for (iface_name, (filepath, class, source)) in &interfaces {
        let impls = implementations
            .get(iface_name)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if let [impl_name] = impls {
            let line_index = LineIndex::new(source);
            issues.push(issue_at(
                filepath,
                line_index.node_loc(class.range()),
                Severity::Info,
                "orphan-interface",
                pkg_name,
                format!(
                    "Interface '{iface_name}' has exactly one implementation ('{impl_name}'). \
                     Consider removing the abstraction."
                ),
            ));
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
    // Insertion-ordered like Python's dict: issues come out in the order each
    // duplicate group was first seen, which (with `collect_functions` in
    // `ast.walk` order) is the order the original reports them in.
    let mut groups: IndexMap<String, Vec<(&Path, String, NodeLoc)>> = IndexMap::new();

    for f in files {
        let line_index = LineIndex::new(&f.source);
        for func in collect_functions(module_body(&f.module)) {
            let lines = line_count(&line_index, func.start, func.end());
            if lines < min_lines || is_trivial_body(func.body()) {
                continue;
            }
            if is_dunder(&func.name) {
                continue; // `__repr__`/`__eq__` across sibling classes are protocol hooks
            }
            let key = dump_stmts(func.body());
            groups.entry(key).or_default().push((
                f.path.as_path(),
                func.name.clone(),
                line_index.node_loc(func.range()),
            ));
        }
    }

    let mut issues = Vec::new();
    for (_key, mut occurrences) in groups {
        if occurrences.len() < MIN_DUPLICATE_OCCURRENCES {
            continue;
        }
        occurrences.sort_by(|a, b| {
            (a.0.to_string_lossy(), a.2.line).cmp(&(b.0.to_string_lossy(), b.2.line))
        });
        let locations: Vec<String> = occurrences
            .iter()
            .map(|(fp, name, loc)| format!("{}:{} ({name})", display_path(fp, None), loc.line))
            .collect();
        let (first_fp, _, first_loc) = occurrences[0];
        issues.push(issue_at(
            first_fp,
            first_loc,
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
    let min_twin_function_lines = thresholds().min_twin_function_lines;
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

    let files_by_path: HashMap<&Path, &ParsedFile> =
        files.iter().map(|f| (f.path.as_path(), f)).collect();
    let mut issues = Vec::new();
    let mut reported: HashSet<Vec<(String, String)>> = HashSet::new();

    for ((filepath, class_name), by_name) in &scope_functions {
        let line_index = &line_indices[filepath];
        for (name, func) in by_name {
            let lines = line_count(line_index, func.start, func.end());
            if lines < min_twin_function_lines {
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
                    &unparse_function(&func.stmt, &files_by_path[filepath].source),
                    &unparse_function(&other_func.stmt, &files_by_path[filepath].source),
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

#[cfg(test)]
mod calibration_tests {
    //! Mirrors the package-level half of the Python repo's tests/test_calibration.py.
    use super::{ParsedFile, check_duplicate_functions_pkg};
    use std::path::PathBuf;

    const ROOT: &str = "/tmp/pkg";

    fn pkg(files: &[(&str, &str)]) -> Vec<ParsedFile> {
        let mut parsed: Vec<ParsedFile> = files
            .iter()
            .map(|(name, source)| {
                let path = PathBuf::from(ROOT).join(name);
                let module =
                    rustpython_parser::parse(source, rustpython_parser::Mode::Module, name)
                        .expect("test source must parse");
                ParsedFile {
                    path,
                    source: source.to_string(),
                    module,
                }
            })
            .collect();
        parsed.sort_by(|a, b| a.path.cmp(&b.path));
        parsed
    }

    #[test]
    fn duplicate_function_body_skips_dunder_protocol_hooks() {
        let body = "    def __repr__(self):\n        a = 1\n        b = 2\n        c = 3\n        \
                    return f'{a}{b}{c}'\n";
        let a = format!("class A:\n{body}");
        let b = format!("class B:\n{body}");
        let files = pkg(&[("a.py", &a), ("b.py", &b)]);
        assert!(check_duplicate_functions_pkg("pkg", &files, 5).is_empty());
        let files = pkg(&[
            ("a.py", &a.replace("__repr__", "render")),
            ("b.py", &b.replace("__repr__", "render")),
        ]);
        assert_eq!(check_duplicate_functions_pkg("pkg", &files, 5).len(), 1);
    }
}
