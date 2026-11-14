//! Cross-file, whole-package checks (`orphan-interface`,
//! `duplicate-function-body`, `sync-async-duplication`) plus the
//! import-resolution helpers the workspace-level graph reuses — mirrors
//! `spaghetti/checks/package_level.py`.
//!
//! The checks never see a tree. A worker that has just parsed a file records
//! the little the checks need about its functions and classes (`FileFacts`)
//! while the tree is in hand; the parent combines facts across files. Facts
//! carry raw measurements (line counts, similarity ratios) and the checks
//! apply the thresholds, so one set of facts serves any
//! `--min-duplicate-lines` or `--twin-similarity` and can live in the file
//! cache.

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
use rustpython_ast::{Ranged, Stmt};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

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

// ── Per-file facts ───────────────────────────────────────────────────────────

/// A function worth comparing for duplication: not a stub, not a dunder.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionFact {
    pub name: String,
    pub loc: NodeLoc,
    pub lines: usize,
    /// SHA-1 of the dumped body statements; equal bodies hash equal.
    pub body: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClassFact {
    pub name: String,
    pub loc: NodeLoc,
    pub bases: Vec<String>,
    pub abstract_: bool,
}

/// `name` has a plausible sync/async counterpart in the same scope.
#[derive(Debug, Clone, PartialEq)]
pub struct TwinFact {
    pub name: String,
    pub counterpart: String,
    /// Enclosing class name, or `""` at module level.
    pub scope: String,
    pub line: usize,
    /// Line count of `name`'s definition (the threshold applies to it alone).
    pub lines: usize,
    pub ratio: f64,
}

/// What the package-level checks need about one file — mirrors
/// `package_level.FileFacts`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FileFacts {
    pub functions: Vec<FunctionFact>,
    pub classes: Vec<ClassFact>,
    pub twins: Vec<TwinFact>,
}

impl FileFacts {
    /// The cache representation; the same shape as the Python port's.
    pub fn to_json(&self) -> Value {
        let functions: Vec<Value> = self
            .functions
            .iter()
            .map(|f| {
                json!([
                    f.name,
                    f.loc.line,
                    f.loc.column,
                    f.loc.end_line,
                    f.loc.end_column,
                    f.lines,
                    f.body
                ])
            })
            .collect();
        let classes: Vec<Value> = self
            .classes
            .iter()
            .map(|c| {
                json!([
                    c.name,
                    c.loc.line,
                    c.loc.column,
                    c.loc.end_line,
                    c.loc.end_column,
                    c.bases,
                    c.abstract_
                ])
            })
            .collect();
        let twins: Vec<Value> = self
            .twins
            .iter()
            .map(|t| json!([t.name, t.counterpart, t.scope, t.line, t.lines, t.ratio]))
            .collect();
        json!({"functions": functions, "classes": classes, "twins": twins})
    }

    /// `None` for anything that does not have exactly the expected shape.
    pub fn from_json(data: &Value) -> Option<FileFacts> {
        fn int(v: &Value) -> Option<usize> {
            usize::try_from(v.as_u64()?).ok()
        }
        fn loc(v: &[Value]) -> Option<NodeLoc> {
            Some(NodeLoc {
                line: int(&v[0])?,
                column: int(&v[1])?,
                end_line: int(&v[2])?,
                end_column: int(&v[3])?,
            })
        }
        let functions = data
            .get("functions")?
            .as_array()?
            .iter()
            .map(|f| {
                let f = f.as_array()?;
                if f.len() != 7 {
                    return None;
                }
                Some(FunctionFact {
                    name: f[0].as_str()?.to_string(),
                    loc: loc(&f[1..5])?,
                    lines: int(&f[5])?,
                    body: f[6].as_str()?.to_string(),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let classes = data
            .get("classes")?
            .as_array()?
            .iter()
            .map(|c| {
                let c = c.as_array()?;
                if c.len() != 7 {
                    return None;
                }
                Some(ClassFact {
                    name: c[0].as_str()?.to_string(),
                    loc: loc(&c[1..5])?,
                    bases: c[5]
                        .as_array()?
                        .iter()
                        .map(|b| b.as_str().map(str::to_string))
                        .collect::<Option<Vec<_>>>()?,
                    abstract_: c[6].as_bool()?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let twins = data
            .get("twins")?
            .as_array()?
            .iter()
            .map(|t| {
                let t = t.as_array()?;
                if t.len() != 6 {
                    return None;
                }
                Some(TwinFact {
                    name: t[0].as_str()?.to_string(),
                    counterpart: t[1].as_str()?.to_string(),
                    scope: t[2].as_str()?.to_string(),
                    line: int(&t[3])?,
                    lines: int(&t[4])?,
                    ratio: t[5].as_f64()?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(FileFacts {
            functions,
            classes,
            twins,
        })
    }
}

/// `base.id` for a `Name`, `base.attr` for an `Attribute`, else `None` —
/// the two spellings the Python check recognises.
fn simple_name(expr: &rustpython_ast::Expr) -> Option<&str> {
    match expr {
        rustpython_ast::Expr::Name(n) => Some(n.id.as_str()),
        rustpython_ast::Expr::Attribute(a) => Some(a.attr.as_str()),
        _ => None,
    }
}

const ABSTRACT_BASES: [&str; 2] = ["ABC", "Protocol"];

/// `_base_names_of`: the `Name`/`Attribute` bases, in order.
fn base_names_of(class: &rustpython_ast::StmtClassDef) -> Vec<String> {
    class
        .bases
        .iter()
        .filter_map(simple_name)
        .map(str::to_string)
        .collect()
}

fn has_abc_metaclass(class: &rustpython_ast::StmtClassDef) -> bool {
    class.keywords.iter().any(|keyword| {
        keyword
            .arg
            .as_ref()
            .is_some_and(|a| a.as_str() == "metaclass")
            && simple_name(&keyword.value) == Some("ABCMeta")
    })
}

/// Record the facts of one parsed file — mirrors `collect_facts`. Functions
/// and classes come out in `ast.walk` (breadth-first) order, twins in the
/// pre-order of `_walk_with_class_context`.
pub fn collect_facts(module_body: &[Stmt], source: &str, line_index: &LineIndex) -> FileFacts {
    let mut facts = FileFacts::default();
    for func in collect_functions(module_body) {
        if is_trivial_body(func.body()) || is_dunder(&func.name) {
            continue; // `__repr__`/`__eq__` across sibling classes are protocol hooks
        }
        let digest = Sha1::digest(dump_stmts(func.body()).as_bytes());
        facts.functions.push(FunctionFact {
            name: func.name.clone(),
            loc: line_index.node_loc(func.range()),
            lines: line_count(line_index, func.start, func.end()),
            body: digest.iter().map(|b| format!("{b:02x}")).collect(),
        });
    }
    for class in collect_classes_bfs(module_body) {
        let bases = base_names_of(class);
        let abstract_ =
            bases.iter().any(|b| ABSTRACT_BASES.contains(&b.as_str())) || has_abc_metaclass(class);
        facts.classes.push(ClassFact {
            name: class.name.to_string(),
            loc: line_index.node_loc(class.range()),
            bases,
            abstract_,
        });
    }
    facts.twins = twin_facts(module_body, source, line_index);
    facts
}

// ── Rule: Orphan Interfaces ──────────────────────────────────────────────────

/// Detect abstract classes with exactly one concrete implementation —
/// mirrors `package_level.py::check_orphan_interfaces_pkg`.
///
/// This is a classic 'Speculative Generality' code smell. If an interface
/// only exists to be implemented by a single class, it is likely adding
/// mental overhead without providing any polymorphic value.
pub fn check_orphan_interfaces_pkg(pkg_name: &str, files: &[(PathBuf, FileFacts)]) -> Vec<Issue> {
    // Insertion-ordered like Python's dict: a same-named interface in a
    // later file keeps the first file's position but takes its location.
    let mut interfaces: IndexMap<&str, (&Path, &ClassFact)> = IndexMap::new();
    let mut implementations: HashMap<&str, Vec<&str>> = HashMap::new();

    for (filepath, facts) in files {
        for class in &facts.classes {
            for base_name in &class.bases {
                if !ABSTRACT_BASES.contains(&base_name.as_str()) {
                    implementations
                        .entry(base_name.as_str())
                        .or_default()
                        .push(class.name.as_str());
                }
            }
            if class.abstract_ {
                interfaces.insert(class.name.as_str(), (filepath.as_path(), class));
            }
        }
    }

    let mut issues = Vec::new();
    for (iface_name, (filepath, class)) in &interfaces {
        let impls = implementations
            .get(iface_name)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if let [impl_name] = impls {
            issues.push(issue_at(
                filepath,
                class.loc,
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

/// Finds functions/methods with byte-for-byte identical bodies anywhere in
/// the package — mirrors `check_duplicate_functions_pkg`.
pub fn check_duplicate_functions_pkg(
    pkg_name: &str,
    files: &[(PathBuf, FileFacts)],
    min_lines: usize,
) -> Vec<Issue> {
    // Insertion-ordered like Python's dict: issues come out in the order each
    // duplicate group was first seen.
    let mut groups: IndexMap<&str, Vec<(&Path, &FunctionFact)>> = IndexMap::new();
    for (filepath, facts) in files {
        for func in &facts.functions {
            if func.lines >= min_lines {
                groups
                    .entry(func.body.as_str())
                    .or_default()
                    .push((filepath.as_path(), func));
            }
        }
    }

    let mut issues = Vec::new();
    for (_key, mut occurrences) in groups {
        if occurrences.len() < MIN_DUPLICATE_OCCURRENCES {
            continue;
        }
        occurrences.sort_by(|a, b| {
            (a.0.to_string_lossy(), a.1.loc.line).cmp(&(b.0.to_string_lossy(), b.1.loc.line))
        });
        let locations: Vec<String> = occurrences
            .iter()
            .map(|(fp, func)| {
                format!(
                    "{}:{} ({})",
                    display_path(fp, None),
                    func.loc.line,
                    func.name
                )
            })
            .collect();
        let (first_fp, first) = occurrences[0];
        issues.push(issue_at(
            first_fp,
            first.loc,
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

/// Every (function, plausible counterpart) pair in one scope of the file,
/// with how similar their source text is — mirrors `_twin_facts`. Scopes are
/// visited in tree order, pairs in definition order, counterparts in sorted
/// order, so the list is the same on every run.
fn twin_facts(module_body: &[Stmt], source: &str, line_index: &LineIndex) -> Vec<TwinFact> {
    // Insertion-ordered, matching Python's dict: a scope is keyed by class
    // *name*, so two same-named classes in one file share a scope, and a
    // redefined function keeps its first position but takes the later node.
    let owned: Vec<(Option<String>, FuncNode)> = collect_functions_with_class_context(module_body);
    let mut scopes: IndexMap<Option<&str>, IndexMap<&str, &FuncNode>> = IndexMap::new();
    for (class_name, func) in &owned {
        scopes
            .entry(class_name.as_deref())
            .or_default()
            .insert(func.name.as_str(), func);
    }
    let mut facts = Vec::new();
    for (class_name, by_name) in &scopes {
        let scope = class_name.unwrap_or_default();
        twins_in_scope(scope, by_name, source, line_index, &mut facts);
    }
    facts
}

fn twins_in_scope(
    scope: &str,
    by_name: &IndexMap<&str, &FuncNode>,
    source: &str,
    line_index: &LineIndex,
    facts: &mut Vec<TwinFact>,
) {
    let mut text: HashMap<&str, String> = HashMap::new();
    for (name, func) in by_name {
        for counterpart in twin_candidates(name) {
            if counterpart == *name {
                continue;
            }
            let Some((counterpart, other)) = by_name.get_key_value(counterpart.as_str()) else {
                continue;
            };
            // `ast.unparse` once per function, however many pairs name it.
            for (key, node) in [(*name, *func), (*counterpart, *other)] {
                text.entry(key)
                    .or_insert_with(|| unparse_function(&node.stmt, source));
            }
            let ratio = sequence_matcher_ratio(&text[name], &text[counterpart]);
            let line = line_index
                .line_number(func.start)
                .min(line_index.line_number(other.start));
            facts.push(TwinFact {
                name: name.to_string(),
                counterpart: counterpart.to_string(),
                scope: scope.to_string(),
                line,
                lines: line_count(line_index, func.start, func.end()),
                ratio,
            });
        }
    }
}

/// Flags function pairs that look like a sync/async "twin" (by name) and
/// whose bodies are highly similar text — mirrors `check_sync_async_twins_pkg`.
pub fn check_sync_async_twins_pkg(
    pkg_name: &str,
    files: &[(PathBuf, FileFacts)],
    min_ratio: f64,
) -> Vec<Issue> {
    let min_twin_function_lines = thresholds().min_twin_function_lines;
    let mut issues = Vec::new();
    for (filepath, facts) in files {
        // A pair is one finding however it is reached (read → aread and
        // aread → read). The scope is part of the key: Request.read/aread and
        // Response.read/aread in one file are two twin pairs, not one.
        let mut reported: HashSet<(&str, [&str; 2])> = HashSet::new();
        for twin in &facts.twins {
            if twin.lines < min_twin_function_lines {
                continue;
            }
            let mut pair = [twin.name.as_str(), twin.counterpart.as_str()];
            pair.sort_unstable();
            let pair_key = (twin.scope.as_str(), pair);
            if reported.contains(&pair_key) || twin.ratio < min_ratio {
                continue;
            }
            reported.insert(pair_key);
            issues.push(issue(
                filepath,
                twin.line,
                Severity::Warning,
                "sync-async-duplication",
                pkg_name,
                format!(
                    "{}() and {}() are {:.0}% similar — likely copy-pasted sync/async twins; extract a shared helper for the non-blocking parts",
                    twin.name,
                    twin.counterpart,
                    twin.ratio * 100.0
                ),
            ));
        }
    }
    issues
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::{FileFacts, collect_facts};
    use crate::ast_helpers::LineIndex;
    use rustpython_ast::Mod;
    use std::path::PathBuf;

    /// The facts of `source` as a module.
    pub(crate) fn facts_of(source: &str, name: &str) -> FileFacts {
        let module = rustpython_parser::parse(source, rustpython_parser::Mode::Module, name)
            .expect("test source must parse");
        let Mod::Module(m) = module else {
            unreachable!()
        };
        collect_facts(&m.body, source, &LineIndex::new(source))
    }

    /// `(path, facts)` per file under `root`, in path order.
    pub(crate) fn pkg(root: &str, files: &[(&str, &str)]) -> Vec<(PathBuf, FileFacts)> {
        let mut parsed: Vec<(PathBuf, FileFacts)> = files
            .iter()
            .map(|(name, source)| (PathBuf::from(root).join(name), facts_of(source, name)))
            .collect();
        parsed.sort_by(|a, b| a.0.cmp(&b.0));
        parsed
    }
}

#[cfg(test)]
mod calibration_tests {
    //! Mirrors the package-level half of the Python repo's tests/test_calibration.py.
    use super::check_duplicate_functions_pkg;
    use super::test_support::pkg;

    const ROOT: &str = "/tmp/pkg";

    #[test]
    fn duplicate_function_body_skips_dunder_protocol_hooks() {
        let body = "    def __repr__(self):\n        a = 1\n        b = 2\n        c = 3\n        \
                    return f'{a}{b}{c}'\n";
        let a = format!("class A:\n{body}");
        let b = format!("class B:\n{body}");
        let files = pkg(ROOT, &[("a.py", &a), ("b.py", &b)]);
        assert!(check_duplicate_functions_pkg("pkg", &files, 5).is_empty());
        let files = pkg(
            ROOT,
            &[
                ("a.py", &a.replace("__repr__", "render")),
                ("b.py", &b.replace("__repr__", "render")),
            ],
        );
        assert_eq!(check_duplicate_functions_pkg("pkg", &files, 5).len(), 1);
    }
}

#[cfg(test)]
mod twin_tests {
    //! Mirrors the twin tests in tests/test_package_level.py.
    use super::test_support::pkg;
    use super::{FileFacts, check_sync_async_twins_pkg};

    fn body(kw: &str, name: &str, call: &str) -> String {
        format!(
            "{kw}def {name}(key):\n    value = {call}(key)\n    if value is None:\n        raise KeyError(key)\n    return decode(value)\n\n"
        )
    }

    #[test]
    fn twin_pairs_are_reported_in_sorted_candidate_order() {
        let source = format!(
            "{}{}{}",
            body("", "get", "store.read"),
            body("async ", "aget", "await store.aread"),
            body("async ", "get_async", "await store.aread"),
        );
        let files = pkg("/tmp/pkg", &[("m.py", &source)]);
        let messages: Vec<String> = check_sync_async_twins_pkg("pkg", &files, 0.6)
            .into_iter()
            .map(|i| i.message)
            .collect();
        assert_eq!(messages.len(), 2);
        assert!(messages[0].starts_with("get() and aget()"), "{messages:?}");
        assert!(
            messages[1].starts_with("get() and get_async()"),
            "{messages:?}"
        );
    }

    #[test]
    fn twin_pairs_in_different_files_are_each_reported() {
        // Mirrors test_twin_pairs_in_different_files_are_each_reported: the
        // dedup key is per file, so module-level get/aget in two files are
        // two findings, as are same-named methods of two classes.
        let module = format!(
            "{}{}",
            body("", "get", "store.read"),
            body("async ", "aget", "await store.aread")
        );
        let class = |name: &str| {
            format!(
                "class {name}:\n{}",
                module
                    .lines()
                    .map(|l| if l.is_empty() {
                        String::new()
                    } else {
                        format!("    {l}")
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        };
        let files = pkg(
            "/tmp/pkg",
            &[
                ("a.py", &module),
                ("b.py", &module),
                ("c.py", &format!("{}\n{}", class("Store"), class("Store"))),
                ("d.py", &class("Store")),
            ],
        );
        let issues = check_sync_async_twins_pkg("pkg", &files, 0.6);
        let files_reported: Vec<String> = issues
            .iter()
            .map(|i| i.file.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        // Two same-named classes in one file share a scope: one finding.
        assert_eq!(files_reported, ["a.py", "b.py", "c.py", "d.py"]);
        assert!(
            issues
                .iter()
                .all(|i| i.message.starts_with("get() and aget()"))
        );
    }

    #[test]
    fn facts_round_trip_through_json() {
        // Mirrors test_facts_round_trip_through_json.
        let source = "from abc import ABC\n\
                      class Base(ABC):\n    pass\n\
                      class Impl(Base):\n    pass\n\
                      def f(x):\n    y = x + 1\n    z = y * 2\n    return z\n\
                      async def af(x):\n    y = x + 1\n    z = y * 2\n    return z\n";
        let facts = super::test_support::facts_of(source, "m.py");
        let names = |v: &[String]| v.to_vec();
        assert_eq!(
            names(
                &facts
                    .classes
                    .iter()
                    .map(|c| c.name.clone())
                    .collect::<Vec<_>>()
            ),
            ["Base", "Impl"]
        );
        assert!(facts.classes[0].abstract_ && !facts.classes[1].abstract_);
        assert_eq!(facts.classes[1].bases, ["Base"]);
        assert_eq!(
            facts
                .functions
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["f", "af"]
        );
        assert_eq!(facts.functions[0].body, facts.functions[1].body);
        assert_eq!(facts.functions[0].lines, 4);
        let pairs: std::collections::HashSet<(&str, &str)> = facts
            .twins
            .iter()
            .map(|t| (t.name.as_str(), t.counterpart.as_str()))
            .collect();
        assert_eq!(pairs, [("f", "af"), ("af", "f")].into_iter().collect());
        assert!(
            facts
                .twins
                .iter()
                .all(|t| t.scope.is_empty() && t.line == 6)
        );
        let back = FileFacts::from_json(&facts.to_json()).expect("facts parse back");
        assert_eq!(back, facts);
        let text = facts.to_json().to_string();
        let reparsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(FileFacts::from_json(&reparsed).unwrap(), facts);
        assert!(FileFacts::from_json(&serde_json::json!({"functions": []})).is_none());
    }
}
