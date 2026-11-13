//! Checks that need every registered package at once — mirrors
//! `spaghetti/checks/workspace_level.py`: import cycles and coupling over the
//! union import graph, and token-based code clones.
//!
//! Workers (`scanner::scan_package`) collect the lightweight inputs — raw
//! import statements and normalised token streams per file — and the parent
//! runs these checks once over all packages, so a cycle or clone that spans
//! two packages is found and a single-package run reports exactly what the
//! old per-package checks did.

use crate::ast_helpers::LineIndex;
use crate::checks::package_level::{
    ImportNode, import_targets, module_and_package_for, module_level_imports, package_prefix,
};
use crate::clones::{TokenStream, duplicated_regions, find_clone_groups};
use crate::config::thresholds;
use crate::contracts::{Contract, violation_reason};
use crate::models::{Issue, Severity, display_path};
use indexmap::IndexMap;
use rustpython_ast::Stmt;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// One module-level import statement, unresolved. `level` is `None` for a
/// plain `import a.b` (`module` then holds the dotted name and `names` is
/// empty); otherwise it is the `from` statement's relative level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawImport {
    pub level: Option<usize>,
    pub module: Option<String>,
    pub names: Vec<String>,
    /// The import statement's line (`node.lineno`), for contract findings.
    pub line: usize,
}

pub fn collect_raw_imports(module_body: &[Stmt], lines: &LineIndex) -> Vec<RawImport> {
    use rustpython_ast::Ranged;
    let mut raw = Vec::new();
    for node in module_level_imports(module_body) {
        match node {
            ImportNode::ImportFrom(n) => raw.push(RawImport {
                level: Some(n.level.as_ref().map(|l| l.to_usize()).unwrap_or(0)),
                module: n.module.as_ref().map(|m| m.to_string()),
                names: n.names.iter().map(|a| a.name.to_string()).collect(),
                line: lines.line_number(n.range().start()),
            }),
            ImportNode::Import(n) => {
                let line = lines.line_number(n.range().start());
                for alias in &n.names {
                    raw.push(RawImport {
                        level: None,
                        module: Some(alias.name.to_string()),
                        names: Vec::new(),
                        line,
                    });
                }
            }
        }
    }
    raw
}

/// module -> modules it imports (neighbours sorted, like Python's `sorted(set)`).
pub type Graph = IndexMap<String, BTreeSet<String>>;

/// module -> (owning package name, file).
pub type ModuleIndex = IndexMap<String, (String, PathBuf)>;

/// One registered package's contribution to the workspace pass.
pub struct PackageImports<'a> {
    pub name: &'a str,
    pub root: &'a Path,
    pub files: &'a IndexMap<PathBuf, Vec<RawImport>>,
}

fn module_index(packages: &[PackageImports<'_>]) -> ModuleIndex {
    let mut index = ModuleIndex::new();
    for pkg in packages {
        for filepath in pkg.files.keys() {
            let (module, _) = module_and_package_for(pkg.root, filepath);
            index.insert(module, (pkg.name.to_string(), filepath.clone()));
        }
    }
    index
}

/// Dotted module names one raw import statement depends on.
fn resolve(raw: &RawImport, package: &str, modules: &HashSet<String>) -> Vec<String> {
    match raw.level {
        None => raw.module.iter().cloned().collect(),
        Some(level) => import_targets(package, level, raw.module.as_deref(), &raw.names, modules),
    }
}

/// Union import graph over every package: module -> modules it imports,
/// keeping only edges into a registered package. `from pkg import name`
/// resolves to the submodule `pkg.name` when that module exists anywhere in
/// the workspace.
pub fn build_import_graph(packages: &[PackageImports<'_>]) -> (Graph, ModuleIndex) {
    let index = module_index(packages);
    let modules: HashSet<String> = index.keys().cloned().collect();
    let stems: Vec<String> = packages
        .iter()
        .map(|p| package_prefix(p.root).trim_end_matches('.').to_string())
        .collect();
    let in_workspace = |name: &str| {
        stems
            .iter()
            .any(|stem| name == stem || name.starts_with(&format!("{stem}.")))
    };
    let files_of: HashMap<&str, &IndexMap<PathBuf, Vec<RawImport>>> =
        packages.iter().map(|p| (p.name, p.files)).collect();
    let roots: HashMap<&str, &Path> = packages.iter().map(|p| (p.name, p.root)).collect();

    let mut graph = Graph::new();
    for (module, (pkg_name, filepath)) in &index {
        let (_, package) = module_and_package_for(roots[pkg_name.as_str()], filepath);
        // `graph[module]` in Python creates the key even with no edges.
        let edges = graph.entry(module.clone()).or_default();
        for raw in &files_of[pkg_name.as_str()][filepath] {
            edges.extend(
                resolve(raw, &package, &modules)
                    .into_iter()
                    .filter(|t| !t.is_empty() && in_workspace(t)),
            );
        }
    }
    (graph, index)
}

/// (importing module, imported dotted name, line) — every import, third-party included.
pub type Edge = (String, String, usize);

/// Every resolved import edge in file order, workspace and external alike,
/// for the architecture-contract check — mirrors `dependency_edges`.
pub fn dependency_edges(packages: &[PackageImports<'_>]) -> (Vec<Edge>, ModuleIndex) {
    let index = module_index(packages);
    let modules: HashSet<String> = index.keys().cloned().collect();
    let files_of: HashMap<&str, &IndexMap<PathBuf, Vec<RawImport>>> =
        packages.iter().map(|p| (p.name, p.files)).collect();
    let roots: HashMap<&str, &Path> = packages.iter().map(|p| (p.name, p.root)).collect();
    let mut edges = Vec::new();
    for (module, (pkg_name, filepath)) in &index {
        let (_, package) = module_and_package_for(roots[pkg_name.as_str()], filepath);
        for raw in &files_of[pkg_name.as_str()][filepath] {
            edges.extend(
                resolve(raw, &package, &modules)
                    .into_iter()
                    .filter(|t| !t.is_empty())
                    .map(|t| (module.clone(), t, raw.line)),
            );
        }
    }
    (edges, index)
}

/// One finding per (import, contract) pair that breaks a contract — mirrors
/// `check_contracts_ws`.
pub fn check_contracts_ws(
    edges: &[Edge],
    index: &ModuleIndex,
    contracts: &[Contract],
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (module, target, line) in edges {
        for contract in contracts {
            let Some(reason) = violation_reason(contract, module, target) else {
                continue;
            };
            let (pkg_name, filepath) = &index[module.as_str()];
            issues.push(Issue::new(
                filepath,
                *line,
                Severity::Error,
                "contract-violation",
                pkg_name,
                format!(
                    "Contract '{}': {module} imports {target} \u{2014} {reason}; depend on an \
                     abstraction (e.g. a typing.Protocol) the lower layer implements and inject \
                     it instead (Dependency Inversion Principle)",
                    contract.name
                ),
            ));
        }
    }
    issues
}

const CYCLE_HINT: &str = " — extract a shared abstraction (e.g. a typing.Protocol) both sides can \
                          depend on, and inject it instead of importing directly to break the \
                          cycle (Dependency Inversion Principle / Dependency Injection)";

/// Every distinct import cycle, found by DFS; attributed to the package of
/// the module where the cycle was entered.
pub fn check_import_cycles_ws(graph: &Graph, index: &ModuleIndex) -> Vec<Issue> {
    if index.is_empty() {
        return Vec::new();
    }
    let mut issues = Vec::new();
    let mut visited: HashSet<&str> = HashSet::new();
    let mut reported: HashSet<BTreeSet<&str>> = HashSet::new();
    let empty = BTreeSet::new();

    for start in graph.keys() {
        if visited.contains(start.as_str()) {
            continue;
        }
        // Explicit stack-based DFS (mirrors Python's recursive version,
        // including its on_stack cycle-membership check) — avoids Rust
        // recursion-depth concerns on a real import graph.
        let mut stack: Vec<&str> = vec![start];
        let mut on_stack: HashSet<&str> = HashSet::from([start.as_str()]);
        visited.insert(start);
        let neighbours = |m: &str| graph.get(m).unwrap_or(&empty).iter();
        let mut frames: Vec<Box<dyn Iterator<Item = &String>>> = vec![Box::new(neighbours(start))];

        while let Some(frame) = frames.last_mut() {
            let Some(neighbor) = frame.next() else {
                frames.pop();
                let done = stack.pop().unwrap();
                on_stack.remove(done);
                continue;
            };
            if on_stack.contains(neighbor.as_str()) {
                let cycle_start = stack.iter().position(|m| *m == neighbor).unwrap();
                let mut cycle: Vec<&str> = stack[cycle_start..].to_vec();
                cycle.push(neighbor);
                let key: BTreeSet<&str> = cycle.iter().copied().collect();
                if let Some((pkg_name, loc)) = index.get(stack[cycle_start])
                    && !reported.contains(&key)
                {
                    reported.insert(key);
                    issues.push(Issue::new(
                        loc,
                        1,
                        Severity::Error,
                        "import-cycle",
                        pkg_name,
                        format!("Circular import: {}{CYCLE_HINT}", cycle.join(" \u{2192} ")),
                    ));
                }
            } else if !visited.contains(neighbor.as_str()) {
                visited.insert(neighbor);
                stack.push(neighbor);
                on_stack.insert(neighbor);
                frames.push(Box::new(neighbours(neighbor)));
            }
        }
    }
    issues
}

/// A module with *both* fan-in and fan-out over their thresholds is a hub
/// whose changes ripple; either alone is usually a legitimate util module or
/// a thin orchestrator.
pub fn check_module_coupling_ws(graph: &Graph, index: &ModuleIndex) -> Vec<Issue> {
    let t = thresholds();
    let (max_fan_in, max_fan_out) = (t.max_module_fan_in, t.max_module_fan_out);
    let mut fan_in: HashMap<&str, usize> = HashMap::new();
    for imports in graph.values() {
        for target in imports {
            *fan_in.entry(target.as_str()).or_insert(0) += 1;
        }
    }
    let mut issues = Vec::new();
    for (module, (pkg_name, filepath)) in index {
        let module_fan_out = graph.get(module).map_or(0, BTreeSet::len);
        let module_fan_in = fan_in.get(module.as_str()).copied().unwrap_or(0);
        if module_fan_in > max_fan_in && module_fan_out > max_fan_out {
            issues.push(Issue::new(
                filepath,
                1,
                Severity::Warning,
                "high-coupling",
                pkg_name,
                format!(
                    "module {module} has fan-in={module_fan_in} and fan-out={module_fan_out} \
                     (max {max_fan_in}/{max_fan_out}) — other modules depend on it heavily and \
                     it depends on other modules heavily; consider splitting it or inverting \
                     some dependencies (Dependency Inversion Principle)"
                ),
            ));
        }
    }
    issues
}

const MAX_LISTED_SITES: usize = 5;

/// One finding per duplicated region of a file (overlapping clone sites
/// merged), listing where else the code appears. Every side of a clone gets
/// a finding, as in SonarQube's duplicated-blocks view, so the owner of each
/// copy sees it. `info` by default: duplication is a density signal (Sonar
/// scores it as a metric, not a defect), and mature libraries carry
/// deliberate copies — sync/async twins, router/app mirrors — that a
/// per-block warning would turn into grade-sinking noise.
pub fn check_duplicate_code_ws(
    streams_by_package: &[(&str, &IndexMap<PathBuf, TokenStream>)],
    min_tokens: usize,
    workspace_root: Option<&Path>,
) -> Vec<Issue> {
    let mut owner: HashMap<&Path, &str> = HashMap::new();
    let mut streams: IndexMap<&Path, &TokenStream> = IndexMap::new();
    for (pkg_name, files) in streams_by_package {
        for (path, stream) in files.iter() {
            owner.insert(path.as_path(), pkg_name);
            streams.insert(path.as_path(), stream);
        }
    }
    let ordered: Vec<(&Path, &TokenStream)> = streams.iter().map(|(p, s)| (*p, *s)).collect();
    let groups = find_clone_groups(&ordered, min_tokens);
    let file_order: Vec<&Path> = streams.keys().copied().collect();
    let mut issues = Vec::new();
    for region in duplicated_regions(&groups, &file_order) {
        let listed = &region.others[..region.others.len().min(MAX_LISTED_SITES)];
        let mut where_ = listed
            .iter()
            .map(|s| {
                format!(
                    "{}:{}-{}",
                    display_path(&s.file, workspace_root),
                    s.start_line,
                    s.end_line
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        if region.others.len() > MAX_LISTED_SITES {
            where_.push_str(&format!(
                " and {} more",
                region.others.len() - MAX_LISTED_SITES
            ));
        }
        let mut issue = Issue::new(
            &region.file,
            region.start_line,
            Severity::Info,
            "duplicate-code",
            owner[region.file.as_path()],
            format!(
                "Lines {}-{} are duplicated in {} other place(s): {where_} — extract the shared \
                 logic into one function; renamed variables do not make a copy independent",
                region.start_line,
                region.end_line,
                region.others.len()
            ),
        );
        issue.end_line = Some(region.end_line);
        issues.push(issue);
    }
    issues
}

#[cfg(test)]
mod tests {
    //! Single-package behaviour of the graph checks (the multi-package cases
    //! live in `scanner::workspace_tests`) — mirrors the import-cycle and
    //! coupling halves of tests/test_package_level.py and test_calibration.py.
    use super::*;
    use crate::config::MAX_MODULE_FAN_IN;
    use rustpython_ast::Mod;

    const ROOT: &str = "/tmp/pkg";

    fn raw(source: &str) -> Vec<RawImport> {
        let module = rustpython_parser::parse(source, rustpython_parser::Mode::Module, "f.py")
            .expect("test source must parse");
        let Mod::Module(m) = module else {
            unreachable!()
        };
        collect_raw_imports(&m.body, &crate::ast_helpers::LineIndex::new(source))
    }

    fn graph_for(root: &str, files: &[(&str, &str)]) -> (Graph, ModuleIndex) {
        let mut imports: IndexMap<PathBuf, Vec<RawImport>> = IndexMap::new();
        let mut names: Vec<&str> = files.iter().map(|(n, _)| *n).collect();
        names.sort();
        for name in names {
            let source = files.iter().find(|(n, _)| *n == name).unwrap().1;
            imports.insert(PathBuf::from(root).join(name), raw(source));
        }
        let pkg_name = Path::new(root).file_name().unwrap().to_str().unwrap();
        build_import_graph(&[PackageImports {
            name: pkg_name,
            root: Path::new(root),
            files: &imports,
        }])
    }

    #[test]
    fn main_guard_imports_do_not_create_cycles() {
        let (graph, index) = graph_for(
            ROOT,
            &[
                ("__init__.py", ""),
                ("console.py", "from .pager import Pager\n"),
                (
                    "pager.py",
                    "class Pager: ...\nif __name__ == \"__main__\":\n    from .console import Console\n",
                ),
            ],
        );
        assert!(check_import_cycles_ws(&graph, &index).is_empty());
    }

    #[test]
    fn init_reexport_of_submodules_is_not_a_cycle() {
        let (graph, index) = graph_for(
            ROOT,
            &[
                ("__init__.py", "from .a import A\nfrom .b import B\n"),
                ("a.py", "from pkg import b\nclass A: ...\n"),
                ("b.py", "class B: ...\n"),
            ],
        );
        assert_eq!(graph["pkg.a"], BTreeSet::from(["pkg.b".to_string()]));
        assert!(check_import_cycles_ws(&graph, &index).is_empty());
    }

    #[test]
    fn real_cycle_is_still_reported_with_a_deterministic_representative() {
        let (graph, index) = graph_for(
            ROOT,
            &[
                ("__init__.py", ""),
                ("a.py", "from .b import B\n"),
                ("b.py", "from .a import A\n"),
            ],
        );
        let issues = check_import_cycles_ws(&graph, &index);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].rule, "import-cycle");
        assert_eq!(issues[0].severity, Severity::Error);
        assert_eq!(issues[0].package, "pkg");
        assert!(issues[0].message.contains("pkg.a → pkg.b → pkg.a"));
        assert_eq!(issues[0].file, PathBuf::from(ROOT).join("a.py"));
    }

    #[test]
    fn module_coupling_flags_hub_module() {
        let n = MAX_MODULE_FAN_IN + 1; // also > MAX_MODULE_FAN_OUT since both are equal
        let mut files: Vec<(String, String)> = Vec::new();
        for i in 0..n {
            files.push((format!("dep{i}.py"), "x = 1\n".to_string()));
        }
        let hub: String = (0..n)
            .map(|i| format!("from .dep{i} import x as x{i}\n"))
            .collect();
        files.push(("hub.py".to_string(), hub));
        for i in 0..n {
            files.push((format!("user{i}.py"), "from .hub import hub\n".to_string()));
        }
        let borrowed: Vec<(&str, &str)> = files
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let (graph, index) = graph_for("/tmp/my_lib", &borrowed);
        let issues = check_module_coupling_ws(&graph, &index);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].rule, "high-coupling");
        assert!(issues[0].message.contains("my_lib.hub"));
    }

    #[test]
    fn module_coupling_allows_high_fan_in_alone() {
        let n = MAX_MODULE_FAN_IN + 1;
        let mut files: Vec<(String, String)> = vec![("util.py".to_string(), "x = 1\n".to_string())];
        for i in 0..n {
            files.push((format!("user{i}.py"), "from .util import x\n".to_string()));
        }
        let borrowed: Vec<(&str, &str)> = files
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let (graph, index) = graph_for("/tmp/my_lib", &borrowed);
        assert!(check_module_coupling_ws(&graph, &index).is_empty());
    }
}
