//! Token-based clone detection (PMD CPD style) over a normalised AST stream —
//! mirrors `spaghetti/clones.py`.
//!
//! The "tokens" are a pre-order linearisation of the AST rather than lexer
//! tokens: every node contributes its CPython class name, identifiers become
//! `ID` and literals `LIT`. That makes the stream identical across the
//! Python and Rust ports and makes the detector find type-2 clones — copies
//! with renamed variables, functions and attributes — not just byte-exact
//! ones. A window of `min_tokens` consecutive tokens that occurs in two or
//! more places, extended to its maximal length, is a clone group.

use crate::ast_helpers::LineIndex;
use crate::fstrings::FStringStarts;
use crate::pyast::Node;
use rustpython_ast::{Expr, Stmt};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// Parallel lists: normalised token names and the 1-based line each came from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenStream {
    pub names: Vec<&'static str>,
    pub lines: Vec<usize>,
}

/// The normalised token stream of a module — mirrors `token_stream`
/// (pre-order, iterative so deep nesting cannot overflow the stack). Lines
/// of f-string parts come from `FStringStarts`, matching CPython 3.12+.
pub fn token_stream(body: &[Stmt], source: &str, index: &LineIndex) -> TokenStream {
    let fstrings = FStringStarts::new(body, source);
    let mut out = TokenStream::default();
    let mut stack: Vec<(Node<'_>, usize)> = Vec::new();
    for stmt in body {
        let node = Node::Stmt(stmt);
        let line = index.line_number(node.start().unwrap_or_default());
        stack.push((node, line));
        while let Some((node, inherited)) = stack.pop() {
            let start = match node {
                Node::Expr(e) => fstrings.get(e).or_else(|| node.start()),
                _ => node.start(),
            };
            let line = start
                .map(|offset| index.line_number(offset))
                .unwrap_or(inherited);
            if matches!(node, Node::Expr(Expr::Constant(_))) {
                out.names.push("LIT");
                out.lines.push(line);
                continue;
            }
            out.names.push(node.py_name());
            out.lines.push(line);
            for _ in 0..node.identifier_count() {
                out.names.push("ID");
                out.lines.push(line);
            }
            stack.extend(node.children().into_iter().rev().map(|c| (c, line)));
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CloneSite {
    pub file: PathBuf,
    pub start_line: usize,
    pub end_line: usize,
}

impl CloneSite {
    pub fn new(file: impl Into<PathBuf>, start_line: usize, end_line: usize) -> Self {
        CloneSite {
            file: file.into(),
            start_line,
            end_line,
        }
    }

    fn overlaps(&self, other: &CloneSite) -> bool {
        self.file == other.file
            && self.start_line <= other.end_line
            && other.start_line <= self.end_line
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneGroup {
    pub tokens: usize,
    pub sites: Vec<CloneSite>,
}

const MAX_PERIOD: usize = 16;

/// (file index, token offset).
type Position = (usize, usize);

/// A window that is one short pattern repeated (`x = 1` forty times, an enum
/// or lookup table) is data layout, not duplicated logic.
fn is_periodic(window: &[u32]) -> bool {
    let n = window.len();
    (1..=MAX_PERIOD.min(n / 2)).any(|period| (period..n).all(|i| window[i] == window[i - period]))
}

/// Encoded token streams plus every window hashed, in file order.
struct Index<'a> {
    files: Vec<&'a Path>,
    lines: Vec<&'a [usize]>,
    encoded: Vec<Vec<u32>>,
    width: usize,
    hashes: Vec<Vec<u64>>,
    by_hash: HashMap<u64, Vec<Position>>,
}

/// Polynomial rolling hash of every `width`-token window; collisions are
/// resolved by comparing the real tokens before a group is accepted.
fn window_hashes(encoded: &[u32], width: usize) -> Vec<u64> {
    const BASE: u64 = 1_000_003;
    let n = encoded.len();
    if n < width {
        return Vec::new();
    }
    let power = (0..width - 1).fold(1u64, |acc, _| acc.wrapping_mul(BASE));
    let mut h = 0u64;
    for &value in &encoded[..width] {
        h = h.wrapping_mul(BASE).wrapping_add(u64::from(value));
    }
    let mut hashes = Vec::with_capacity(n - width + 1);
    hashes.push(h);
    for i in width..n {
        h = h
            .wrapping_sub(u64::from(encoded[i - width]).wrapping_mul(power))
            .wrapping_mul(BASE)
            .wrapping_add(u64::from(encoded[i]));
        hashes.push(h);
    }
    hashes
}

impl<'a> Index<'a> {
    fn new(streams: &[(&'a Path, &'a TokenStream)], width: usize) -> Self {
        let mut vocab: HashMap<&'static str, u32> = HashMap::new();
        let files: Vec<&'a Path> = streams.iter().map(|(f, _)| *f).collect();
        let lines: Vec<&'a [usize]> = streams.iter().map(|(_, s)| s.lines.as_slice()).collect();
        let encoded: Vec<Vec<u32>> = streams
            .iter()
            .map(|(_, s)| {
                s.names
                    .iter()
                    .map(|name| {
                        let next = vocab.len() as u32 + 1;
                        *vocab.entry(name).or_insert(next)
                    })
                    .collect()
            })
            .collect();
        let hashes: Vec<Vec<u64>> = encoded
            .iter()
            .map(|tokens| window_hashes(tokens, width))
            .collect();
        let mut by_hash: HashMap<u64, Vec<Position>> = HashMap::new();
        for (file_index, file_hashes) in hashes.iter().enumerate() {
            for (offset, &h) in file_hashes.iter().enumerate() {
                by_hash.entry(h).or_default().push((file_index, offset));
            }
        }
        Index {
            files,
            lines,
            encoded,
            width,
            hashes,
            by_hash,
        }
    }

    fn token_at(&self, position: Position, shift: isize) -> Option<u32> {
        let (file_index, offset) = position;
        let tokens = &self.encoded[file_index];
        let at = offset as isize + shift;
        if at >= 0 && (at as usize) < tokens.len() {
            Some(tokens[at as usize])
        } else {
            None
        }
    }

    fn window(&self, position: Position) -> &[u32] {
        let (file_index, offset) = position;
        &self.encoded[file_index][offset..offset + self.width]
    }

    fn same_token_everywhere(&self, members: &[Position], shift: isize) -> bool {
        let mut seen: Option<u32> = None;
        for &m in members {
            match self.token_at(m, shift) {
                None => return false,
                Some(tok) => match seen {
                    None => seen = Some(tok),
                    Some(prev) if prev != tok => return false,
                    Some(_) => {}
                },
            }
        }
        seen.is_some()
    }

    /// The maximal clone group whose first site starts at `first`, or `None`
    /// if the window there is not the left-maximal start of one.
    fn group_at(&self, first: Position) -> Option<CloneGroup> {
        let candidates = &self.by_hash[&self.hashes[first.0][first.1]];
        if candidates.len() < 2 || candidates[0] != first {
            return None; // a group is emitted once, from its first site
        }
        let window = self.window(first);
        if is_periodic(window) {
            return None;
        }
        let members: Vec<Position> = candidates
            .iter()
            .copied()
            .filter(|&c| self.window(c) == window)
            .collect();
        if members.len() < 2 || self.same_token_everywhere(&members, -1) {
            return None; // the window one step left forms a group covering this one
        }
        let mut length = self.width;
        while self.same_token_everywhere(&members, length as isize) {
            length += 1;
        }
        let kept = drop_overlapping(&members, length);
        if kept.len() < 2 {
            return None;
        }
        Some(CloneGroup {
            tokens: length,
            sites: kept.iter().map(|&m| self.site(m, length)).collect(),
        })
    }

    fn site(&self, position: Position, length: usize) -> CloneSite {
        let (file_index, offset) = position;
        let lines = self.lines[file_index];
        let end = *lines[offset..offset + length].iter().max().unwrap_or(&0);
        CloneSite::new(self.files[file_index], lines[offset], end)
    }
}

fn drop_overlapping(members: &[Position], length: usize) -> Vec<Position> {
    let mut kept: Vec<Position> = Vec::new();
    for &member in members {
        if kept
            .iter()
            .all(|&m| m.0 != member.0 || member.1 >= m.1 + length)
        {
            kept.push(member);
        }
    }
    kept
}

/// Maximal groups of >= 2 sites sharing at least `min_tokens` consecutive
/// normalised tokens. `streams` is iterated in its given order, which fixes
/// the order of the result and the first site of each group.
pub fn find_clone_groups(streams: &[(&Path, &TokenStream)], min_tokens: usize) -> Vec<CloneGroup> {
    if min_tokens < 1 {
        return Vec::new();
    }
    let index = Index::new(streams, min_tokens);
    let mut groups = Vec::new();
    for (file_index, hashes) in index.hashes.iter().enumerate() {
        for offset in 0..hashes.len() {
            if let Some(group) = index.group_at((file_index, offset)) {
                groups.push(group);
            }
        }
    }
    groups
}

/// A span of one file that is duplicated elsewhere, with every other site
/// any of its clone groups pointed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicatedRegion {
    pub file: PathBuf,
    pub start_line: usize,
    pub end_line: usize,
    pub others: Vec<CloneSite>,
}

fn mostly_overlaps(site: &CloneSite, start: usize, end: usize) -> bool {
    let shared = site.end_line.min(end) as i64 - site.start_line.max(start) as i64 + 1;
    let shortest = (site.end_line - site.start_line).min(end - start) as i64 + 1;
    shared * 2 >= shortest
}

/// Zero or one region: a span whose only copies lie inside itself (two
/// adjacent repeats merged into one block) has nothing to point at.
fn region(path: &Path, start: usize, end: usize, others: &[CloneSite]) -> Option<DuplicatedRegion> {
    let span = CloneSite::new(path, start, end);
    let unique: BTreeSet<(String, usize, usize, &CloneSite)> = others
        .iter()
        .filter(|o| !o.overlaps(&span))
        .map(|o| {
            (
                o.file.to_string_lossy().into_owned(),
                o.start_line,
                o.end_line,
                o,
            )
        })
        .collect();
    if unique.is_empty() {
        return None;
    }
    Some(DuplicatedRegion {
        file: path.to_path_buf(),
        start_line: start,
        end_line: end,
        others: unique.into_iter().map(|(_, _, _, s)| s.clone()).collect(),
    })
}

/// Collapse clone sites within a file that overlap by at least half of the
/// smaller span into one region each, so a stretch of code covered by
/// several cascading groups is reported once while two distinct clones that
/// merely touch stay separate. Regions come out in `file_order` then by
/// start line.
pub fn duplicated_regions(groups: &[CloneGroup], file_order: &[&Path]) -> Vec<DuplicatedRegion> {
    let mut sites_by_file: HashMap<&Path, Vec<(&CloneSite, Vec<&CloneSite>)>> = HashMap::new();
    for group in groups {
        for (i, site) in group.sites.iter().enumerate() {
            let others: Vec<&CloneSite> = group
                .sites
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, s)| s)
                .collect();
            sites_by_file
                .entry(site.file.as_path())
                .or_default()
                .push((site, others));
        }
    }

    let mut regions = Vec::new();
    for &path in file_order {
        let mut entries: Vec<&(&CloneSite, Vec<&CloneSite>)> = sites_by_file
            .get(path)
            .map(|v| v.iter().collect())
            .unwrap_or_default();
        entries.sort_by_key(|(site, _)| (site.start_line, site.end_line));
        let mut current: Option<(usize, usize, Vec<CloneSite>)> = None;
        for (site, others) in entries {
            match &mut current {
                Some((start, end, acc)) if mostly_overlaps(site, *start, *end) => {
                    *end = (*end).max(site.end_line);
                    acc.extend(others.iter().map(|&o| o.clone()));
                }
                _ => {
                    if let Some((start, end, acc)) = current.take() {
                        regions.extend(region(path, start, end, &acc));
                    }
                    current = Some((
                        site.start_line,
                        site.end_line,
                        others.iter().map(|&o| o.clone()).collect(),
                    ));
                }
            }
        }
        if let Some((start, end, acc)) = current {
            regions.extend(region(path, start, end, &acc));
        }
    }
    regions
}

#[cfg(test)]
mod tests {
    //! Mirrors tests/test_clones.py.
    use super::*;
    use rustpython_ast::Mod;

    const BODY: &str = "\ndef {name}(items, limit):\n    total = 0\n    seen = set()\n    for item in items:\n        if item in seen:\n            continue\n        seen.add(item)\n        if item.value > limit:\n            total += item.value * 2\n        else:\n            total -= 1\n    return total, len(seen)\n";

    fn stream(source: &str) -> TokenStream {
        let module = rustpython_parser::parse(source, rustpython_parser::Mode::Module, "f.py")
            .expect("test source must parse");
        let Mod::Module(m) = module else {
            unreachable!()
        };
        token_stream(&m.body, source, &LineIndex::new(source))
    }

    fn body(name: &str) -> String {
        BODY.replace("{name}", name)
    }

    #[test]
    fn token_stream_normalises_identifiers_and_literals() {
        let s = stream("x = 1\ny = 'a'\n");
        assert_eq!(
            s.names,
            ["Assign", "Name", "ID", "LIT", "Assign", "Name", "ID", "LIT"]
        );
        assert_eq!(s.lines, [1, 1, 1, 1, 2, 2, 2, 2]);
    }

    #[test]
    fn token_stream_follows_cpython_field_order() {
        // arguments: parameters first, then kw_defaults, then defaults;
        // operators are nodes; keyword without a name (`**kw`) has no ID.
        let s = stream("def f(a, b=1, *, c=2):\n    return -a < b(**k, x=1)\n");
        assert_eq!(
            s.names,
            [
                "FunctionDef",
                "ID",
                "arguments",
                "arg",
                "ID",
                "arg",
                "ID",
                "arg",
                "ID",
                "LIT",
                "LIT",
                "Return",
                "Compare",
                "UnaryOp",
                "USub",
                "Name",
                "ID",
                "Lt",
                "Call",
                "Name",
                "ID",
                "keyword",
                "Name",
                "ID",
                "keyword",
                "ID",
                "LIT",
            ]
        );
    }

    #[test]
    fn renamed_copy_is_detected_as_one_group() {
        let a = Path::new("/t/a.py");
        let b = Path::new("/t/b.py");
        let original = body("summarize");
        let renamed = body("tally")
            .replace("items", "rows")
            .replace("total", "acc")
            .replace("seen", "done")
            .replace("limit", "cap")
            .replace('2', "7");
        let sa = stream(&original);
        let sb = stream(&renamed);
        let groups = find_clone_groups(&[(a, &sa), (b, &sb)], 30);
        assert_eq!(groups.len(), 1);
        let group = &groups[0];
        let files: Vec<&Path> = group.sites.iter().map(|s| s.file.as_path()).collect();
        assert_eq!(files, [a, b]);
        assert_eq!(group.sites[0].start_line, 2);
        assert_eq!(group.sites[0].end_line, 13);
        assert_eq!(group.tokens, sa.names.len());
    }

    #[test]
    fn no_group_below_min_tokens_or_for_distinct_code() {
        let a = Path::new("/t/a.py");
        let b = Path::new("/t/b.py");
        let (sa, sb) = (stream("x = 1\n"), stream("y = 2\n"));
        assert!(find_clone_groups(&[(a, &sa), (b, &sb)], 5).is_empty());
        let sa = stream(&body("f"));
        let sb = stream("def g(a):\n    return [a for _ in range(3)]\n");
        assert!(find_clone_groups(&[(a, &sa), (b, &sb)], 10).is_empty());
    }

    #[test]
    fn three_copies_form_one_group_and_overlaps_are_dropped() {
        let paths: Vec<PathBuf> = (0..3)
            .map(|i| PathBuf::from(format!("/t/m{i}.py")))
            .collect();
        let streams: Vec<TokenStream> = (0..3).map(|i| stream(&body(&format!("f{i}")))).collect();
        let input: Vec<(&Path, &TokenStream)> = paths
            .iter()
            .map(|p| p.as_path())
            .zip(streams.iter())
            .collect();
        let groups = find_clone_groups(&input, 20);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].sites.len(), 3);
        // repeated trivial statements in one file never pair with themselves
        let rep = stream(&"x = 1\n".repeat(40));
        assert!(find_clone_groups(&[(Path::new("/t/rep.py"), &rep)], 8).is_empty());
    }

    #[test]
    fn duplicated_regions_merge_cascading_sites_per_file() {
        let (a, b, c) = (Path::new("a.py"), Path::new("b.py"), Path::new("c.py"));
        let groups = vec![
            CloneGroup {
                tokens: 60,
                sites: vec![
                    CloneSite::new(a, 10, 20),
                    CloneSite::new(b, 1, 11),
                    CloneSite::new(c, 5, 15),
                ],
            },
            CloneGroup {
                tokens: 55,
                sites: vec![CloneSite::new(a, 14, 26), CloneSite::new(b, 5, 17)],
            },
            CloneGroup {
                tokens: 50,
                sites: vec![CloneSite::new(a, 40, 48), CloneSite::new(c, 30, 38)],
            },
            // touches the first region by one line only: a distinct clone, kept apart
            CloneGroup {
                tokens: 50,
                sites: vec![CloneSite::new(a, 26, 39), CloneSite::new(c, 60, 73)],
            },
        ];
        let regions = duplicated_regions(&groups, &[a, b, c]);
        let spans: Vec<(&Path, usize, usize)> = regions
            .iter()
            .map(|r| (r.file.as_path(), r.start_line, r.end_line))
            .collect();
        assert_eq!(
            spans,
            [
                (a, 10, 26),
                (a, 26, 39),
                (a, 40, 48),
                (b, 1, 17),
                (c, 5, 15),
                (c, 30, 38),
                (c, 60, 73),
            ]
        );
        assert_eq!(
            regions[0].others,
            [
                CloneSite::new(b, 1, 11),
                CloneSite::new(b, 5, 17),
                CloneSite::new(c, 5, 15)
            ]
        );
    }

    #[test]
    fn duplicated_regions_drop_a_span_whose_only_copy_is_inside_itself() {
        let a = Path::new("a.py");
        let groups = vec![CloneGroup {
            tokens: 50,
            sites: vec![CloneSite::new(a, 10, 20), CloneSite::new(a, 16, 26)],
        }];
        assert!(duplicated_regions(&groups, &[a]).is_empty());
    }
}
