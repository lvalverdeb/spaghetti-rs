//! A direct port of Python's `difflib.SequenceMatcher.ratio()` — the
//! Ratcliff/Obershelp algorithm. Built because Phase 0's spike (see the
//! port proposal's §7.3) found the `similar` crate's ratio genuinely
//! diverges from `difflib`'s on real structurally-different code, so
//! nothing on crates.io could be trusted for this rule.
//!
//! Operates on `Vec<char>` (matching Python's default `SequenceMatcher(None,
//! a, b)`, which treats strings as character sequences).
//!
//! Implements `autojunk` (Python's default-on heuristic — active whenever
//! `len(b) >= 200` — that treats a character as "popular" when it occurs
//! more than `len(b)//100 + 1` times, excluding it from the match-candidate
//! index). Initially assumed this wouldn't matter for realistic
//! (short, well under 200 chars) function-body inputs — wrong: Phase 0's
//! own `load`/`aload` ground-truth pair has an unparsed `aload` body of 414
//! characters, well past the threshold, and produced a real 0.79-vs-0.69
//! mismatch until this was added. Verified against all three of Phase 0's
//! ground-truth ratios after adding it — all three now match exactly.

use std::collections::{HashMap, HashSet};

struct Matcher<'a> {
    a: &'a [char],
    b: &'a [char],
    b2j: HashMap<char, Vec<usize>>,
    bpopular: HashSet<char>,
}

impl<'a> Matcher<'a> {
    fn new(a: &'a [char], b: &'a [char]) -> Self {
        let mut b2j: HashMap<char, Vec<usize>> = HashMap::new();
        for (j, &ch) in b.iter().enumerate() {
            b2j.entry(ch).or_default().push(j);
        }

        let mut bpopular = HashSet::new();
        let n = b.len();
        if n >= 200 {
            let ntest = n / 100 + 1;
            bpopular.extend(
                b2j.iter()
                    .filter(|(_, idxs)| idxs.len() > ntest)
                    .map(|(&ch, _)| ch),
            );
            for ch in &bpopular {
                b2j.remove(ch);
            }
        }

        Matcher {
            a,
            b,
            b2j,
            bpopular,
        }
    }

    /// Longest matching block within a[alo..ahi] / b[blo..bhi].
    /// Returns (besti, bestj, bestsize).
    fn find_longest_match(
        &self,
        alo: usize,
        ahi: usize,
        blo: usize,
        bhi: usize,
    ) -> (usize, usize, usize) {
        let mut besti = alo;
        let mut bestj = blo;
        let mut bestsize = 0usize;
        let mut j2len: HashMap<usize, usize> = HashMap::new();

        for i in alo..ahi {
            let mut newj2len: HashMap<usize, usize> = HashMap::new();
            if let Some(js) = self.b2j.get(&self.a[i]) {
                for &j in js {
                    if j < blo {
                        continue;
                    }
                    if j >= bhi {
                        break;
                    }
                    let prev = j
                        .checked_sub(1)
                        .and_then(|p| j2len.get(&p))
                        .copied()
                        .unwrap_or(0);
                    let k = prev + 1;
                    newj2len.insert(j, k);
                    if k > bestsize {
                        besti = i + 1 - k;
                        bestj = j + 1 - k;
                        bestsize = k;
                    }
                }
            }
            j2len = newj2len;
        }

        // Extend through matching characters at the boundaries — needed
        // because "popular" characters were removed from b2j above, so a
        // match touching one wouldn't otherwise be found by the scan loop.
        // Mirrors CPython's two extension passes (non-popular first, then
        // popular) in `difflib.SequenceMatcher.find_longest_match`.
        while besti > alo
            && bestj > blo
            && !self.bpopular.contains(&self.b[bestj - 1])
            && self.a[besti - 1] == self.b[bestj - 1]
        {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi
            && bestj + bestsize < bhi
            && !self.bpopular.contains(&self.b[bestj + bestsize])
            && self.a[besti + bestsize] == self.b[bestj + bestsize]
        {
            bestsize += 1;
        }
        while besti > alo
            && bestj > blo
            && self.bpopular.contains(&self.b[bestj - 1])
            && self.a[besti - 1] == self.b[bestj - 1]
        {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi
            && bestj + bestsize < bhi
            && self.bpopular.contains(&self.b[bestj + bestsize])
            && self.a[besti + bestsize] == self.b[bestj + bestsize]
        {
            bestsize += 1;
        }

        (besti, bestj, bestsize)
    }

    /// Sum of all matching-block sizes across the whole sequence pair —
    /// all `ratio()` needs (the merge/sort step `get_matching_blocks` does
    /// in Python doesn't change this total, so it's skipped here).
    fn total_matched(&self) -> usize {
        let mut total = 0usize;
        let mut queue = vec![(0usize, self.a.len(), 0usize, self.b.len())];
        while let Some((alo, ahi, blo, bhi)) = queue.pop() {
            let (i, j, k) = self.find_longest_match(alo, ahi, blo, bhi);
            if k == 0 {
                continue;
            }
            total += k;
            if alo < i && blo < j {
                queue.push((alo, i, blo, j));
            }
            if i + k < ahi && j + k < bhi {
                queue.push((i + k, ahi, j + k, bhi));
            }
        }
        total
    }
}

/// Mirrors `difflib.SequenceMatcher(None, a, b).ratio()`.
pub fn sequence_matcher_ratio(a: &str, b: &str) -> f64 {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let total_len = a_chars.len() + b_chars.len();
    if total_len == 0 {
        return 1.0;
    }
    let matcher = Matcher::new(&a_chars, &b_chars);
    let matched = matcher.total_matched();
    2.0 * matched as f64 / total_len as f64
}
