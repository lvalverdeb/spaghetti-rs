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

use std::collections::HashMap;

struct Matcher<'a> {
    a: &'a [char],
    b: &'a [char],
    /// Positions of each character in `b`, minus the "popular" ones
    /// (autojunk) — exactly `SequenceMatcher.b2j` after `__chain_b`.
    b2j: HashMap<char, Vec<usize>>,
}

impl<'a> Matcher<'a> {
    fn new(a: &'a [char], b: &'a [char]) -> Self {
        let mut b2j: HashMap<char, Vec<usize>> = HashMap::new();
        for (j, &ch) in b.iter().enumerate() {
            b2j.entry(ch).or_default().push(j);
        }

        let n = b.len();
        if n >= 200 {
            let ntest = n / 100 + 1;
            b2j.retain(|_, idxs| idxs.len() <= ntest);
        }

        Matcher { a, b, b2j }
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
        // CPython's `find_longest_match` has two extension passes gated on
        // `isbjunk`, which tests the *junk* set (`isjunk=None` here, so it
        // is empty) — not the popular set. Popular characters therefore
        // extend a match like any other; treating them as junk (the earlier
        // port) stopped the first pass at a popular character and the
        // second at a non-popular one, splitting blocks `difflib` keeps
        // whole and making the ratio asymmetric. Found on httpx's
        // `iter_raw`/`aiter_raw` (0.930 vs difflib's 0.939).
        while besti > alo && bestj > blo && self.a[besti - 1] == self.b[bestj - 1] {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi
            && bestj + bestsize < bhi
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

#[cfg(test)]
mod tests {
    use super::sequence_matcher_ratio;

    #[test]
    fn popular_characters_extend_a_match_like_difflib() {
        // Both inputs are over the 200-character autojunk threshold, so `a`
        // is "popular" and dropped from `b2j`. difflib still extends a match
        // through popular characters (they are not *junk*); treating them
        // as junk gave 0.0299 here, and an asymmetric ratio on real code.
        // Expected value: `difflib.SequenceMatcher(None, a, b).ratio()`.
        let a = "zaaaaaaaaaaaaaaaaaaaaayaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaazxxyyaaaaaaaaaaaaaaaaaaaaaaaayxxyyqqqzzaaaaaaaaaaaaaaayyyyqqaaaaaaaaaaaazzxaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaqq";
        let b = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaxaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaayzzqqqqxaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaxaaaaaaaaaaaaaaaaaaaaaaaaaaaaazxxyyqaaaaaaaaaaaaaaaa";
        assert_eq!(a.len(), 200);
        assert_eq!(b.len(), 201);
        let expected = 2.0 * 35.0 / 401.0;
        assert!((sequence_matcher_ratio(a, b) - expected).abs() < 1e-12);
        // Swapped, every character of the new `b` is popular, so `b2j` is
        // empty and difflib finds nothing at all — ratio() is not symmetric.
        assert_eq!(sequence_matcher_ratio(b, a), 0.0);
    }
}
