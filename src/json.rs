//! `json.dumps(value, indent=2)` byte for byte — shared by the JSON report,
//! the SARIF document and the baseline file.

use serde::Serialize;

/// serde_json's pretty printer already matches Python's indentation and
/// separators; what it doesn't do is `ensure_ascii`, so every non-ASCII
/// character (and DEL, which Python's `[^\ -~]` escape class also catches) is
/// rewritten to `\uXXXX` — as a UTF-16 surrogate pair above the BMP,
/// lowercase hex, exactly like Python. Safe to do over the whole document:
/// outside string literals serde_json only ever emits ASCII.
pub fn dumps_pretty<T: Serialize>(value: &T) -> String {
    let pretty = serde_json::to_string_pretty(value).expect("document is serializable");
    let mut out = String::with_capacity(pretty.len());
    for c in pretty.chars() {
        if (c as u32) < 0x7f {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

/// Python's default `json.dumps(value)` separators (`", "` and `": "`) on one
/// line. `ensure_ascii` mirrors the Python flag: the MCP reply lines use the
/// default (`True`), the snapshot store writes `ensure_ascii=False`.
pub fn dumps_compact<T: Serialize>(value: &T, ensure_ascii: bool) -> String {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, PyCompact);
    value.serialize(&mut ser).expect("document is serializable");
    let text = String::from_utf8(buf).expect("serde_json emits UTF-8");
    if ensure_ascii {
        escape_non_ascii(&text)
    } else {
        text
    }
}

/// `json.dumps(value, indent=2)` with `ensure_ascii` on — see `dumps_pretty`.
fn escape_non_ascii(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if (c as u32) < 0x7f {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

struct PyCompact;

impl serde_json::ser::Formatter for PyCompact {
    fn begin_array_value<W: ?Sized + std::io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_key<W: ?Sized + std::io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_value<W: ?Sized + std::io::Write>(
        &mut self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        writer.write_all(b": ")
    }
}

/// Python's `repr(float)`: shortest round-trip digits, always with a decimal
/// point or an exponent (`100.0`, `87.7`, `-0.3`).
pub fn py_float_repr(x: f64) -> String {
    if x.is_finite() && x.fract() == 0.0 && x.abs() < 1e16 {
        format!("{x:.1}")
    } else {
        serde_json::to_string(&x).unwrap_or_else(|_| x.to_string())
    }
}

/// Python's `round(x, ndigits)`: the double nearest the correctly-rounded
/// decimal. Rust's `{:.N}` formatting is the same correctly-rounded
/// conversion, so parsing it back yields the identical double.
pub fn py_round(x: f64, ndigits: usize) -> f64 {
    format!("{x:.ndigits$}").parse().unwrap_or(x)
}

#[cfg(test)]
mod tests {
    use super::{dumps_compact, dumps_pretty, py_float_repr, py_round};

    #[test]
    fn compact_uses_python_default_separators() {
        let v: serde_json::Value =
            serde_json::from_str("{\"a\": [1, 2.5, null], \"b\": {\"c\": \"\u{e9}\"}}").unwrap();
        assert_eq!(
            dumps_compact(&v, true),
            "{\"a\": [1, 2.5, null], \"b\": {\"c\": \"\\u00e9\"}}"
        );
        assert_eq!(
            dumps_compact(&v, false),
            "{\"a\": [1, 2.5, null], \"b\": {\"c\": \"\u{e9}\"}}"
        );
    }

    #[test]
    fn float_repr_and_round_match_python() {
        assert_eq!(py_float_repr(100.0), "100.0");
        assert_eq!(py_float_repr(87.7), "87.7");
        assert_eq!(py_float_repr(-0.3), "-0.3");
        assert_eq!(py_round(0.8999999999999999, 2), 0.9);
        assert_eq!(py_round(87.25, 1), 87.2);
        assert_eq!(py_round(0.35, 1), 0.3);
    }

    #[test]
    fn escapes_non_ascii_like_python() {
        assert_eq!(
            dumps_pretty(&"\u{e9} \u{2014} \u{1f600}"),
            "\"\\u00e9 \\u2014 \\ud83d\\ude00\""
        );
        assert_eq!(dumps_pretty(&"\x7f"), "\"\\u007f\"");
    }
}
