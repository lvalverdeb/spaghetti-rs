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

#[cfg(test)]
mod tests {
    use super::dumps_pretty;

    #[test]
    fn escapes_non_ascii_like_python() {
        assert_eq!(
            dumps_pretty(&"\u{e9} \u{2014} \u{1f600}"),
            "\"\\u00e9 \\u2014 \\ud83d\\ude00\""
        );
        assert_eq!(dumps_pretty(&"\x7f"), "\"\\u007f\"");
    }
}
