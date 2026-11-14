//! Incremental per-file cache: skip the per-file checks for unchanged files —
//! mirrors `spaghetti/cache.py`.
//!
//! An entry is keyed by the SHA-1 of a file's text (and, unlike the Python
//! port, its path and package — see `FileCache::path`) and lives under a
//! directory named by the *configuration key* — a hash of the applied
//! settings, the tool version and the Python language version the checks
//! model — so changing a threshold or upgrading invalidates everything at
//! once without a manifest. An entry holds exactly what the scanner produces
//! for a file before finalisation: raw findings (byte-offset columns, no
//! fingerprints), the Maintainability Index, the function count, the two
//! workspace transports (raw imports, token stream) and the per-file facts
//! the package-level checks combine. A hit therefore needs no parse at all.
//!
//! Entries are written atomically (temp file + rename) so concurrent package
//! scans can share one directory, and any unreadable or mismatching entry is
//! a miss, never an error.
//!
//! The entry JSON has the same shape as the Python port's (`schema_version`
//! 2), so either can be inspected the same way. The configuration key has the
//! same structure (`{"schema", "tool", "python", "overrides"}`, canonical
//! JSON, first 16 hex digits of its SHA-1) but is deliberately never equal to
//! Python's: `tool` is `"<version>-rs"`, and the overrides are this port's
//! own serialisation. The two tools therefore never read each other's
//! entries, even when pointed at the same `.spaghetti/cache`.

use crate::checks::package_level::FileFacts;
use crate::checks::workspace_level::RawImport;
use crate::clones::TokenStream;
use crate::config::{RuleSetting, ThresholdValue};
use crate::models::{Issue, Severity};
use crate::rules::rule_meta;
use crate::settings::Settings;
use serde_json::{Map, Value, json};
use sha1::{Digest, Sha1};
use std::borrow::Cow;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const CACHE_SCHEMA_VERSION: u64 = 2;
pub const DEFAULT_CACHE_DIR: &str = ".spaghetti/cache";
/// The Python version whose `ast` semantics the checks reproduce.
pub const PYTHON_VERSION: [u64; 2] = [3, 13];

/// The overrides a run applies — the shape of Python's
/// `settings.to_overrides(settings)`.
pub fn overrides_json(settings: &Settings) -> Value {
    let thresholds: Map<String, Value> = settings
        .thresholds
        .iter()
        .map(|(k, v)| {
            let v = match v {
                ThresholdValue::Int(i) => json!(i),
                ThresholdValue::Float(f) => json!(f),
            };
            (k.clone(), v)
        })
        .collect();
    let rules: Map<String, Value> = settings
        .rules
        .iter()
        .map(|(k, v)| {
            let v = match v {
                RuleSetting::Off => "off",
                RuleSetting::Severity(s) => s.as_str(),
            };
            (k.clone(), json!(v))
        })
        .collect();
    let contracts: Vec<Value> = settings
        .contracts
        .iter()
        .map(|c| {
            json!({
                "name": c.name,
                "type": format!("{:?}", c.kind).to_lowercase(),
                "source": c.source,
                "forbidden": c.forbidden,
                "allow": c.allow,
                "layers": c.layers,
            })
        })
        .collect();
    json!({
        "thresholds": thresholds,
        "rules": rules,
        "layers": settings.layers,
        "library_packages": settings.library_packages,
        "contracts": contracts,
    })
}

/// `json.dumps(value, sort_keys=True)`: `", "` / `": "` separators, keys
/// sorted at every level, non-ASCII escaped.
fn canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                canonical_json(&Value::String(k.clone()), out);
                out.push_str(": ");
                canonical_json(&map[k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                canonical_json(v, out);
            }
            out.push(']');
        }
        Value::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                        let mut buf = [0u16; 2];
                        for unit in c.encode_utf16(&mut buf) {
                            out.push_str(&format!("\\u{unit:04x}"));
                        }
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// Hash of everything that changes a per-file result other than the file.
pub fn cache_key(overrides: &Value, tool_version: &str) -> String {
    let material = json!({
        "schema": CACHE_SCHEMA_VERSION,
        "tool": format!("{tool_version}-rs"),
        "python": PYTHON_VERSION,
        "overrides": overrides,
    });
    let mut text = String::new();
    canonical_json(&material, &mut text);
    let digest = Sha1::digest(text.as_bytes());
    hex(&digest)[..16].to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Everything the scanner produced for one file before finalisation —
/// mirrors `cache.FileEntry`.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub issues: Vec<Issue>,
    pub parsed: bool,
    pub functions: usize,
    pub mi: Option<f64>,
    pub raw_imports: Option<Vec<RawImport>>,
    pub tokens: Option<TokenStream>,
    pub facts: Option<FileFacts>,
}

impl FileEntry {
    pub fn to_json(&self) -> Value {
        let issues: Vec<Value> = self
            .issues
            .iter()
            .map(|i| {
                json!({
                    "rule": i.rule,
                    "line": i.line,
                    "severity": i.severity.as_str(),
                    "message": i.message,
                    "column": i.column,
                    "end_line": i.end_line,
                    "end_column": i.end_column,
                })
            })
            .collect();
        let raw_imports = self.raw_imports.as_ref().map(|imports| {
            imports
                .iter()
                .map(|r| {
                    // Python stores -1 for a plain `import a.b`.
                    let level = r.level.map_or(json!(-1), |l| json!(l));
                    json!([level, r.module, r.names, r.line])
                })
                .collect::<Vec<Value>>()
        });
        let tokens = self.tokens.as_ref().map(|t| json!([t.names, t.lines]));
        json!({
            "schema_version": CACHE_SCHEMA_VERSION,
            "issues": issues,
            "parsed": self.parsed,
            "functions": self.functions,
            "mi": self.mi,
            "raw_imports": raw_imports,
            "tokens": tokens,
            "facts": self.facts.as_ref().map(FileFacts::to_json),
        })
    }

    /// `None` for anything that does not have exactly the expected shape.
    pub fn from_json(data: &Value, file: &Path, package: &str) -> Option<FileEntry> {
        if data.get("schema_version")?.as_u64()? != CACHE_SCHEMA_VERSION {
            return None;
        }
        let issues = data
            .get("issues")?
            .as_array()?
            .iter()
            .map(|i| {
                let rule = rule_meta(i.get("rule")?.as_str()?)?.id;
                let severity = match i.get("severity")?.as_str()? {
                    "info" => Severity::Info,
                    "warning" => Severity::Warning,
                    "error" => Severity::Error,
                    _ => return None,
                };
                let opt = |key: &str| -> Option<Option<usize>> {
                    match i.get(key)? {
                        Value::Null => Some(None),
                        v => Some(Some(usize::try_from(v.as_u64()?).ok()?)),
                    }
                };
                let mut issue = Issue::new(
                    file,
                    usize::try_from(i.get("line")?.as_u64()?).ok()?,
                    severity,
                    rule,
                    package,
                    i.get("message")?.as_str()?.to_string(),
                );
                issue.column = opt("column")?;
                issue.end_line = opt("end_line")?;
                issue.end_column = opt("end_column")?;
                Some(issue)
            })
            .collect::<Option<Vec<Issue>>>()?;
        let raw_imports = match data.get("raw_imports")? {
            Value::Null => None,
            v => Some(
                v.as_array()?
                    .iter()
                    .map(|r| {
                        let r = r.as_array()?;
                        if r.len() != 4 {
                            return None;
                        }
                        let level = r[0].as_i64()?;
                        let module = match &r[1] {
                            Value::Null => None,
                            m => Some(m.as_str()?.to_string()),
                        };
                        let names = r[2]
                            .as_array()?
                            .iter()
                            .map(|n| n.as_str().map(str::to_string))
                            .collect::<Option<Vec<String>>>()?;
                        Some(RawImport {
                            level: if level < 0 {
                                None
                            } else {
                                Some(usize::try_from(level).ok()?)
                            },
                            module,
                            names,
                            line: usize::try_from(r[3].as_u64()?).ok()?,
                        })
                    })
                    .collect::<Option<Vec<RawImport>>>()?,
            ),
        };
        let tokens = match data.get("tokens")? {
            Value::Null => None,
            v => {
                let pair = v.as_array()?;
                if pair.len() != 2 {
                    return None;
                }
                let names = pair[0]
                    .as_array()?
                    .iter()
                    .map(|n| {
                        let name = n.as_str()?;
                        if name.starts_with(crate::clones::BOUNDARY_PREFIX) {
                            Some(Cow::Owned(name.to_owned()))
                        } else {
                            crate::pyast::intern_token_name(name).map(Cow::Borrowed)
                        }
                    })
                    .collect::<Option<Vec<Cow<'static, str>>>>()?;
                let lines = pair[1]
                    .as_array()?
                    .iter()
                    .map(|l| usize::try_from(l.as_u64()?).ok())
                    .collect::<Option<Vec<usize>>>()?;
                if names.len() != lines.len() {
                    return None;
                }
                Some(TokenStream { names, lines })
            }
        };
        let mi = match data.get("mi")? {
            Value::Null => None,
            v => Some(v.as_f64()?),
        };
        let facts = match data.get("facts")? {
            Value::Null => None,
            v => Some(FileFacts::from_json(v)?),
        };
        Some(FileEntry {
            issues,
            parsed: data.get("parsed")?.as_bool()?,
            functions: usize::try_from(data.get("functions")?.as_u64()?).ok()?,
            mi,
            raw_imports,
            tokens,
            facts,
        })
    }
}

/// One configuration's entry directory — mirrors `cache.FileCache`.
#[derive(Debug, Clone)]
pub struct FileCache {
    pub dir: PathBuf,
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl FileCache {
    pub fn new(root: &Path, key: &str) -> Self {
        FileCache {
            dir: root.join(key),
        }
    }

    /// The entry for `source` as `file` of `package`. The file's identity is
    /// part of the hash because several per-file checks depend on it (test
    /// files, `__init__.py`, the module path, layer rules), so two identical
    /// files at different paths must not share an entry.
    fn path(&self, source: &str, file: &Path, package: &str) -> PathBuf {
        let mut hasher = Sha1::new();
        hasher.update(package.as_bytes());
        hasher.update([0]);
        hasher.update(file.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(source.as_bytes());
        self.dir.join(format!("{}.json", hex(&hasher.finalize())))
    }

    pub fn load(&self, source: &str, file: &Path, package: &str) -> Option<FileEntry> {
        let text = std::fs::read_to_string(self.path(source, file, package)).ok()?;
        let data: Value = serde_json::from_str(&text).ok()?;
        FileEntry::from_json(&data, file, package)
    }

    /// Write `entry` atomically; a cache that cannot be written is a cache
    /// that misses, so every failure is silent.
    pub fn store(&self, source: &str, file: &Path, package: &str, entry: &FileEntry) {
        let _ = self.try_store(self.path(source, file, package), entry);
    }

    fn try_store(&self, target: PathBuf, entry: &FileEntry) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let tmp = self.dir.join(format!(
            ".{}-{}-{:?}.tmp",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
            std::thread::current().id()
        ));
        let result = (|| {
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(entry.to_json().to_string().as_bytes())?;
            std::fs::rename(&tmp, &target)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{cache_key, canonical_json};
    use serde_json::json;

    #[test]
    fn key_covers_settings_and_tool_version() {
        let base = cache_key(&json!({"thresholds": {"MAX_FUNCTION_LINES": 50}}), "2.3.0");
        assert_eq!(base.len(), 16);
        assert_ne!(
            cache_key(&json!({"thresholds": {"MAX_FUNCTION_LINES": 51}}), "2.3.0"),
            base
        );
        assert_ne!(
            cache_key(&json!({"thresholds": {"MAX_FUNCTION_LINES": 50}}), "2.3.1"),
            base
        );
        assert_eq!(
            cache_key(&json!({"thresholds": {"MAX_FUNCTION_LINES": 50}}), "2.3.0"),
            base
        );
    }

    #[test]
    fn canonical_json_matches_python_sort_keys() {
        let mut out = String::new();
        canonical_json(
            &json!({"b": [1, 2.5, null], "a": {"y": true, "x": "é\""}}),
            &mut out,
        );
        // json.dumps({"b": [1, 2.5, None], "a": {"y": True, "x": "é\""}}, sort_keys=True)
        assert_eq!(
            out,
            "{\"a\": {\"x\": \"\\u00e9\\\"\", \"y\": true}, \"b\": [1, 2.5, null]}"
        );
    }
}
