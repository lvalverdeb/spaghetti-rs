//! Architecture contracts: the one custom rule most teams actually want —
//! mirrors `spaghetti/contracts.py`.
//!
//! A contract names module prefixes and states which may not import which —
//! the `import-linter` / `Tach` idea, evaluated on the workspace import graph
//! spaghetti already builds. Two kinds:
//!
//! - `forbidden`: modules under any `source` prefix must not import anything
//!   under a `forbidden` prefix (third-party names included), except `allow`.
//! - `layers`: an ordered list, highest first. A module may import its own
//!   layer and lower layers; importing a *higher* layer is a violation.
//!
//! Configured as a list of tables:
//!
//! ```toml
//! [[tool.spaghetti.contracts]]
//! name = "domain stays framework-free"
//! type = "forbidden"
//! source = ["shop.domain"]
//! forbidden = ["shop.transport", "fastapi", "sqlalchemy"]
//!
//! [[tool.spaghetti.contracts]]
//! name = "clean layering"
//! type = "layers"
//! layers = ["shop.api", "shop.service", "shop.domain"]
//! ```

use serde_json::Value;
use std::fmt;

pub const CONTRACT_KINDS: &[&str] = &["forbidden", "layers"];
const KEYS: &[&str] = &["name", "type", "source", "forbidden", "allow", "layers"];

/// A contract table is malformed; the message names the contract and key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractError(pub String);

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ContractError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractKind {
    Forbidden,
    Layers,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contract {
    pub name: String,
    pub kind: ContractKind,
    pub source: Vec<String>,
    pub forbidden: Vec<String>,
    pub allow: Vec<String>,
    pub layers: Vec<String>,
}

impl Contract {
    pub fn forbidden(name: &str, source: &[&str], forbidden: &[&str], allow: &[&str]) -> Self {
        let owned = |v: &[&str]| v.iter().map(|s| s.to_string()).collect();
        Contract {
            name: name.to_string(),
            kind: ContractKind::Forbidden,
            source: owned(source),
            forbidden: owned(forbidden),
            allow: owned(allow),
            layers: Vec::new(),
        }
    }

    pub fn layered(name: &str, layers: &[&str]) -> Self {
        Contract {
            name: name.to_string(),
            kind: ContractKind::Layers,
            source: Vec::new(),
            forbidden: Vec::new(),
            allow: Vec::new(),
            layers: layers.iter().map(|s| s.to_string()).collect(),
        }
    }
}

fn under(module: &str, prefix: &str) -> bool {
    module == prefix
        || (module.len() > prefix.len()
            && module.starts_with(prefix)
            && module.as_bytes()[prefix.len()] == b'.')
}

/// Index of the layer `module` belongs to (0 = highest), or `None`.
fn layer_of(module: &str, layers: &[String]) -> Option<usize> {
    layers.iter().position(|prefix| under(module, prefix))
}

/// Why `module` importing `target` breaks `contract`, or `None` if it doesn't.
pub fn violation_reason(contract: &Contract, module: &str, target: &str) -> Option<String> {
    match contract.kind {
        ContractKind::Forbidden => {
            if !contract.source.iter().any(|s| under(module, s)) {
                return None;
            }
            if contract.allow.iter().any(|a| under(target, a)) {
                return None;
            }
            contract
                .forbidden
                .iter()
                .find(|f| under(target, f))
                .map(|hit| format!("'{hit}' is forbidden for '{module}'"))
        }
        ContractKind::Layers => {
            let source_layer = layer_of(module, &contract.layers)?;
            let target_layer = layer_of(target, &contract.layers)?;
            if target_layer >= source_layer {
                return None;
            }
            Some(format!(
                "layer '{}' may not depend on the higher layer '{}'",
                contract.layers[source_layer], contract.layers[target_layer]
            ))
        }
    }
}

fn str_list(value: Option<&Value>, place: &str) -> Result<Vec<String>, ContractError> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items))
            if items
                .iter()
                .all(|v| v.as_str().is_some_and(|s| !s.is_empty())) =>
        {
            Ok(items
                .iter()
                .map(|v| v.as_str().unwrap_or_default().to_string())
                .collect())
        }
        Some(_) => Err(ContractError(format!(
            "{place} must be a list of non-empty strings"
        ))),
    }
}

/// Validate the `contracts` setting (a list of tables) — mirrors
/// `contracts.py::parse_contracts`, message for message.
pub fn parse_contracts(data: &Value, origin: &str) -> Result<Vec<Contract>, ContractError> {
    let Some(tables) = data.as_array() else {
        return Err(ContractError(format!(
            "{origin}: contracts must be a list of tables"
        )));
    };
    let mut contracts = Vec::new();
    for (i, table) in tables.iter().enumerate() {
        let place = format!("{origin}: contracts[{}]", i + 1);
        let Some(table) = table.as_object() else {
            return Err(ContractError(format!("{place} must be a table")));
        };
        let mut unknown: Vec<&str> = table
            .keys()
            .map(String::as_str)
            .filter(|k| !KEYS.contains(k))
            .collect();
        if !unknown.is_empty() {
            unknown.sort_unstable();
            return Err(ContractError(format!(
                "{place}: unknown key(s) {}",
                unknown.join(", ")
            )));
        }
        let name = match table.get("name").and_then(Value::as_str) {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => return Err(ContractError(format!("{place}: name is required"))),
        };
        let kind = match table.get("type").and_then(Value::as_str) {
            Some("forbidden") => ContractKind::Forbidden,
            Some("layers") => ContractKind::Layers,
            _ => {
                return Err(ContractError(format!(
                    "{place}: type must be one of {}",
                    CONTRACT_KINDS.join(", ")
                )));
            }
        };
        let contract = Contract {
            name,
            kind,
            source: str_list(table.get("source"), &format!("{place}.source"))?,
            forbidden: str_list(table.get("forbidden"), &format!("{place}.forbidden"))?,
            allow: str_list(table.get("allow"), &format!("{place}.allow"))?,
            layers: str_list(table.get("layers"), &format!("{place}.layers"))?,
        };
        if kind == ContractKind::Forbidden
            && (contract.source.is_empty() || contract.forbidden.is_empty())
        {
            return Err(ContractError(format!(
                "{place}: a forbidden contract needs source and forbidden"
            )));
        }
        if kind == ContractKind::Layers && contract.layers.len() < 2 {
            return Err(ContractError(format!(
                "{place}: a layers contract needs at least two layers"
            )));
        }
        contracts.push(contract);
    }
    Ok(contracts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> (Contract, Contract) {
        (
            Contract::forbidden(
                "no fw",
                &["shop.domain"],
                &["shop.transport", "fastapi"],
                &["fastapi.encoders"],
            ),
            Contract::layered("layering", &["shop.api", "shop.service", "shop.domain"]),
        )
    }

    #[test]
    fn violation_reason_matches_python() {
        let (forbidden, layers) = fixtures();
        let cases: &[(&Contract, &str, &str, Option<&str>)] = &[
            (
                &forbidden,
                "shop.domain.order",
                "shop.transport.http",
                Some("'shop.transport' is forbidden for 'shop.domain.order'"),
            ),
            (
                &forbidden,
                "shop.domain.order",
                "fastapi",
                Some("'fastapi' is forbidden for 'shop.domain.order'"),
            ),
            (&forbidden, "shop.domain.order", "fastapi.encoders", None),
            (&forbidden, "shop.domain.order", "shop.domain.money", None),
            (&forbidden, "shop.api.routes", "shop.transport.http", None),
            (&forbidden, "shop.domainx", "fastapi", None),
            (
                &layers,
                "shop.domain.order",
                "shop.api.routes",
                Some("layer 'shop.domain' may not depend on the higher layer 'shop.api'"),
            ),
            (&layers, "shop.service.checkout", "shop.domain.order", None),
            (&layers, "shop.api.routes", "shop.api.deps", None),
            (&layers, "shop.api.routes", "requests", None),
        ];
        for (contract, module, target, expected) in cases {
            assert_eq!(
                violation_reason(contract, module, target).as_deref(),
                *expected,
                "{module} -> {target}"
            );
        }
    }

    #[test]
    fn parse_contracts_validates_shape() {
        let good: Value = serde_json::from_str(
            r#"[{"name": "a", "type": "forbidden", "source": ["x"], "forbidden": ["y"]},
                {"name": "b", "type": "layers", "layers": ["x.api", "x.core"]}]"#,
        )
        .unwrap();
        let parsed = parse_contracts(&good, "pyproject.toml").unwrap();
        assert_eq!(
            parsed.iter().map(|c| c.kind).collect::<Vec<_>>(),
            [ContractKind::Forbidden, ContractKind::Layers]
        );
        let bad_cases = [
            (r#""nope""#, "must be a list"),
            (r#"[{"type": "forbidden"}]"#, "name is required"),
            (r#"[{"name": "a", "type": "deny"}]"#, "type must be one of"),
            (
                r#"[{"name": "a", "type": "forbidden", "source": ["x"]}]"#,
                "needs source and forbidden",
            ),
            (
                r#"[{"name": "a", "type": "layers", "layers": ["x"]}]"#,
                "at least two layers",
            ),
            (
                r#"[{"name": "a", "type": "layers", "layers": ["x", "y"], "bogus": 1}]"#,
                "unknown key",
            ),
            (
                r#"[{"name": "a", "type": "forbidden", "source": "x", "forbidden": ["y"]}]"#,
                "list of non-empty strings",
            ),
        ];
        for (bad, needle) in bad_cases {
            let value: Value = serde_json::from_str(bad).unwrap();
            let msg = parse_contracts(&value, "pyproject.toml")
                .unwrap_err()
                .to_string();
            assert!(msg.contains(needle), "{bad}: {msg}");
        }
    }
}
