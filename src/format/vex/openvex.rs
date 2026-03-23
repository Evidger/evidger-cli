use crate::models::{Component, Vulnerability, VexDocument, VexStatement, VexStatus};
use serde_json::{json, Value};

/// Parse an OpenVEX JSON document into a normalised `VexDocument`.
/// Missing optional fields are silently ignored.
pub fn parse(value: &Value) -> VexDocument {
    let id = value.get("@id").and_then(Value::as_str).map(String::from);
    let author = value.get("author").and_then(Value::as_str).map(String::from);
    let timestamp = value
        .get("timestamp")
        .and_then(Value::as_str)
        .map(String::from);
    let version = value
        .get("version")
        .and_then(Value::as_u64)
        .map(|v| v as u32);

    let statements = value
        .get("statements")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_statement).collect())
        .unwrap_or_default();

    VexDocument {
        id,
        author,
        timestamp,
        version,
        statements,
    }
}

/// Serialize a normalised `VexDocument` into an OpenVEX 0.2.0 JSON value.
pub fn serialize(doc: &VexDocument) -> Value {
    let statements: Vec<Value> = doc.statements.iter().map(serialize_statement).collect();
    let mut out = json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": doc.id.as_deref().unwrap_or("https://openvex.dev/docs/public/merged"),
        "author": doc.author.as_deref().unwrap_or("evidger-cli"),
        "version": doc.version.unwrap_or(1),
        "statements": statements,
    });
    if let Some(ts) = &doc.timestamp {
        out["timestamp"] = Value::String(ts.clone());
    }
    out
}

fn serialize_statement(stmt: &VexStatement) -> Value {
    let mut vuln = json!({ "name": stmt.vulnerability.id });
    if let Some(d) = &stmt.vulnerability.description {
        vuln["description"] = Value::String(d.clone());
    }

    let mut obj = json!({
        "vulnerability": vuln,
        "products": [],
        "status": stmt.status.to_string(),
    });
    if let Some(j) = &stmt.justification {
        obj["justification"] = Value::String(j.clone());
    }
    if let Some(i) = &stmt.impact_statement {
        obj["impact_statement"] = Value::String(i.clone());
    }
    if let Some(a) = &stmt.action_statement {
        obj["action_statement"] = Value::String(a.clone());
    }
    obj
}

fn parse_statement(v: &Value) -> VexStatement {
    let vuln = v.get("vulnerability").unwrap_or(&Value::Null);

    let vulnerability = Vulnerability {
        id: vuln
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        description: vuln
            .get("description")
            .and_then(Value::as_str)
            .map(String::from),
        severity: None,
        aliases: vuln
            .get("aliases")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
    };

    let status = match v.get("status").and_then(Value::as_str).unwrap_or("") {
        "not_affected" => VexStatus::NotAffected,
        "affected" => VexStatus::Affected,
        "fixed" => VexStatus::Fixed,
        _ => VexStatus::UnderInvestigation,
    };

    let products = v
        .get("products")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_product).collect())
        .unwrap_or_default();

    VexStatement {
        vulnerability,
        products,
        status,
        justification: v
            .get("justification")
            .and_then(Value::as_str)
            .map(String::from),
        impact_statement: v
            .get("impact_statement")
            .and_then(Value::as_str)
            .map(String::from),
        action_statement: v
            .get("action_statement")
            .and_then(Value::as_str)
            .map(String::from),
    }
}

fn parse_product(v: &Value) -> Component {
    let purl = v
        .get("identifiers")
        .and_then(|i| i.get("purl"))
        .and_then(Value::as_str)
        .map(String::from);

    let id = v.get("@id").and_then(Value::as_str).map(String::from);

    // Use purl or @id as the display name when no explicit name field is present
    let name = purl
        .clone()
        .or_else(|| id.clone())
        .unwrap_or_default();

    Component {
        name,
        version: None,
        purl,
        bom_ref: id,
    }
}
