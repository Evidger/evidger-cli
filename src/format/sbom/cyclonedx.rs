use crate::models::{Component, SbomDocument};
use serde_json::{json, Value};

/// Parse a CycloneDX JSON document into a normalised `SbomDocument`.
/// Missing optional fields are silently ignored.
pub fn parse(value: &Value) -> SbomDocument {
    let spec_version = value
        .get("specVersion")
        .and_then(Value::as_str)
        .map(String::from);

    let serial_number = value
        .get("serialNumber")
        .and_then(Value::as_str)
        .map(String::from);

    let version = value
        .get("version")
        .and_then(Value::as_u64)
        .map(|v| v as u32);

    let components = value
        .get("components")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_component).collect())
        .unwrap_or_default();

    SbomDocument {
        format: "CycloneDX".to_string(),
        spec_version,
        serial_number,
        version,
        components,
    }
}

/// Serialize a normalised `SbomDocument` into a CycloneDX 1.6 JSON value.
pub fn serialize(doc: &SbomDocument) -> Value {
    let components: Vec<Value> = doc.components.iter().map(serialize_component).collect();
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": doc.spec_version.as_deref().unwrap_or("1.6"),
        "version": doc.version.unwrap_or(1),
        "components": components,
    })
}

fn serialize_component(c: &Component) -> Value {
    let mut obj = json!({ "type": "library", "name": c.name });
    if let Some(v) = &c.version {
        obj["version"] = Value::String(v.clone());
    }
    if let Some(p) = &c.purl {
        obj["purl"] = Value::String(p.clone());
    }
    obj
}

fn parse_component(v: &Value) -> Component {
    Component {
        name: v
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        version: v.get("version").and_then(Value::as_str).map(String::from),
        purl: v.get("purl").and_then(Value::as_str).map(String::from),
        bom_ref: v.get("bom-ref").and_then(Value::as_str).map(String::from),
    }
}
