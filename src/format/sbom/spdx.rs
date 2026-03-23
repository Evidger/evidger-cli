use crate::models::{Component, SbomDocument};
use serde_json::{json, Value};

/// Serialize a normalised `SbomDocument` into an SPDX 3.0 JSON-LD value.
pub fn serialize(doc: &SbomDocument) -> Value {
    let creation_info = json!({
        "type": "CreationInfo",
        "@id": "_:ci",
        "specVersion": "3.0.0",
        "created": "1970-01-01T00:00:00Z",
        "createdBy": ["https://spdx.org/tools-bin/evidger-cli"]
    });

    let packages: Vec<Value> = doc.components.iter().map(serialize_package).collect();

    let mut graph = vec![creation_info];
    graph.extend(packages);

    json!({
        "@context": "https://spdx.org/rdf/3.0.0/spdx-context.jsonld",
        "@graph": graph
    })
}

fn serialize_package(c: &Component) -> Value {
    let spdx_id = format!("https://example.com/pkg/{}", c.name.replace(' ', "-"));
    let mut pkg = json!({
        "type": "software_Package",
        "spdxId": spdx_id,
        "creationInfo": "_:ci",
        "name": c.name,
    });
    if let Some(v) = &c.version {
        pkg["software_packageVersion"] = Value::String(v.clone());
    }
    if let Some(p) = &c.purl {
        pkg["externalIdentifier"] = json!([{
            "type": "ExternalIdentifier",
            "externalIdentifierType": "packageUrl",
            "identifier": p
        }]);
    }
    pkg
}

/// Parse an SPDX 3.0 JSON-LD document into a normalised `SbomDocument`.
/// Extracts all `software_Package` elements from the `@graph` array.
pub fn parse(value: &Value) -> SbomDocument {
    let components = value
        .get("@graph")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter(|e| {
                    e.get("type").and_then(Value::as_str) == Some("software_Package")
                })
                .map(parse_package)
                .collect()
        })
        .unwrap_or_default();

    SbomDocument {
        format: "SPDX".into(),
        spec_version: None,
        serial_number: None,
        version: None,
        components,
    }
}

fn parse_package(v: &Value) -> Component {
    let name = v
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let version = v
        .get("software_packageVersion")
        .and_then(Value::as_str)
        .map(String::from);

    // purl from externalIdentifier with externalIdentifierType "packageUrl"
    let purl = v
        .get("externalIdentifier")
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter().find(|e| {
                e.get("externalIdentifierType").and_then(Value::as_str) == Some("packageUrl")
            })
        })
        .and_then(|e| e.get("identifier").and_then(Value::as_str))
        .map(String::from)
        // fallback: software_packageUrl field
        .or_else(|| {
            v.get("software_packageUrl")
                .and_then(Value::as_str)
                .map(String::from)
        });

    let spdx_id = v.get("spdxId").and_then(Value::as_str).map(String::from);

    Component {
        name,
        version,
        purl,
        bom_ref: spdx_id,
    }
}
