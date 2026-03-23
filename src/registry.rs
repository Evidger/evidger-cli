use crate::errors::{EvidgerError, Result};
use serde_json::Value;
use std::sync::OnceLock;

// Schemas are embedded into the binary at compile time.
const CYCLONEDX_SCHEMA: &str = include_str!("schemas/cyclonedx_json_schema.json");
const SPDX_SCHEMA: &str = include_str!("schemas/spdx_json_schema.json");
const OPENVEX_SCHEMA: &str = include_str!("schemas/openvex_json_schema.json");
const CSAF_SCHEMA: &str = include_str!("schemas/csaf_json_schema.json");

// Compiled validators — initialised once on first use, reused afterwards.
static CYCLONEDX_VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
static SPDX_VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
static OPENVEX_VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
static CSAF_VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();

/// The set of formats that evidger understands.
/// Also used as the `--to` argument of the `convert` command.
#[derive(Debug, Clone, PartialEq, clap::ValueEnum)]
pub enum Format {
    #[value(name = "cyclonedx")]
    CycloneDx,
    #[value(name = "spdx")]
    Spdx,
    #[value(name = "openvex")]
    OpenVex,
    #[value(name = "csaf")]
    Csaf,
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Format::CycloneDx => write!(f, "CycloneDX"),
            Format::Spdx => write!(f, "SPDX"),
            Format::OpenVex => write!(f, "OpenVEX"),
            Format::Csaf => write!(f, "CSAF"),
        }
    }
}

/// Detect the format of a parsed JSON document by inspecting well-known fields.
///
/// - CycloneDX:  `"bomFormat": "CycloneDX"`
/// - SPDX:       presence of `"spdxVersion"`
/// - OpenVEX:    `"@context"` containing `"openvex"`
///
/// Returns `EvidgerError::UnsupportedFormat` when no marker is recognised.
pub fn detect_format(value: &Value) -> Result<Format> {
    if value
        .get("bomFormat")
        .and_then(Value::as_str)
        .map(|s| s.eq_ignore_ascii_case("CycloneDX"))
        .unwrap_or(false)
    {
        return Ok(Format::CycloneDx);
    }

    // SPDX 2.x uses `spdxVersion`; SPDX 3.0 uses `@context` pointing to spdx.org
    if value.get("spdxVersion").is_some()
        || value
            .get("@context")
            .and_then(Value::as_str)
            .map(|s| s.contains("spdx.org"))
            .unwrap_or(false)
    {
        return Ok(Format::Spdx);
    }

    if value
        .get("@context")
        .and_then(Value::as_str)
        .map(|s| s.contains("openvex"))
        .unwrap_or(false)
    {
        return Ok(Format::OpenVex);
    }

    // CSAF 2.0 documents have `document.csaf_version == "2.0"`
    if value
        .get("document")
        .and_then(|d| d.get("csaf_version"))
        .and_then(Value::as_str)
        == Some("2.0")
    {
        return Ok(Format::Csaf);
    }

    Err(EvidgerError::UnsupportedFormat(
        "no known format marker found (expected bomFormat, spdxVersion, @context, or document.csaf_version)".to_string(),
    ))
}

/// Return a compiled `jsonschema::Validator` for the given format.
///
/// Schemas are parsed and compiled once (on first call per format) and cached
/// for the lifetime of the process.  Subsequent calls return the same instance.
///
/// # Panics
/// Panics if an embedded schema fails to parse or compile — this would be a
/// programming error, not a user error.
pub fn compiled_validator_for(format: &Format) -> Result<&'static jsonschema::Validator> {
    let (schema_str, cell) = match format {
        Format::CycloneDx => (CYCLONEDX_SCHEMA, &CYCLONEDX_VALIDATOR),
        Format::Spdx => (SPDX_SCHEMA, &SPDX_VALIDATOR),
        Format::OpenVex => (OPENVEX_SCHEMA, &OPENVEX_VALIDATOR),
        Format::Csaf => (CSAF_SCHEMA, &CSAF_VALIDATOR),
    };

    let validator = cell.get_or_init(|| compile(schema_str));
    Ok(validator)
}

/// Parse a schema string and compile it into a `Validator`.
///
/// Uses `EmbeddedRetriever` so that any `$ref` pointing to an external URL
/// (e.g. `http://cyclonedx.org/schema/jsf-0.82.schema.json`) is resolved
/// without making a network request.  Unknown external schemas are treated as
/// the JSON Schema `true` (accepts everything), preserving all constraints
/// that are defined inside the embedded schema itself.
///
/// The parsed `Value` is leaked to give it a `'static` lifetime, which allows
/// the compiled `Validator` to be stored in a `OnceLock`.
fn compile(schema_str: &str) -> jsonschema::Validator {
    let value: &'static Value = Box::leak(Box::new(
        serde_json::from_str(schema_str).expect("embedded schema must be valid JSON"),
    ));
    jsonschema::options()
        .with_retriever(EmbeddedRetriever)
        .build(value)
        .expect("embedded schema must be a valid JSON Schema")
}

/// A `Retrieve` implementation that never makes network or filesystem calls.
///
/// The CycloneDX 1.7 schema references three companion schemas via relative
/// `$ref` URIs.  We return minimal stub schemas that define only the
/// properties those `$ref` pointers actually dereference into — just enough
/// for the validator to compile while keeping the binary self-contained.
///
/// Any URI we do not recognise is answered with the JSON Schema `true`
/// (accept everything).
struct EmbeddedRetriever;

impl jsonschema::Retrieve for EmbeddedRetriever {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let s = uri.to_string();

        // cyclonedx.org/schema/cryptography-defs.schema.json
        //   referenced as: cryptography-defs.schema.json#/definitions/algorithmFamiliesEnum
        //                   cryptography-defs.schema.json#/definitions/ellipticCurvesEnum
        if s.contains("cryptography-defs") {
            return Ok(serde_json::json!({
                "definitions": {
                    "algorithmFamiliesEnum": { "type": "string" },
                    "ellipticCurvesEnum":    { "type": "string" }
                }
            }));
        }

        // cyclonedx.org/schema/jsf-0.82.schema.json
        //   referenced as: jsf-0.82.schema.json#/definitions/signature
        if s.contains("jsf-0.82") {
            return Ok(serde_json::json!({
                "definitions": {
                    "signature": { "type": "object" }
                }
            }));
        }

        // cyclonedx.org/schema/spdx.schema.json — used whole as a type schema.
        // Returning `true` is fine: any SPDX expression string passes.
        Ok(serde_json::json!(true))
    }
}
