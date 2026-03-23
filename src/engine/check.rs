use crate::{
    errors::Result,
    json,
    registry::{self, Format},
};
use std::path::Path;

/// A single validation failure returned by the jsonschema crate.
#[derive(Debug)]
pub struct ValidationFailure {
    /// JSON Pointer to the failing field (e.g. `/statements/0/status`).
    pub instance_path: String,
    /// Human-readable description of the failure.
    pub message: String,
}

/// The outcome of running `check` against one file.
#[derive(Debug)]
pub struct CheckResult {
    pub path: String,
    pub format: Format,
    pub failures: Vec<ValidationFailure>,
}

impl CheckResult {
    pub fn is_valid(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Validate an already-parsed JSON value against the schema for `format`.
///
/// Returns a `CheckResult` with zero failures when the document is valid.
/// Returns `EvidgerError` only for hard errors (schema compilation, etc.), not
/// for validation failures — those are collected into `CheckResult::failures`.
pub fn check_value(value: &serde_json::Value, format: &Format) -> Result<Vec<ValidationFailure>> {
    let validator = registry::compiled_validator_for(format)?;

    let failures = validator
        .iter_errors(value)
        .map(|e| ValidationFailure {
            instance_path: e.instance_path.to_string(),
            message: e.to_string(),
        })
        .collect();

    Ok(failures)
}

/// Load a JSON file, detect its format, and validate it against the
/// corresponding embedded schema.
pub fn check_file(path: &Path) -> Result<CheckResult> {
    let value = json::load_json(path)?;
    let format = registry::detect_format(&value)?;
    let failures = check_value(&value, &format)?;

    Ok(CheckResult {
        path: path.display().to_string(),
        format,
        failures,
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Minimal valid OpenVEX document that satisfies every required field and
    /// every conditional constraint (status "fixed" has no extra requirements).
    fn valid_openvex() -> serde_json::Value {
        json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id":      "https://example.com/vex/test-1",
            "author":   "Test Author",
            "timestamp":"2024-01-01T00:00:00Z",
            "version":  1,
            "statements": [{
                "vulnerability": { "name": "CVE-2024-0001" },
                "products":      [{ "identifiers": { "purl": "pkg:npm/foo@1.0.0" } }],
                "status":        "fixed"
            }]
        })
    }

    // ── valid document ────────────────────────────────────────────────────────

    #[test]
    fn valid_openvex_passes() {
        let doc = valid_openvex();
        let failures = check_value(&doc, &Format::OpenVex).expect("check_value must not error");
        assert!(
            failures.is_empty(),
            "expected no failures, got: {failures:#?}"
        );
    }

    // ── missing required field ────────────────────────────────────────────────

    #[test]
    fn missing_required_field_fails() {
        let mut doc = valid_openvex();
        // Remove the top-level required field "author"
        doc.as_object_mut().unwrap().remove("author");

        let failures = check_value(&doc, &Format::OpenVex).expect("check_value must not error");
        assert!(
            !failures.is_empty(),
            "expected a failure for missing 'author' field"
        );
        let mentions_author = failures
            .iter()
            .any(|f| f.message.contains("author") || f.instance_path.contains("author"));
        assert!(
            mentions_author,
            "failure message should mention 'author'; got: {failures:#?}"
        );
    }

    // ── additional (unknown) field ────────────────────────────────────────────

    #[test]
    fn extra_field_fails() {
        let mut doc = valid_openvex();
        // Inject a field not in the schema — additionalProperties: false must catch it
        doc.as_object_mut()
            .unwrap()
            .insert("unknown_field".to_string(), json!("surprise"));

        let failures = check_value(&doc, &Format::OpenVex).expect("check_value must not error");
        assert!(
            !failures.is_empty(),
            "expected a failure for unknown field 'unknown_field'"
        );
    }
}
