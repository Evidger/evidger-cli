pub mod sbom;
pub mod vex;

use crate::{
    errors::{EvidgerError, Result},
    models::{SbomDocument, VexDocument},
    registry::Format,
};
use serde_json::Value;

/// A parsed, normalised document — either an SBOM or a VEX.
#[derive(Debug, Clone)]
pub enum Document {
    Sbom(SbomDocument),
    Vex(VexDocument),
}

impl Document {
    pub fn kind(&self) -> &'static str {
        match self {
            Document::Sbom(_) => "SBOM",
            Document::Vex(_) => "VEX",
        }
    }
}

/// Serialize a normalised `Document` back to JSON.
/// SBOMs are written as CycloneDX 1.6; VEXes as OpenVEX 0.2.0.
pub fn serialize_document(doc: &Document) -> Value {
    match doc {
        Document::Sbom(s) => sbom::cyclonedx::serialize(s),
        Document::Vex(v) => vex::openvex::serialize(v),
    }
}

/// Serialize a normalised `Document` to the requested target `Format`.
///
/// Returns `EvidgerError::UnsupportedFormat` when the document kind is
/// incompatible with the target format (e.g. SBOM → CSAF).
pub fn serialize_as(doc: &Document, target: &Format) -> Result<Value> {
    match (doc, target) {
        (Document::Sbom(s), Format::CycloneDx) => Ok(sbom::cyclonedx::serialize(s)),
        (Document::Sbom(s), Format::Spdx) => Ok(sbom::spdx::serialize(s)),
        (Document::Vex(v), Format::OpenVex) => Ok(vex::openvex::serialize(v)),
        (Document::Vex(v), Format::Csaf) => Ok(vex::csaf::serialize(v)),
        (doc, target) => Err(EvidgerError::UnsupportedFormat(format!(
            "cannot convert a {} document to {} format",
            doc.kind(),
            target
        ))),
    }
}

/// Dispatch to the correct format parser and return a normalised `Document`.
pub fn parse_document(format: &Format, value: &Value) -> Result<Document> {
    match format {
        Format::CycloneDx => Ok(Document::Sbom(sbom::cyclonedx::parse(value))),
        Format::Spdx => Ok(Document::Sbom(sbom::spdx::parse(value))),
        Format::OpenVex => Ok(Document::Vex(vex::openvex::parse(value))),
        Format::Csaf => Ok(Document::Vex(vex::csaf::parse(value))),
    }
}
