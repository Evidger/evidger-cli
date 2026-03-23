use serde::{Deserialize, Serialize};

/// A single software component inside an SBOM.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Component {
    /// Human-readable name (e.g. `"log4j-core"`).
    pub name: String,

    /// Version string, if present (e.g. `"2.17.2"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Package URL — the primary deduplication key across formats.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,

    /// Intra-document reference identifier (CycloneDX `bom-ref`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
}

impl Component {
    /// The best available unique identifier for this component.
    /// Prefers `purl`, falls back to `bom_ref`, then `name@version`.
    pub fn identity(&self) -> String {
        if let Some(p) = &self.purl {
            return p.clone();
        }
        if let Some(r) = &self.bom_ref {
            return r.clone();
        }
        match &self.version {
            Some(v) => format!("{}@{}", self.name, v),
            None => self.name.clone(),
        }
    }
}

/// Normalised representation of an SBOM document (CycloneDX or SPDX).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SbomDocument {
    /// Source format name (e.g. `"CycloneDX"`, `"SPDX"`).
    pub format: String,

    /// Specification version (e.g. `"1.6"` for CycloneDX).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,

    /// Document serial number / unique identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,

    /// Document version counter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,

    /// All components declared in this SBOM.
    pub components: Vec<Component>,
}
