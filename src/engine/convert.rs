use crate::{errors::Result, format, json, registry, registry::Format};
use serde_json::Value;
use std::path::Path;

/// Load, parse, and re-serialize `path` as `target` format.
pub fn convert_file(path: &Path, target: &Format) -> Result<Value> {
    let value = json::load_json(path)?;
    let format = registry::detect_format(&value)?;
    let doc = format::parse_document(&format, &value)?;
    format::serialize_as(&doc, target)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Component, SbomDocument, VexDocument, VexStatement, VexStatus, Vulnerability};
    use crate::format::{Document, serialize_as};

    fn sbom_with(components: Vec<Component>) -> Document {
        Document::Sbom(SbomDocument {
            format: "CycloneDX".into(),
            spec_version: None,
            serial_number: None,
            version: None,
            components,
        })
    }

    fn vex_with(statements: Vec<VexStatement>) -> Document {
        Document::Vex(VexDocument {
            id: None,
            author: None,
            timestamp: None,
            version: None,
            statements,
        })
    }

    fn comp(name: &str, version: &str, purl: &str) -> Component {
        Component {
            name: name.into(),
            version: Some(version.into()),
            purl: Some(purl.into()),
            bom_ref: None,
        }
    }

    fn stmt(id: &str, status: VexStatus) -> VexStatement {
        VexStatement {
            vulnerability: Vulnerability {
                id: id.into(),
                description: Some(format!("Description of {id}")),
                severity: None,
                aliases: vec![],
            },
            products: vec![],
            status,
            justification: None,
            impact_statement: None,
            action_statement: None,
        }
    }

    // ── SBOM → CycloneDX ──────────────────────────────────────────────────────

    #[test]
    fn sbom_to_cyclonedx_preserves_components() {
        let doc = sbom_with(vec![comp("log4j", "2.17.2", "pkg:maven/log4j@2.17.2")]);
        let out = serialize_as(&doc, &Format::CycloneDx).unwrap();
        assert_eq!(out["bomFormat"].as_str(), Some("CycloneDX"));
        assert_eq!(out["components"][0]["name"].as_str(), Some("log4j"));
    }

    // ── SBOM → SPDX ───────────────────────────────────────────────────────────

    #[test]
    fn sbom_to_spdx_produces_graph() {
        let doc = sbom_with(vec![comp("log4j", "2.17.2", "pkg:maven/log4j@2.17.2")]);
        let out = serialize_as(&doc, &Format::Spdx).unwrap();
        assert!(out["@context"].as_str().unwrap().contains("spdx.org"));
        let graph = out["@graph"].as_array().unwrap();
        // creation info + 1 package
        assert_eq!(graph.len(), 2);
        let pkg = graph.iter().find(|e| e["type"].as_str() == Some("software_Package")).unwrap();
        assert_eq!(pkg["name"].as_str(), Some("log4j"));
        assert_eq!(pkg["software_packageVersion"].as_str(), Some("2.17.2"));
    }

    #[test]
    fn sbom_to_spdx_includes_purl_as_external_identifier() {
        let doc = sbom_with(vec![comp("log4j", "2.17.2", "pkg:maven/log4j@2.17.2")]);
        let out = serialize_as(&doc, &Format::Spdx).unwrap();
        let graph = out["@graph"].as_array().unwrap();
        let pkg = graph.iter().find(|e| e["type"].as_str() == Some("software_Package")).unwrap();
        let ext_id = &pkg["externalIdentifier"][0];
        assert_eq!(ext_id["externalIdentifierType"].as_str(), Some("packageUrl"));
        assert_eq!(ext_id["identifier"].as_str(), Some("pkg:maven/log4j@2.17.2"));
    }

    // ── VEX → OpenVEX ─────────────────────────────────────────────────────────

    #[test]
    fn vex_to_openvex_preserves_statements() {
        let doc = vex_with(vec![stmt("CVE-2021-44228", VexStatus::Fixed)]);
        let out = serialize_as(&doc, &Format::OpenVex).unwrap();
        assert!(out["@context"].as_str().unwrap().contains("openvex"));
        assert_eq!(out["statements"][0]["vulnerability"]["name"].as_str(), Some("CVE-2021-44228"));
        assert_eq!(out["statements"][0]["status"].as_str(), Some("fixed"));
    }

    // ── VEX → CSAF ────────────────────────────────────────────────────────────

    #[test]
    fn vex_to_csaf_produces_valid_structure() {
        let doc = vex_with(vec![stmt("CVE-2021-44228", VexStatus::Fixed)]);
        let out = serialize_as(&doc, &Format::Csaf).unwrap();
        assert_eq!(out["document"]["csaf_version"].as_str(), Some("2.0"));
        assert!(out["vulnerabilities"].is_array());
    }

    #[test]
    fn vex_to_csaf_fixed_uses_vendor_fix_remediation() {
        let doc = vex_with(vec![stmt("CVE-2021-44228", VexStatus::Fixed)]);
        let out = serialize_as(&doc, &Format::Csaf).unwrap();
        let rem = &out["vulnerabilities"][0]["remediations"][0];
        assert_eq!(rem["category"].as_str(), Some("vendor_fix"));
    }

    #[test]
    fn vex_to_csaf_not_affected_uses_flags() {
        let doc = vex_with(vec![stmt("CVE-2021-45046", VexStatus::NotAffected)]);
        let out = serialize_as(&doc, &Format::Csaf).unwrap();
        let flag = &out["vulnerabilities"][0]["flags"][0];
        assert!(flag["label"].as_str().is_some());
    }

    #[test]
    fn vex_to_csaf_non_cve_id_uses_ids_array() {
        let doc = vex_with(vec![stmt("GHSA-xxxx-yyyy-zzzz", VexStatus::Fixed)]);
        let out = serialize_as(&doc, &Format::Csaf).unwrap();
        let vuln = &out["vulnerabilities"][0];
        assert!(vuln.get("cve").is_none(), "non-CVE ID must not use `cve` field");
        assert_eq!(
            vuln["ids"][0]["text"].as_str(),
            Some("GHSA-xxxx-yyyy-zzzz")
        );
    }

    // ── Incompatible conversions ───────────────────────────────────────────────

    #[test]
    fn sbom_to_openvex_fails() {
        let doc = sbom_with(vec![]);
        assert!(serialize_as(&doc, &Format::OpenVex).is_err());
    }

    #[test]
    fn sbom_to_csaf_fails() {
        let doc = sbom_with(vec![]);
        assert!(serialize_as(&doc, &Format::Csaf).is_err());
    }

    #[test]
    fn vex_to_cyclonedx_fails() {
        let doc = vex_with(vec![]);
        assert!(serialize_as(&doc, &Format::CycloneDx).is_err());
    }

    #[test]
    fn vex_to_spdx_fails() {
        let doc = vex_with(vec![]);
        assert!(serialize_as(&doc, &Format::Spdx).is_err());
    }
}
