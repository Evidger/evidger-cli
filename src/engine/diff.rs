use crate::{
    errors::{EvidgerError, Result},
    format::{self, Document},
    json,
    models::{Component, VexStatement, VexStatus},
    registry,
};
use std::collections::HashMap;
use std::path::Path;

/// A change affecting a component between two SBOMs.
#[derive(Debug, Clone)]
pub enum ComponentChange {
    /// Present in B but not in A.
    Added(Component),
    /// Present in A but not in B.
    Removed(Component),
    /// Same name in both but the version differs.
    VersionChanged {
        name: String,
        from: Option<String>,
        to: Option<String>,
    },
}

/// A change affecting a vulnerability between two VEX documents.
#[derive(Debug, Clone)]
pub enum VulnerabilityChange {
    /// Present in B but not in A.
    Added(String),
    /// Present in A but not in B.
    Removed(String),
    /// Same ID in both but the `status` field changed.
    StatusChanged {
        id: String,
        from: VexStatus,
        to: VexStatus,
    },
    /// Same ID in both but the `justification` field changed.
    JustificationChanged {
        id: String,
        from: Option<String>,
        to: Option<String>,
    },
    /// Same ID in both but the `impact_statement` field changed.
    ImpactStatementChanged {
        id: String,
        from: Option<String>,
        to: Option<String>,
    },
    /// Same ID in both but the `action_statement` field changed.
    ActionStatementChanged {
        id: String,
        from: Option<String>,
        to: Option<String>,
    },
}

impl VulnerabilityChange {
    pub fn id(&self) -> &str {
        match self {
            VulnerabilityChange::Added(id) => id,
            VulnerabilityChange::Removed(id) => id,
            VulnerabilityChange::StatusChanged { id, .. } => id,
            VulnerabilityChange::JustificationChanged { id, .. } => id,
            VulnerabilityChange::ImpactStatementChanged { id, .. } => id,
            VulnerabilityChange::ActionStatementChanged { id, .. } => id,
        }
    }
}

/// Full diff result for two files.
#[derive(Debug)]
pub struct DiffResult {
    pub file_a: String,
    pub file_b: String,
    pub component_changes: Vec<ComponentChange>,
    pub vulnerability_changes: Vec<VulnerabilityChange>,
}

impl DiffResult {
    pub fn is_identical(&self) -> bool {
        self.component_changes.is_empty() && self.vulnerability_changes.is_empty()
    }
}

/// Load, parse, and diff two files.
///
/// Both files must be of the same kind (SBOM vs SBOM, or VEX vs VEX).
/// Returns `EvidgerError::UnsupportedFormat` if the kinds differ.
pub fn diff_files(path_a: &Path, path_b: &Path) -> Result<DiffResult> {
    let value_a = json::load_json(path_a)?;
    let value_b = json::load_json(path_b)?;

    let format_a = registry::detect_format(&value_a)?;
    let format_b = registry::detect_format(&value_b)?;

    let doc_a = format::parse_document(&format_a, &value_a)?;
    let doc_b = format::parse_document(&format_b, &value_b)?;

    let (component_changes, vulnerability_changes) = match (doc_a, doc_b) {
        (Document::Sbom(a), Document::Sbom(b)) => {
            (diff_components(&a.components, &b.components), vec![])
        }
        (Document::Vex(a), Document::Vex(b)) => {
            (vec![], diff_vulnerabilities(&a.statements, &b.statements))
        }
        (a, b) => {
            return Err(EvidgerError::UnsupportedFormat(format!(
                "cannot diff a {} against a {}",
                a.kind(),
                b.kind()
            )));
        }
    };

    Ok(DiffResult {
        file_a: path_a.display().to_string(),
        file_b: path_b.display().to_string(),
        component_changes,
        vulnerability_changes,
    })
}

fn diff_components(a: &[Component], b: &[Component]) -> Vec<ComponentChange> {
    // Match components by name; version differences become VersionChanged.
    let map_a: HashMap<&str, &Component> = a.iter().map(|c| (c.name.as_str(), c)).collect();
    let map_b: HashMap<&str, &Component> = b.iter().map(|c| (c.name.as_str(), c)).collect();

    let mut changes = Vec::new();

    for (name, comp_a) in &map_a {
        match map_b.get(name) {
            None => changes.push(ComponentChange::Removed((*comp_a).clone())),
            Some(comp_b) if comp_a.version != comp_b.version => {
                changes.push(ComponentChange::VersionChanged {
                    name: name.to_string(),
                    from: comp_a.version.clone(),
                    to: comp_b.version.clone(),
                });
            }
            _ => {} // same name, same version → no change
        }
    }

    for (name, comp_b) in &map_b {
        if !map_a.contains_key(name) {
            changes.push(ComponentChange::Added((*comp_b).clone()));
        }
    }

    changes
}

fn diff_vulnerabilities(a: &[VexStatement], b: &[VexStatement]) -> Vec<VulnerabilityChange> {
    let map_a: HashMap<&str, &VexStatement> =
        a.iter().map(|s| (s.vulnerability.id.as_str(), s)).collect();
    let map_b: HashMap<&str, &VexStatement> =
        b.iter().map(|s| (s.vulnerability.id.as_str(), s)).collect();

    let mut changes = Vec::new();

    for (id, stmt_a) in &map_a {
        match map_b.get(id) {
            None => changes.push(VulnerabilityChange::Removed(id.to_string())),
            Some(stmt_b) => {
                if stmt_a.status != stmt_b.status {
                    changes.push(VulnerabilityChange::StatusChanged {
                        id: id.to_string(),
                        from: stmt_a.status.clone(),
                        to: stmt_b.status.clone(),
                    });
                }
                if stmt_a.justification != stmt_b.justification {
                    changes.push(VulnerabilityChange::JustificationChanged {
                        id: id.to_string(),
                        from: stmt_a.justification.clone(),
                        to: stmt_b.justification.clone(),
                    });
                }
                if stmt_a.impact_statement != stmt_b.impact_statement {
                    changes.push(VulnerabilityChange::ImpactStatementChanged {
                        id: id.to_string(),
                        from: stmt_a.impact_statement.clone(),
                        to: stmt_b.impact_statement.clone(),
                    });
                }
                if stmt_a.action_statement != stmt_b.action_statement {
                    changes.push(VulnerabilityChange::ActionStatementChanged {
                        id: id.to_string(),
                        from: stmt_a.action_statement.clone(),
                        to: stmt_b.action_statement.clone(),
                    });
                }
            }
        }
    }

    for (id, _) in &map_b {
        if !map_a.contains_key(id) {
            changes.push(VulnerabilityChange::Added(id.to_string()));
        }
    }

    changes
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Component, SbomDocument, VexStatement, VexStatus, Vulnerability};

    fn make_component(name: &str, version: &str, purl: &str) -> Component {
        Component {
            name: name.to_string(),
            version: Some(version.to_string()),
            purl: Some(purl.to_string()),
            bom_ref: None,
        }
    }

    fn make_statement(cve: &str, status: VexStatus) -> VexStatement {
        VexStatement {
            vulnerability: Vulnerability {
                id: cve.to_string(),
                description: None,
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

    // ── SBOM diff ─────────────────────────────────────────────────────────────

    #[test]
    fn identical_sboms_produce_no_changes() {
        let comp = make_component("log4j", "2.17.2", "pkg:maven/log4j@2.17.2");
        let a = SbomDocument {
            format: "CycloneDX".into(),
            spec_version: None,
            serial_number: None,
            version: None,
            components: vec![comp.clone()],
        };
        let b = a.clone();
        assert!(diff_components(&a.components, &b.components).is_empty());
    }

    #[test]
    fn added_component_detected() {
        let base = make_component("log4j", "2.17.2", "pkg:maven/log4j@2.17.2");
        let a = vec![base.clone()];
        let b = vec![base, make_component("commons", "3.12.0", "pkg:maven/commons@3.12.0")];

        let changes = diff_components(&a, &b);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], ComponentChange::Added(c) if c.name == "commons"));
    }

    #[test]
    fn removed_component_detected() {
        let base = make_component("log4j", "2.17.2", "pkg:maven/log4j@2.17.2");
        let a = vec![base.clone(), make_component("commons", "3.12.0", "pkg:maven/commons@3.12.0")];
        let b = vec![base];

        let changes = diff_components(&a, &b);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], ComponentChange::Removed(c) if c.name == "commons"));
    }

    #[test]
    fn version_change_detected() {
        let a = vec![make_component("log4j", "2.17.1", "pkg:maven/log4j@2.17.1")];
        let b = vec![make_component("log4j", "2.17.2", "pkg:maven/log4j@2.17.2")];

        let changes = diff_components(&a, &b);
        assert_eq!(changes.len(), 1);
        assert!(
            matches!(&changes[0], ComponentChange::VersionChanged { name, from, to }
                if name == "log4j"
                && from.as_deref() == Some("2.17.1")
                && to.as_deref() == Some("2.17.2"))
        );
    }

    // ── VEX diff ──────────────────────────────────────────────────────────────

    #[test]
    fn added_vulnerability_detected() {
        let a = vec![make_statement("CVE-2021-44228", VexStatus::Fixed)];
        let b = vec![
            make_statement("CVE-2021-44228", VexStatus::Fixed),
            make_statement("CVE-2021-45046", VexStatus::NotAffected),
        ];

        let changes = diff_vulnerabilities(&a, &b);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], VulnerabilityChange::Added(id) if id == "CVE-2021-45046"));
    }

    #[test]
    fn removed_vulnerability_detected() {
        let a = vec![
            make_statement("CVE-2021-44228", VexStatus::Fixed),
            make_statement("CVE-2021-45046", VexStatus::NotAffected),
        ];
        let b = vec![make_statement("CVE-2021-44228", VexStatus::Fixed)];

        let changes = diff_vulnerabilities(&a, &b);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], VulnerabilityChange::Removed(id) if id == "CVE-2021-45046"));
    }

    #[test]
    fn remediation_detected_as_status_change() {
        let a = vec![make_statement("CVE-2021-44228", VexStatus::Affected)];
        let b = vec![make_statement("CVE-2021-44228", VexStatus::Fixed)];

        let changes = diff_vulnerabilities(&a, &b);
        assert_eq!(changes.len(), 1);
        assert!(
            matches!(
                &changes[0],
                VulnerabilityChange::StatusChanged { id, from, to }
                    if id == "CVE-2021-44228"
                    && *from == VexStatus::Affected
                    && *to == VexStatus::Fixed
            ),
            "expected StatusChanged(affected -> fixed), got: {changes:#?}"
        );
    }

    #[test]
    fn identical_status_produces_no_change() {
        let a = vec![make_statement("CVE-2021-44228", VexStatus::Fixed)];
        let b = vec![make_statement("CVE-2021-44228", VexStatus::Fixed)];
        assert!(diff_vulnerabilities(&a, &b).is_empty());
    }

    #[test]
    fn justification_change_detected() {
        let mut stmt_a = make_statement("CVE-2021-44228", VexStatus::NotAffected);
        stmt_a.justification = Some("component_not_present".to_string());
        let mut stmt_b = make_statement("CVE-2021-44228", VexStatus::NotAffected);
        stmt_b.justification = Some("vulnerable_code_not_present".to_string());

        let changes = diff_vulnerabilities(&[stmt_a], &[stmt_b]);
        assert_eq!(changes.len(), 1);
        assert!(
            matches!(&changes[0], VulnerabilityChange::JustificationChanged { id, from, to }
                if id == "CVE-2021-44228"
                && from.as_deref() == Some("component_not_present")
                && to.as_deref() == Some("vulnerable_code_not_present"))
        );
    }

    #[test]
    fn action_statement_change_detected() {
        let mut stmt_a = make_statement("CVE-2021-44228", VexStatus::Affected);
        stmt_a.action_statement = Some("Update to 2.15.0".to_string());
        let mut stmt_b = make_statement("CVE-2021-44228", VexStatus::Affected);
        stmt_b.action_statement = Some("Update to 2.17.0".to_string());

        let changes = diff_vulnerabilities(&[stmt_a], &[stmt_b]);
        assert_eq!(changes.len(), 1);
        assert!(
            matches!(&changes[0], VulnerabilityChange::ActionStatementChanged { id, from, to }
                if id == "CVE-2021-44228"
                && from.as_deref() == Some("Update to 2.15.0")
                && to.as_deref() == Some("Update to 2.17.0"))
        );
    }

    #[test]
    fn multiple_field_changes_all_reported() {
        let mut stmt_a = make_statement("CVE-2021-44228", VexStatus::Affected);
        stmt_a.action_statement = Some("Update to 2.15.0".to_string());

        // status changes AND action_statement is cleared
        let stmt_b = make_statement("CVE-2021-44228", VexStatus::Fixed);

        let changes = diff_vulnerabilities(&[stmt_a], &[stmt_b]);
        // StatusChanged + ActionStatementChanged
        assert_eq!(changes.len(), 2, "got: {changes:#?}");
        assert!(changes.iter().any(|c| matches!(c, VulnerabilityChange::StatusChanged { .. })));
        assert!(changes.iter().any(|c| matches!(c, VulnerabilityChange::ActionStatementChanged { .. })));
    }
}
