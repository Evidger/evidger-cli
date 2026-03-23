use crate::{
    errors::{EvidgerError, Result},
    format::{self, Document},
    json,
    models::{Component, SbomDocument, VexDocument, VexStatement},
    registry,
};
use std::collections::HashMap;
use std::path::PathBuf;

/// A version or status conflict that was resolved by last-wins.
#[derive(Debug)]
pub struct Conflict {
    /// The component name or vulnerability ID that conflicted.
    pub id: String,
    /// File whose value was kept.
    pub kept_from: String,
    /// File whose value was discarded.
    pub overridden_from: String,
}

/// Result of a merge operation.
pub struct MergeResult {
    /// Ordered list of source file paths that were merged.
    pub sources: Vec<String>,
    /// The merged document (SBOM or VEX).
    pub document: Document,
    /// Version / status conflicts resolved by last-wins.
    pub conflicts: Vec<Conflict>,
}

/// Load, parse, and merge all files in `paths`.
///
/// All files must be of the same document kind (all SBOMs or all VEXes).
/// Formats may differ (e.g. CycloneDX + SPDX, or OpenVEX + CSAF).
/// Returns `EvidgerError::MergeConflict` if kinds are mixed.
pub fn merge_files(paths: &[PathBuf]) -> Result<MergeResult> {
    let mut docs: Vec<(String, Document)> = Vec::with_capacity(paths.len());

    for path in paths {
        let value = json::load_json(path)?;
        let format = registry::detect_format(&value)?;
        let doc = format::parse_document(&format, &value)?;
        docs.push((path.display().to_string(), doc));
    }

    // Ensure all documents are the same kind.
    let first_kind = docs[0].1.kind();
    for (path, doc) in &docs[1..] {
        if doc.kind() != first_kind {
            return Err(EvidgerError::MergeConflict(format!(
                "cannot merge a {} with a {} ({})",
                first_kind,
                doc.kind(),
                path
            )));
        }
    }

    let sources: Vec<String> = docs.iter().map(|(p, _)| p.clone()).collect();

    match first_kind {
        "SBOM" => {
            let sboms: Vec<SbomDocument> = docs
                .into_iter()
                .map(|(_, d)| match d {
                    Document::Sbom(s) => s,
                    _ => unreachable!(),
                })
                .collect();
            let (merged, conflicts) = merge_sboms(sboms, &sources);
            Ok(MergeResult {
                sources,
                document: Document::Sbom(merged),
                conflicts,
            })
        }
        "VEX" => {
            let vexes: Vec<VexDocument> = docs
                .into_iter()
                .map(|(_, d)| match d {
                    Document::Vex(v) => v,
                    _ => unreachable!(),
                })
                .collect();
            let (merged, conflicts) = merge_vexes(vexes, &sources);
            Ok(MergeResult {
                sources,
                document: Document::Vex(merged),
                conflicts,
            })
        }
        _ => unreachable!(),
    }
}

/// Merge SBOM documents: deduplicate by component name; last file wins on version conflict.
fn merge_sboms(docs: Vec<SbomDocument>, sources: &[String]) -> (SbomDocument, Vec<Conflict>) {
    // name → (component, source_index)
    let mut seen: HashMap<String, (Component, usize)> = HashMap::new();
    let mut conflicts: Vec<Conflict> = Vec::new();

    for (idx, doc) in docs.iter().enumerate() {
        for comp in &doc.components {
            match seen.get(&comp.name) {
                Some((existing, prev_idx)) if existing.version != comp.version => {
                    conflicts.push(Conflict {
                        id: comp.name.clone(),
                        kept_from: sources[idx].clone(),
                        overridden_from: sources[*prev_idx].clone(),
                    });
                    seen.insert(comp.name.clone(), (comp.clone(), idx));
                }
                None => {
                    seen.insert(comp.name.clone(), (comp.clone(), idx));
                }
                _ => {} // identical — keep existing, no conflict
            }
        }
    }

    let mut components: Vec<Component> = seen.into_values().map(|(c, _)| c).collect();
    components.sort_by(|a, b| a.name.cmp(&b.name));

    let merged = SbomDocument {
        format: "CycloneDX".into(),
        spec_version: Some("1.6".into()),
        serial_number: None,
        version: Some(1),
        components,
    };
    (merged, conflicts)
}

/// Merge VEX documents: deduplicate by CVE ID; last file wins on status conflict.
fn merge_vexes(docs: Vec<VexDocument>, sources: &[String]) -> (VexDocument, Vec<Conflict>) {
    // id → (statement, source_index)
    let mut seen: HashMap<String, (VexStatement, usize)> = HashMap::new();
    let mut conflicts: Vec<Conflict> = Vec::new();

    for (idx, doc) in docs.iter().enumerate() {
        for stmt in &doc.statements {
            let id = stmt.vulnerability.id.clone();
            match seen.get(&id) {
                Some((existing, prev_idx)) if existing.status != stmt.status => {
                    conflicts.push(Conflict {
                        id: id.clone(),
                        kept_from: sources[idx].clone(),
                        overridden_from: sources[*prev_idx].clone(),
                    });
                    seen.insert(id, (stmt.clone(), idx));
                }
                None => {
                    seen.insert(id, (stmt.clone(), idx));
                }
                _ => {} // identical status — keep existing
            }
        }
    }

    let mut statements: Vec<VexStatement> =
        seen.into_values().map(|(s, _)| s).collect();
    statements.sort_by(|a, b| a.vulnerability.id.cmp(&b.vulnerability.id));

    let merged = VexDocument {
        id: None,
        author: Some("evidger-cli".into()),
        timestamp: None,
        version: Some(1),
        statements,
    };
    (merged, conflicts)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{VexStatus, Vulnerability};

    fn make_comp(name: &str, version: &str) -> Component {
        Component {
            name: name.into(),
            version: Some(version.into()),
            purl: None,
            bom_ref: None,
        }
    }

    fn make_stmt(id: &str, status: VexStatus) -> VexStatement {
        VexStatement {
            vulnerability: Vulnerability {
                id: id.into(),
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

    fn sbom(components: Vec<Component>) -> SbomDocument {
        SbomDocument {
            format: "CycloneDX".into(),
            spec_version: None,
            serial_number: None,
            version: None,
            components,
        }
    }

    fn vex(statements: Vec<VexStatement>) -> VexDocument {
        VexDocument {
            id: None,
            author: None,
            timestamp: None,
            version: None,
            statements,
        }
    }

    // ── SBOM ──────────────────────────────────────────────────────────────────

    #[test]
    fn sbom_disjoint_components_are_combined() {
        let a = sbom(vec![make_comp("log4j", "2.17.2")]);
        let b = sbom(vec![make_comp("commons", "3.12.0")]);
        let sources = ["a".into(), "b".into()];
        let (merged, conflicts) = merge_sboms(vec![a, b], &sources);
        assert_eq!(merged.components.len(), 2);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn sbom_identical_component_is_deduped() {
        let comp = make_comp("log4j", "2.17.2");
        let a = sbom(vec![comp.clone()]);
        let b = sbom(vec![comp]);
        let sources = ["a".into(), "b".into()];
        let (merged, conflicts) = merge_sboms(vec![a, b], &sources);
        assert_eq!(merged.components.len(), 1);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn sbom_version_conflict_resolved_last_wins() {
        let a = sbom(vec![make_comp("log4j", "2.17.1")]);
        let b = sbom(vec![make_comp("log4j", "2.17.2")]);
        let sources = ["a".into(), "b".into()];
        let (merged, conflicts) = merge_sboms(vec![a, b], &sources);
        assert_eq!(merged.components.len(), 1);
        assert_eq!(merged.components[0].version.as_deref(), Some("2.17.2"));
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].id, "log4j");
    }

    // ── VEX ───────────────────────────────────────────────────────────────────

    #[test]
    fn vex_disjoint_statements_are_combined() {
        let a = vex(vec![make_stmt("CVE-2021-44228", VexStatus::Fixed)]);
        let b = vex(vec![make_stmt("CVE-2021-45046", VexStatus::NotAffected)]);
        let sources = ["a".into(), "b".into()];
        let (merged, conflicts) = merge_vexes(vec![a, b], &sources);
        assert_eq!(merged.statements.len(), 2);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn vex_identical_statement_is_deduped() {
        let stmt = make_stmt("CVE-2021-44228", VexStatus::Fixed);
        let a = vex(vec![stmt.clone()]);
        let b = vex(vec![stmt]);
        let sources = ["a".into(), "b".into()];
        let (merged, conflicts) = merge_vexes(vec![a, b], &sources);
        assert_eq!(merged.statements.len(), 1);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn vex_status_conflict_resolved_last_wins() {
        let a = vex(vec![make_stmt("CVE-2021-44228", VexStatus::Affected)]);
        let b = vex(vec![make_stmt("CVE-2021-44228", VexStatus::Fixed)]);
        let sources = ["a".into(), "b".into()];
        let (merged, conflicts) = merge_vexes(vec![a, b], &sources);
        assert_eq!(merged.statements.len(), 1);
        assert_eq!(merged.statements[0].status, VexStatus::Fixed);
        assert_eq!(conflicts.len(), 1);
    }

    #[test]
    fn vex_output_sorted_by_id() {
        let a = vex(vec![
            make_stmt("CVE-2022-99999", VexStatus::Fixed),
            make_stmt("CVE-2021-00001", VexStatus::NotAffected),
        ]);
        let sources = ["a".into()];
        let (merged, _) = merge_vexes(vec![a], &sources);
        assert_eq!(merged.statements[0].vulnerability.id, "CVE-2021-00001");
        assert_eq!(merged.statements[1].vulnerability.id, "CVE-2022-99999");
    }
}
