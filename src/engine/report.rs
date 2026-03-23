use crate::{errors::Result, format, json, registry};
use crate::format::Document;
use crate::models::{Component, SbomDocument, VexDocument, VexStatement};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

static SBOM_TEMPLATE: &str = include_str!("report_sbom.html");
static VEX_TEMPLATE: &str = include_str!("report_vex.html");
static CORRELATED_TEMPLATE: &str = include_str!("report_correlated.html");

// ─── Public entry point ──────────────────────────────────────────────────────

/// Load, parse, and generate an HTML report.
///
/// - `vex_path`: when provided, correlate the SBOM with the VEX document and
///   produce a correlated report instead of a plain SBOM report.
/// - `output`: target path; defaults to input file with `.html` extension.
/// - `minify`: collapse whitespace in the generated HTML.
pub fn generate_report(
    input: &Path,
    vex_path: Option<&Path>,
    output: Option<&Path>,
    minify: bool,
) -> Result<PathBuf> {
    let (report_data, template) = if let Some(vex) = vex_path {
        build_correlated_report(input, vex)?
    } else {
        let value = json::load_json(input)?;
        let fmt = registry::detect_format(&value)?;
        let doc = format::parse_document(&fmt, &value)?;
        build_report(&doc, input)
    };

    let mut html = template.replace("__DATA_PLACEHOLDER__", &report_data);
    if minify {
        html = minify_html(&html);
    }

    let out_path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            let mut p = input.to_path_buf();
            p.set_extension("html");
            p
        }
    };

    std::fs::write(&out_path, html)?;
    Ok(out_path)
}

// ─── Single-document report ──────────────────────────────────────────────────

/// Return `(injected JSON string, &template)` for a single document.
fn build_report(doc: &Document, source: &Path) -> (String, &'static str) {
    let source_name = source
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    match doc {
        Document::Sbom(sbom) => {
            let components: Vec<Value> = sbom
                .components
                .iter()
                .map(|c| json!({"name": c.name, "version": c.version, "purl": c.purl}))
                .collect();

            let data = json!({
                "source": source_name,
                "format": sbom.format,
                "spec_version": sbom.spec_version,
                "serial_number": sbom.serial_number,
                "doc_version": sbom.version,
                "components": components,
            });

            (serde_json::to_string(&data).unwrap_or_else(|_| "{}".to_string()), SBOM_TEMPLATE)
        }

        Document::Vex(vex) => {
            let mut sev_dist: std::collections::BTreeMap<String, u32> =
                std::collections::BTreeMap::new();

            let vulnerabilities: Vec<Value> = vex
                .statements
                .iter()
                .map(|s| {
                    let sev = s
                        .vulnerability
                        .severity
                        .as_ref()
                        .map(|sv| sv.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    *sev_dist.entry(sev.clone()).or_insert(0) += 1;

                    let products: Vec<Value> = s
                        .products
                        .iter()
                        .map(|p| json!({"name": p.name, "version": p.version}))
                        .collect();

                    json!({
                        "id": s.vulnerability.id,
                        "description": s.vulnerability.description,
                        "severity": sev,
                        "status": s.status.to_string(),
                        "justification": s.justification,
                        "impact_statement": s.impact_statement,
                        "action_statement": s.action_statement,
                        "products": products,
                    })
                })
                .collect();

            let sev_json: Value = sev_dist
                .iter()
                .map(|(k, v)| (k.clone(), json!(v)))
                .collect::<serde_json::Map<_, _>>()
                .into();

            let data = json!({
                "source": source_name,
                "doc_id": vex.id,
                "author": vex.author,
                "timestamp": vex.timestamp,
                "severity_distribution": sev_json,
                "vulnerabilities": vulnerabilities,
            });

            (serde_json::to_string(&data).unwrap_or_else(|_| "{}".to_string()), VEX_TEMPLATE)
        }
    }
}

// ─── Correlated report ───────────────────────────────────────────────────────

fn build_correlated_report(
    sbom_path: &Path,
    vex_path: &Path,
) -> Result<(String, &'static str)> {
    let sbom_val = json::load_json(sbom_path)?;
    let sbom_fmt = registry::detect_format(&sbom_val)?;
    let sbom_doc = format::parse_document(&sbom_fmt, &sbom_val)?;

    let vex_val = json::load_json(vex_path)?;
    let vex_fmt = registry::detect_format(&vex_val)?;
    let vex_doc = format::parse_document(&vex_fmt, &vex_val)?;

    let sbom = match &sbom_doc {
        Document::Sbom(s) => s,
        Document::Vex(_) => {
            return Err(crate::errors::EvidgerError::UnsupportedFormat(
                "first argument must be an SBOM; got a VEX document".to_string(),
            ))
        }
    };
    let vex = match &vex_doc {
        Document::Vex(v) => v,
        Document::Sbom(_) => {
            return Err(crate::errors::EvidgerError::UnsupportedFormat(
                "--vex argument must be a VEX document; got an SBOM".to_string(),
            ))
        }
    };

    let sbom_source = sbom_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("sbom");
    let vex_source = vex_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vex");

    let data = build_correlated_data(sbom, vex, sbom_source, vex_source);
    Ok((
        serde_json::to_string(&data).unwrap_or_else(|_| "{}".to_string()),
        CORRELATED_TEMPLATE,
    ))
}

/// Core correlation: match each VEX statement to SBOM components and produce
/// the JSON payload consumed by the correlated HTML template.
pub(crate) fn build_correlated_data(
    sbom: &SbomDocument,
    vex: &VexDocument,
    sbom_source: &str,
    vex_source: &str,
) -> Value {
    let correlations = correlate(sbom, vex);

    // ── Statistics ───────────────────────────────────────────────────────────
    let total = correlations.len();
    let affected = correlations.iter().filter(|c| c.status == "affected").count();
    let fixed = correlations.iter().filter(|c| c.status == "fixed").count();
    let not_affected = correlations.iter().filter(|c| c.status == "not_affected").count();
    let under_inv = correlations
        .iter()
        .filter(|c| c.status == "under_investigation")
        .count();
    let actionable = affected + under_inv;
    let noise_pct = if total > 0 {
        (not_affected * 100 / total) as u64
    } else {
        0
    };

    // ── Component risk table ─────────────────────────────────────────────────
    // Every SBOM component gets a row, even those with no correlations.
    let mut comp_risk: Vec<Value> = sbom
        .components
        .iter()
        .map(|comp| {
            let rows: Vec<_> = correlations
                .iter()
                .filter(|c| c.component_name == comp.name)
                .collect();
            let c_affected = rows.iter().filter(|c| c.status == "affected").count() as u64;
            let c_fixed = rows.iter().filter(|c| c.status == "fixed").count() as u64;
            let c_not_aff = rows.iter().filter(|c| c.status == "not_affected").count() as u64;
            let c_inv = rows
                .iter()
                .filter(|c| c.status == "under_investigation")
                .count() as u64;
            // Risk score: affected weighs most, then under_investigation
            let risk_score = c_affected * 4 + c_inv * 2 + c_fixed;
            json!({
                "name": comp.name,
                "version": comp.version,
                "affected": c_affected,
                "fixed": c_fixed,
                "not_affected": c_not_aff,
                "under_investigation": c_inv,
                "risk_score": risk_score,
            })
        })
        .collect();

    // Sort by risk score descending, then by name
    comp_risk.sort_by(|a, b| {
        let sa = a["risk_score"].as_u64().unwrap_or(0);
        let sb = b["risk_score"].as_u64().unwrap_or(0);
        sb.cmp(&sa)
            .then_with(|| a["name"].as_str().cmp(&b["name"].as_str()))
    });

    let corr_values: Vec<Value> = correlations
        .into_iter()
        .map(|c| {
            json!({
                "vuln_id": c.vuln_id,
                "description": c.description,
                "severity": c.severity,
                "status": c.status,
                "component_name": c.component_name,
                "component_version": c.component_version,
                "justification": c.justification,
                "action_statement": c.action_statement,
            })
        })
        .collect();

    json!({
        "sbom_source": sbom_source,
        "vex_source": vex_source,
        "stats": {
            "total": total,
            "affected": affected,
            "fixed": fixed,
            "not_affected": not_affected,
            "under_investigation": under_inv,
            "actionable": actionable,
            "noise_reduction_pct": noise_pct,
        },
        "correlations": corr_values,
        "component_risk": comp_risk,
    })
}

// ─── Matching helpers ────────────────────────────────────────────────────────

struct CorrelatedEntry {
    vuln_id: String,
    description: Option<String>,
    severity: String,
    status: String,
    component_name: String,
    component_version: Option<String>,
    justification: Option<String>,
    action_statement: Option<String>,
}

/// Strip the `@version` suffix from a purl-like string.
/// `"pkg:maven/org/name@1.0"` → `"pkg:maven/org/name"`
fn purl_base(s: &str) -> &str {
    match s.rfind('@') {
        Some(i) => &s[..i],
        None => s,
    }
}

/// Extract the component name from a purl-like string.
/// `"pkg:maven/org.apache/log4j-core@2.0"` → `"log4j-core"`
fn purl_name(s: &str) -> &str {
    let base = purl_base(s);
    match base.rfind('/') {
        Some(i) => &base[i + 1..],
        None => base,
    }
}

/// Decide whether a VEX `product` entry matches an SBOM `component`.
///
/// Strategy (most-specific first):
/// 1. Exact purl match
/// 2. Base-purl match (ignores version differences between SBOM and VEX)
/// 3. purl_name of product purl  == component name
/// 4. purl_name of component purl == product name
/// 5. Direct name equality
/// 6. product name contains component name (handles CSAF product IDs like `log4j-core-2.17.2`)
fn matches(comp: &Component, product: &Component) -> bool {
    // 1. Exact purl
    if let (Some(cp), Some(pp)) = (&comp.purl, &product.purl) {
        if cp == pp {
            return true;
        }
        // 2. Base purl (version-agnostic)
        if purl_base(cp) == purl_base(pp) {
            return true;
        }
    }
    // 3. purl_name of product purl matches component name
    if let Some(pp) = &product.purl {
        if purl_name(pp) == comp.name {
            return true;
        }
    }
    // 4. purl_name of component purl matches product name
    if let Some(cp) = &comp.purl {
        if purl_name(cp) == product.name {
            return true;
        }
    }
    // 5. Direct name equality
    if comp.name == product.name {
        return true;
    }
    // 6. Product name/bom_ref contains component name (CSAF product IDs)
    let needle = &comp.name;
    if product.name.contains(needle.as_str()) {
        return true;
    }
    if let Some(br) = &product.bom_ref {
        if br.contains(needle.as_str()) {
            return true;
        }
    }
    false
}

/// Pair each VEX statement with the SBOM components it applies to.
fn correlate(sbom: &SbomDocument, vex: &VexDocument) -> Vec<CorrelatedEntry> {
    let mut entries = Vec::new();

    for stmt in &vex.statements {
        let applicable: Vec<&Component> = if stmt.products.is_empty() {
            // No product scope → applies to all SBOM components
            sbom.components.iter().collect()
        } else {
            sbom.components
                .iter()
                .filter(|comp| stmt.products.iter().any(|p| matches(comp, p)))
                .collect()
        };

        for comp in applicable {
            entries.push(CorrelatedEntry {
                vuln_id: stmt.vulnerability.id.clone(),
                description: stmt.vulnerability.description.clone(),
                severity: stmt
                    .vulnerability
                    .severity
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                status: stmt.status.to_string(),
                component_name: comp.name.clone(),
                component_version: comp.version.clone(),
                justification: stmt.justification.clone(),
                action_statement: stmt.action_statement.clone(),
            });
        }
    }

    entries
}

// ─── Minifier ────────────────────────────────────────────────────────────────

/// Minify HTML by trimming each line and removing blank lines.
fn minify_html(html: &str) -> String {
    html.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::Document;
    use crate::models::{
        Component, SbomDocument, Severity, VexDocument, VexStatement, VexStatus, Vulnerability,
    };

    // ── Fixtures ─────────────────────────────────────────────────────────────

    fn sbom_doc() -> Document {
        Document::Sbom(SbomDocument {
            format: "CycloneDX".into(),
            spec_version: Some("1.6".into()),
            serial_number: None,
            version: None,
            components: vec![Component {
                name: "log4j-core".into(),
                version: Some("2.17.2".into()),
                purl: Some("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.2".into()),
                bom_ref: None,
            }],
        })
    }

    fn vex_doc() -> Document {
        Document::Vex(VexDocument {
            id: Some("doc-1".into()),
            author: Some("security-team".into()),
            timestamp: Some("2024-01-01T00:00:00Z".into()),
            version: None,
            statements: vec![VexStatement {
                vulnerability: Vulnerability {
                    id: "CVE-2021-44228".into(),
                    description: Some("Log4Shell".into()),
                    severity: Some(Severity::Critical),
                    aliases: vec![],
                },
                products: vec![],
                status: VexStatus::Fixed,
                justification: None,
                impact_statement: None,
                action_statement: Some("Upgrade to 2.17.2".into()),
            }],
        })
    }

    fn make_sbom(components: Vec<Component>) -> SbomDocument {
        SbomDocument {
            format: "CycloneDX".into(),
            spec_version: None,
            serial_number: None,
            version: None,
            components,
        }
    }

    fn make_vex(statements: Vec<VexStatement>) -> VexDocument {
        VexDocument {
            id: None,
            author: None,
            timestamp: None,
            version: None,
            statements,
        }
    }

    fn comp(name: &str, purl: &str) -> Component {
        Component {
            name: name.into(),
            version: Some("1.0".into()),
            purl: Some(purl.into()),
            bom_ref: None,
        }
    }

    fn stmt_with_product(id: &str, status: VexStatus, product_purl: &str) -> VexStatement {
        VexStatement {
            vulnerability: Vulnerability {
                id: id.into(),
                description: None,
                severity: Some(Severity::High),
                aliases: vec![],
            },
            products: vec![Component {
                name: product_purl.into(),
                version: None,
                purl: Some(product_purl.into()),
                bom_ref: None,
            }],
            status,
            justification: None,
            impact_statement: None,
            action_statement: None,
        }
    }

    fn stmt_global(id: &str, status: VexStatus) -> VexStatement {
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

    // ── Single-document report ────────────────────────────────────────────────

    #[test]
    fn sbom_uses_sbom_template() {
        let (_, tmpl) = build_report(&sbom_doc(), Path::new("sbom.json"));
        assert!(tmpl.contains("SBOM Report"));
        assert!(!tmpl.contains("VEX Report"));
    }

    #[test]
    fn vex_uses_vex_template() {
        let (_, tmpl) = build_report(&vex_doc(), Path::new("vex.json"));
        assert!(tmpl.contains("VEX Report"));
        assert!(!tmpl.contains("SBOM Report"));
    }

    #[test]
    fn sbom_data_contains_component_and_metadata() {
        let (json_str, _) = build_report(&sbom_doc(), Path::new("sbom.json"));
        let data: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(data["components"][0]["name"].as_str(), Some("log4j-core"));
        assert_eq!(data["format"].as_str(), Some("CycloneDX"));
        assert_eq!(data["spec_version"].as_str(), Some("1.6"));
    }

    #[test]
    fn vex_data_contains_vulnerability_and_metadata() {
        let (json_str, _) = build_report(&vex_doc(), Path::new("vex.json"));
        let data: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(data["vulnerabilities"][0]["id"].as_str(), Some("CVE-2021-44228"));
        assert_eq!(data["vulnerabilities"][0]["status"].as_str(), Some("fixed"));
        assert_eq!(data["author"].as_str(), Some("security-team"));
    }

    #[test]
    fn vex_data_has_severity_distribution() {
        let (json_str, _) = build_report(&vex_doc(), Path::new("vex.json"));
        let data: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(data["severity_distribution"]["critical"].as_u64(), Some(1));
    }

    #[test]
    fn both_templates_are_standalone() {
        for tmpl in [SBOM_TEMPLATE, VEX_TEMPLATE, CORRELATED_TEMPLATE] {
            assert!(tmpl.starts_with("<!DOCTYPE html>"));
            assert!(!tmpl.contains("src=\"http"));
            assert!(!tmpl.contains("href=\"http"));
        }
    }

    #[test]
    fn default_output_path_replaces_extension() {
        let mut p = Path::new("tests/data/sbom.json").to_path_buf();
        p.set_extension("html");
        assert_eq!(p, Path::new("tests/data/sbom.html"));
    }

    // ── Correlation: matching ─────────────────────────────────────────────────

    #[test]
    fn exact_purl_match() {
        let c = comp("log4j", "pkg:maven/log4j@1.0");
        let p = comp("log4j", "pkg:maven/log4j@1.0");
        assert!(matches(&c, &p));
    }

    #[test]
    fn base_purl_match_ignores_version() {
        let c = comp("log4j-core", "pkg:maven/org.apache/log4j-core@2.17.2");
        let p = comp("log4j-core", "pkg:maven/org.apache/log4j-core@2.15.0");
        assert!(matches(&c, &p));
    }

    #[test]
    fn purl_name_matches_component_name() {
        let c = comp("log4j-core", "pkg:maven/org.apache/log4j-core@2.17.2");
        let p = Component {
            name: "pkg:maven/org.apache/log4j-core@2.15.0".into(),
            version: None,
            purl: Some("pkg:maven/org.apache/log4j-core@2.15.0".into()),
            bom_ref: None,
        };
        assert!(matches(&c, &p));
    }

    #[test]
    fn csaf_product_id_contains_component_name() {
        let c = comp("log4j-core", "pkg:maven/org.apache/log4j-core@2.17.2");
        let p = Component {
            name: "log4j-core-2.17.2".into(),
            version: None,
            purl: None,
            bom_ref: Some("log4j-core-2.17.2".into()),
        };
        assert!(matches(&c, &p));
    }

    #[test]
    fn no_match_for_different_components() {
        let c = comp("commons-lang3", "pkg:maven/org.apache.commons/commons-lang3@3.12.0");
        let p = comp("log4j-core", "pkg:maven/org.apache/log4j-core@2.15.0");
        assert!(!matches(&c, &p));
    }

    // ── Correlation: correlate() ──────────────────────────────────────────────

    #[test]
    fn global_statement_applies_to_all_components() {
        let sbom = make_sbom(vec![
            comp("log4j-core", "pkg:a@1"),
            comp("commons-lang3", "pkg:b@1"),
        ]);
        let vex = make_vex(vec![stmt_global("CVE-001", VexStatus::Affected)]);
        let result = correlate(&sbom, &vex);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn product_scoped_statement_matches_only_target() {
        let sbom = make_sbom(vec![
            comp("log4j-core", "pkg:maven/org.apache/log4j-core@2.17.2"),
            comp("commons-lang3", "pkg:maven/org.apache/commons-lang3@3.12.0"),
        ]);
        let vex = make_vex(vec![stmt_with_product(
            "CVE-001",
            VexStatus::Fixed,
            "pkg:maven/org.apache/log4j-core@2.15.0",
        )]);
        let result = correlate(&sbom, &vex);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].component_name, "log4j-core");
    }

    #[test]
    fn no_match_produces_empty_correlation() {
        let sbom = make_sbom(vec![comp("zookeeper", "pkg:maven/zookeeper@3.8.0")]);
        let vex = make_vex(vec![stmt_with_product(
            "CVE-001",
            VexStatus::Affected,
            "pkg:maven/log4j-core@2.15.0",
        )]);
        let result = correlate(&sbom, &vex);
        assert_eq!(result.len(), 0);
    }

    // ── Correlation: stats ────────────────────────────────────────────────────

    #[test]
    fn stats_count_correctly() {
        let sbom = make_sbom(vec![
            comp("log4j-core", "pkg:maven/org.apache/log4j-core@2.17.2"),
            comp("commons-lang3", "pkg:maven/org.apache/commons-lang3@3.12.0"),
        ]);
        let vex = make_vex(vec![
            stmt_with_product("CVE-001", VexStatus::Fixed, "pkg:maven/org.apache/log4j-core@2.15.0"),
            stmt_with_product("CVE-002", VexStatus::NotAffected, "pkg:maven/org.apache/log4j-core@2.15.0"),
            stmt_with_product("CVE-003", VexStatus::Affected, "pkg:maven/org.apache/commons-lang3@3.11.0"),
        ]);
        let data = build_correlated_data(&sbom, &vex, "sbom.json", "vex.json");
        let stats = &data["stats"];
        assert_eq!(stats["total"].as_u64(), Some(3));
        assert_eq!(stats["fixed"].as_u64(), Some(1));
        assert_eq!(stats["not_affected"].as_u64(), Some(1));
        assert_eq!(stats["affected"].as_u64(), Some(1));
        assert_eq!(stats["actionable"].as_u64(), Some(1));
        assert_eq!(stats["noise_reduction_pct"].as_u64(), Some(33));
    }

    #[test]
    fn component_risk_includes_all_sbom_components() {
        let sbom = make_sbom(vec![
            comp("log4j-core", "pkg:a@1"),
            comp("clean-lib", "pkg:b@1"),
        ]);
        let vex = make_vex(vec![stmt_with_product("CVE-001", VexStatus::Affected, "pkg:a@1")]);
        let data = build_correlated_data(&sbom, &vex, "s.json", "v.json");
        let risk = data["component_risk"].as_array().unwrap();
        assert_eq!(risk.len(), 2, "all SBOM components must appear in risk table");
    }

    #[test]
    fn component_risk_sorted_by_score_descending() {
        let sbom = make_sbom(vec![
            comp("clean-lib", "pkg:b@1"),
            comp("risky-lib", "pkg:a@1"),
        ]);
        let vex = make_vex(vec![stmt_with_product("CVE-001", VexStatus::Affected, "pkg:a@1")]);
        let data = build_correlated_data(&sbom, &vex, "s.json", "v.json");
        let risk = data["component_risk"].as_array().unwrap();
        // risky-lib has risk_score > 0, must come first
        assert_eq!(risk[0]["name"].as_str(), Some("risky-lib"));
        assert_eq!(risk[1]["name"].as_str(), Some("clean-lib"));
    }

    #[test]
    fn correlated_template_is_used() {
        let sbom = make_sbom(vec![comp("log4j-core", "pkg:a@1")]);
        let vex = make_vex(vec![]);
        let data = build_correlated_data(&sbom, &vex, "sbom.json", "vex.json");
        let json_str = serde_json::to_string(&data).unwrap();
        let html = CORRELATED_TEMPLATE.replace("__DATA_PLACEHOLDER__", &json_str);
        assert!(html.contains("Correlated Security Report"));
        assert!(html.contains("sbom.json"));
        assert!(!html.contains("__DATA_PLACEHOLDER__"));
    }

    // ── minify_html ───────────────────────────────────────────────────────────

    #[test]
    fn minify_removes_blank_lines() {
        assert_eq!(minify_html("line1\n\nline2"), "line1line2");
    }

    #[test]
    fn minify_trims_leading_trailing_whitespace_per_line() {
        assert_eq!(minify_html("  <div>\n    <p>hi</p>\n  </div>"), "<div><p>hi</p></div>");
    }

    #[test]
    fn minify_preserves_content_within_lines() {
        let out = minify_html("  const x = a > b ? 1 : 0;\n  const y = 'hello world';");
        assert!(out.contains("a > b ? 1 : 0"));
        assert!(out.contains("'hello world'"));
    }

    #[test]
    fn minify_output_is_smaller_than_input() {
        let (json_str, tmpl) = build_report(&sbom_doc(), Path::new("sbom.json"));
        let html = tmpl.replace("__DATA_PLACEHOLDER__", &json_str);
        assert!(minify_html(&html).len() < html.len());
    }

    #[test]
    fn minified_html_is_single_line() {
        let (json_str, tmpl) = build_report(&vex_doc(), Path::new("vex.json"));
        let html = tmpl.replace("__DATA_PLACEHOLDER__", &json_str);
        assert!(!minify_html(&html).contains('\n'));
    }
}
