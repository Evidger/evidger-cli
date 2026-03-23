use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("evidger-cli").unwrap()
}

fn stdout_json(args: &[&str]) -> serde_json::Value {
    let out = cmd().args(args).output().unwrap();
    assert!(
        out.status.success(),
        "convert failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("output must be valid JSON")
}

// ─── CycloneDX → SPDX ────────────────────────────────────────────────────────

#[test]
fn cyclonedx_to_spdx_produces_spdx_context() {
    let json = stdout_json(&["convert", "tests/data/sbom_cyclonedx_valid.json", "--to", "spdx"]);
    assert_eq!(
        json["@context"].as_str(),
        Some("https://spdx.org/rdf/3.0.0/spdx-context.jsonld")
    );
}

#[test]
fn cyclonedx_to_spdx_preserves_all_components() {
    let json = stdout_json(&["convert", "tests/data/sbom_cyclonedx_valid.json", "--to", "spdx"]);
    let packages: Vec<_> = json["@graph"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["type"].as_str() == Some("software_Package"))
        .collect();
    assert_eq!(packages.len(), 2, "expected 2 packages (log4j-core + commons-lang3)");
    let names: Vec<_> = packages.iter().filter_map(|p| p["name"].as_str()).collect();
    assert!(names.contains(&"log4j-core"));
    assert!(names.contains(&"commons-lang3"));
}

#[test]
fn cyclonedx_to_spdx_preserves_purl_as_external_identifier() {
    let json = stdout_json(&["convert", "tests/data/sbom_cyclonedx_valid.json", "--to", "spdx"]);
    let pkg = json["@graph"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"].as_str() == Some("log4j-core"))
        .unwrap();
    assert_eq!(
        pkg["externalIdentifier"][0]["externalIdentifierType"].as_str(),
        Some("packageUrl")
    );
}

// ─── SPDX → CycloneDX ────────────────────────────────────────────────────────

#[test]
fn spdx_to_cyclonedx_produces_cyclonedx_format() {
    let json = stdout_json(&["convert", "tests/data/sbom_spdx_valid.json", "--to", "cyclonedx"]);
    assert_eq!(json["bomFormat"].as_str(), Some("CycloneDX"));
    assert_eq!(json["specVersion"].as_str(), Some("1.6"));
}

#[test]
fn spdx_to_cyclonedx_preserves_all_components() {
    let json = stdout_json(&["convert", "tests/data/sbom_spdx_valid.json", "--to", "cyclonedx"]);
    let comps = json["components"].as_array().unwrap();
    assert_eq!(comps.len(), 2);
    let names: Vec<_> = comps.iter().filter_map(|c| c["name"].as_str()).collect();
    assert!(names.contains(&"log4j-core"));
    assert!(names.contains(&"commons-lang3"));
}

// ─── OpenVEX → CSAF ──────────────────────────────────────────────────────────

#[test]
fn openvex_to_csaf_produces_csaf_version() {
    let json = stdout_json(&["convert", "tests/data/vex_openvex_valid.json", "--to", "csaf"]);
    assert_eq!(json["document"]["csaf_version"].as_str(), Some("2.0"));
    assert_eq!(json["document"]["category"].as_str(), Some("csaf_vex"));
}

#[test]
fn openvex_to_csaf_preserves_all_vulnerabilities() {
    let json = stdout_json(&["convert", "tests/data/vex_openvex_valid.json", "--to", "csaf"]);
    let vulns = json["vulnerabilities"].as_array().unwrap();
    assert_eq!(vulns.len(), 2);
    let ids: Vec<_> = vulns.iter().filter_map(|v| v["cve"].as_str()).collect();
    assert!(ids.contains(&"CVE-2021-44228"));
    assert!(ids.contains(&"CVE-2021-45046"));
}

#[test]
fn openvex_fixed_becomes_vendor_fix_remediation() {
    let json = stdout_json(&["convert", "tests/data/vex_openvex_valid.json", "--to", "csaf"]);
    let vuln = json["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["cve"].as_str() == Some("CVE-2021-44228"))
        .unwrap();
    assert_eq!(vuln["remediations"][0]["category"].as_str(), Some("vendor_fix"));
}

#[test]
fn openvex_not_affected_becomes_csaf_flag() {
    let json = stdout_json(&["convert", "tests/data/vex_openvex_valid.json", "--to", "csaf"]);
    let vuln = json["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["cve"].as_str() == Some("CVE-2021-45046"))
        .unwrap();
    assert!(vuln["flags"][0]["label"].as_str().is_some());
}

// ─── CSAF → OpenVEX ──────────────────────────────────────────────────────────

#[test]
fn csaf_to_openvex_produces_openvex_context() {
    let json = stdout_json(&["convert", "tests/data/vex_csaf_valid.json", "--to", "openvex"]);
    assert!(json["@context"].as_str().unwrap().contains("openvex"));
    assert!(json["statements"].is_array());
}

#[test]
fn csaf_to_openvex_preserves_all_vulnerabilities() {
    let json = stdout_json(&["convert", "tests/data/vex_csaf_valid.json", "--to", "openvex"]);
    let stmts = json["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 2);
    let ids: Vec<_> = stmts
        .iter()
        .filter_map(|s| s["vulnerability"]["name"].as_str())
        .collect();
    assert!(ids.contains(&"CVE-2021-44228"));
    assert!(ids.contains(&"CVE-2021-45046"));
}

#[test]
fn csaf_to_openvex_preserves_status() {
    let json = stdout_json(&["convert", "tests/data/vex_csaf_valid.json", "--to", "openvex"]);
    let stmts = json["statements"].as_array().unwrap();
    let log4shell = stmts
        .iter()
        .find(|s| s["vulnerability"]["name"].as_str() == Some("CVE-2021-44228"))
        .unwrap();
    assert_eq!(log4shell["status"].as_str(), Some("fixed"));
}

// ─── Identity round-trips ─────────────────────────────────────────────────────

#[test]
fn cyclonedx_roundtrip_preserves_component_count() {
    // CycloneDX → SPDX → re-check component count
    let spdx = stdout_json(&["convert", "tests/data/sbom_cyclonedx_valid.json", "--to", "spdx"]);
    let pkg_count = spdx["@graph"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["type"].as_str() == Some("software_Package"))
        .count();
    assert_eq!(pkg_count, 2);
}

#[test]
fn openvex_roundtrip_preserves_statement_count() {
    // OpenVEX → CSAF → re-check statement count
    let csaf = stdout_json(&["convert", "tests/data/vex_openvex_valid.json", "--to", "csaf"]);
    assert_eq!(csaf["vulnerabilities"].as_array().unwrap().len(), 2);
}

// ─── Output to file with -o ───────────────────────────────────────────────────

#[test]
fn convert_writes_to_output_file() {
    let out_path = std::env::temp_dir().join("evidger_convert_test.json");

    cmd()
        .args([
            "convert",
            "tests/data/sbom_cyclonedx_valid.json",
            "--to", "spdx",
            "-o", out_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("SPDX"));

    let content = std::fs::read_to_string(&out_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(json["@context"].as_str().unwrap().contains("spdx.org"));

    let _ = std::fs::remove_file(&out_path);
}

// ─── Converted output passes schema validation ───────────────────────────────

#[test]
fn cyclonedx_to_spdx_output_passes_check() {
    let out_path = std::env::temp_dir().join("evidger_check_spdx.json");

    cmd()
        .args(["convert", "tests/data/sbom_cyclonedx_valid.json", "--to", "spdx",
               "-o", out_path.to_str().unwrap()])
        .assert().success();

    cmd()
        .args(["check", out_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("[OK]"));

    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn openvex_to_csaf_output_passes_check() {
    let out_path = std::env::temp_dir().join("evidger_check_csaf.json");

    cmd()
        .args(["convert", "tests/data/vex_openvex_valid.json", "--to", "csaf",
               "-o", out_path.to_str().unwrap()])
        .assert().success();

    cmd()
        .args(["check", out_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("[OK]"));

    let _ = std::fs::remove_file(&out_path);
}

// ─── Error cases ─────────────────────────────────────────────────────────────

#[test]
fn convert_sbom_to_vex_format_fails() {
    cmd()
        .args(["convert", "tests/data/sbom_cyclonedx_valid.json", "--to", "csaf"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0002"));
}

#[test]
fn convert_vex_to_sbom_format_fails() {
    cmd()
        .args(["convert", "tests/data/vex_openvex_valid.json", "--to", "cyclonedx"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0002"));
}

#[test]
fn convert_missing_file_gives_e0004() {
    cmd()
        .args(["convert", "tests/data/does_not_exist.json", "--to", "spdx"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0004"));
}

#[test]
fn convert_invalid_format_argument_fails() {
    cmd()
        .args(["convert", "tests/data/sbom_cyclonedx_valid.json", "--to", "invalid"])
        .assert()
        .failure();
}
