use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn cmd() -> Command {
    Command::cargo_bin("evidger-cli").unwrap()
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Parse the stdout of a merge command as JSON.
fn stdout_json(args: &[&str]) -> serde_json::Value {
    let out = cmd().args(args).output().unwrap();
    assert!(out.status.success(), "merge failed:\n{}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).expect("merge output must be valid JSON")
}

fn component_names(json: &serde_json::Value) -> Vec<String> {
    json["components"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|c| c["name"].as_str().map(String::from))
        .collect()
}

fn vuln_ids(json: &serde_json::Value) -> Vec<String> {
    json["statements"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|s| s["vulnerability"]["name"].as_str().map(String::from))
        .collect()
}

// ─── Same-format SBOM merge ───────────────────────────────────────────────────

// valid : log4j-core@2.17.2, commons-lang3@3.12.0
// v2    : log4j-core@2.17.2, jackson-databind@2.13.4
// merged: log4j-core (dedup), commons-lang3, jackson-databind = 3 components

#[test]
fn merge_two_cyclonedx_sboms_combines_components() {
    let json = stdout_json(&[
        "merge",
        "tests/data/sbom_cyclonedx_valid.json",
        "tests/data/sbom_cyclonedx_v2.json",
    ]);
    let names = component_names(&json);
    assert_eq!(names.len(), 3, "expected 3 unique components, got: {names:?}");
    assert!(names.contains(&"log4j-core".into()));
    assert!(names.contains(&"commons-lang3".into()));
    assert!(names.contains(&"jackson-databind".into()));
}

#[test]
fn merge_cyclonedx_sbom_output_is_valid_cyclonedx() {
    let json = stdout_json(&[
        "merge",
        "tests/data/sbom_cyclonedx_valid.json",
        "tests/data/sbom_cyclonedx_v2.json",
    ]);
    assert_eq!(json["bomFormat"].as_str(), Some("CycloneDX"));
    assert_eq!(json["specVersion"].as_str(), Some("1.6"));
}

#[test]
fn merge_identical_sboms_deduplicates() {
    let json = stdout_json(&[
        "merge",
        "tests/data/sbom_cyclonedx_valid.json",
        "tests/data/sbom_cyclonedx_valid.json",
    ]);
    let names = component_names(&json);
    // log4j-core and commons-lang3 — no duplicates
    assert_eq!(names.len(), 2);
}

// ─── Cross-format SBOM merge (CycloneDX + SPDX) ──────────────────────────────

// cyclonedx_valid : log4j-core@2.17.2, commons-lang3@3.12.0
// spdx_v2         : log4j-core@2.17.2, jackson-databind@2.13.4
// merged          : log4j-core (dedup), commons-lang3, jackson-databind = 3

#[test]
fn merge_cyclonedx_and_spdx_sboms() {
    let json = stdout_json(&[
        "merge",
        "tests/data/sbom_cyclonedx_valid.json",
        "tests/data/sbom_spdx_v2.json",
    ]);
    let names = component_names(&json);
    assert_eq!(names.len(), 3, "expected 3 unique components, got: {names:?}");
    assert!(names.contains(&"log4j-core".into()));
    assert!(names.contains(&"commons-lang3".into()));
    assert!(names.contains(&"jackson-databind".into()));
}

// ─── Version conflict ─────────────────────────────────────────────────────────

// upgraded : log4j-core@2.18.0
// valid    : log4j-core@2.17.2  → conflict, last (valid) wins for the duplicate

#[test]
fn merge_version_conflict_last_wins() {
    let json = stdout_json(&[
        "merge",
        "tests/data/sbom_cyclonedx_upgraded.json",
        "tests/data/sbom_cyclonedx_valid.json",
    ]);
    let components = json["components"].as_array().unwrap();
    let log4j = components
        .iter()
        .find(|c| c["name"].as_str() == Some("log4j-core"))
        .expect("log4j-core must be present");
    assert_eq!(
        log4j["version"].as_str(),
        Some("2.17.2"),
        "last file wins — version should be 2.17.2"
    );
}

#[test]
fn merge_version_conflict_reported_to_stderr() {
    let out = cmd()
        .args([
            "merge",
            "tests/data/sbom_cyclonedx_upgraded.json",
            "tests/data/sbom_cyclonedx_valid.json",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("conflict"),
        "expected conflict warning on stderr; got:\n{stderr}"
    );
    assert!(stderr.contains("log4j-core"));
}

// ─── Same-format VEX merge ────────────────────────────────────────────────────

// valid : CVE-2021-44228 (fixed), CVE-2021-45046 (not_affected)
// v2    : CVE-2021-44228 (fixed), CVE-2022-42003 (not_affected)
// merged: CVE-44228 (dedup), CVE-45046, CVE-42003 = 3 statements

#[test]
fn merge_two_openvex_vexes_combines_statements() {
    let json = stdout_json(&[
        "merge",
        "tests/data/vex_openvex_valid.json",
        "tests/data/vex_openvex_v2.json",
    ]);
    let ids = vuln_ids(&json);
    assert_eq!(ids.len(), 3, "expected 3 unique vulnerabilities, got: {ids:?}");
    assert!(ids.contains(&"CVE-2021-44228".into()));
    assert!(ids.contains(&"CVE-2021-45046".into()));
    assert!(ids.contains(&"CVE-2022-42003".into()));
}

#[test]
fn merge_openvex_output_is_valid_openvex() {
    let json = stdout_json(&[
        "merge",
        "tests/data/vex_openvex_valid.json",
        "tests/data/vex_openvex_v2.json",
    ]);
    assert!(json["@context"].as_str().unwrap_or("").contains("openvex"));
    assert!(json["statements"].is_array());
}

// ─── Cross-format VEX merge (OpenVEX + CSAF) ─────────────────────────────────

// openvex_valid : CVE-2021-44228 (fixed), CVE-2021-45046 (not_affected)
// csaf_v2       : CVE-2021-44228 (fixed), CVE-2022-42003 (not_affected)
// merged        : CVE-44228 (dedup), CVE-45046, CVE-42003 = 3

#[test]
fn merge_openvex_and_csaf_vexes() {
    let json = stdout_json(&[
        "merge",
        "tests/data/vex_openvex_valid.json",
        "tests/data/vex_csaf_v2.json",
    ]);
    let ids = vuln_ids(&json);
    assert_eq!(ids.len(), 3, "expected 3 unique vulnerabilities, got: {ids:?}");
    assert!(ids.contains(&"CVE-2021-44228".into()));
    assert!(ids.contains(&"CVE-2021-45046".into()));
    assert!(ids.contains(&"CVE-2022-42003".into()));
}

// ─── SPDX + SPDX merge ───────────────────────────────────────────────────────

// spdx_valid : log4j-core@2.17.2, commons-lang3@3.12.0
// spdx_v2    : log4j-core@2.17.2, jackson-databind@2.13.4
// merged     : log4j-core (dedup), commons-lang3, jackson-databind = 3

#[test]
fn merge_two_spdx_sboms_combines_components() {
    let json = stdout_json(&[
        "merge",
        "tests/data/sbom_spdx_valid.json",
        "tests/data/sbom_spdx_v2.json",
    ]);
    let names = component_names(&json);
    assert_eq!(names.len(), 3, "expected 3 unique components, got: {names:?}");
    assert!(names.contains(&"log4j-core".into()));
    assert!(names.contains(&"commons-lang3".into()));
    assert!(names.contains(&"jackson-databind".into()));
}

#[test]
fn merge_two_spdx_sboms_output_is_cyclonedx() {
    let json = stdout_json(&[
        "merge",
        "tests/data/sbom_spdx_valid.json",
        "tests/data/sbom_spdx_v2.json",
    ]);
    assert_eq!(json["bomFormat"].as_str(), Some("CycloneDX"));
    assert_eq!(json["specVersion"].as_str(), Some("1.6"));
}

#[test]
fn merge_identical_spdx_sboms_deduplicates() {
    let json = stdout_json(&[
        "merge",
        "tests/data/sbom_spdx_valid.json",
        "tests/data/sbom_spdx_valid.json",
    ]);
    assert_eq!(component_names(&json).len(), 2);
}

// ─── CSAF + CSAF merge ────────────────────────────────────────────────────────

// csaf_valid : CVE-2021-44228 (fixed), CVE-2021-45046 (not_affected)
// csaf_v2    : CVE-2021-44228 (fixed), CVE-2022-42003 (not_affected)
// merged     : CVE-44228 (dedup), CVE-45046, CVE-42003 = 3

#[test]
fn merge_two_csaf_vexes_combines_statements() {
    let json = stdout_json(&[
        "merge",
        "tests/data/vex_csaf_valid.json",
        "tests/data/vex_csaf_v2.json",
    ]);
    let ids = vuln_ids(&json);
    assert_eq!(ids.len(), 3, "expected 3 unique vulnerabilities, got: {ids:?}");
    assert!(ids.contains(&"CVE-2021-44228".into()));
    assert!(ids.contains(&"CVE-2021-45046".into()));
    assert!(ids.contains(&"CVE-2022-42003".into()));
}

#[test]
fn merge_two_csaf_vexes_output_is_openvex() {
    let json = stdout_json(&[
        "merge",
        "tests/data/vex_csaf_valid.json",
        "tests/data/vex_csaf_v2.json",
    ]);
    assert!(json["@context"].as_str().unwrap_or("").contains("openvex"));
    assert!(json["statements"].is_array());
}

#[test]
fn merge_identical_csaf_vexes_deduplicates() {
    let json = stdout_json(&[
        "merge",
        "tests/data/vex_csaf_valid.json",
        "tests/data/vex_csaf_valid.json",
    ]);
    assert_eq!(vuln_ids(&json).len(), 2);
}

#[test]
fn merge_csaf_preserves_justification_and_action_statement() {
    let json = stdout_json(&[
        "merge",
        "tests/data/vex_csaf_valid.json",
        "tests/data/vex_csaf_v2.json",
    ]);
    let stmts = json["statements"].as_array().unwrap();

    let log4shell = stmts
        .iter()
        .find(|s| s["vulnerability"]["name"].as_str() == Some("CVE-2021-44228"))
        .expect("CVE-2021-44228 must be in merged output");
    assert_eq!(log4shell["status"].as_str(), Some("fixed"));
    assert!(
        log4shell["action_statement"].as_str().is_some(),
        "action_statement from CSAF remediation must be preserved"
    );

    let not_affected = stmts
        .iter()
        .find(|s| s["vulnerability"]["name"].as_str() == Some("CVE-2021-45046"))
        .expect("CVE-2021-45046 must be in merged output");
    assert_eq!(not_affected["status"].as_str(), Some("not_affected"));
    assert!(
        not_affected["justification"].as_str().is_some(),
        "justification from CSAF flags must be preserved"
    );
}

// ─── Three-way merge ─────────────────────────────────────────────────────────

#[test]
fn merge_three_sboms() {
    // valid(log4j+commons) + v2(log4j+jackson) + upgraded(log4j@2.18+commons)
    // unique names: log4j-core, commons-lang3, jackson-databind = 3
    let json = stdout_json(&[
        "merge",
        "tests/data/sbom_cyclonedx_valid.json",
        "tests/data/sbom_cyclonedx_v2.json",
        "tests/data/sbom_cyclonedx_upgraded.json",
    ]);
    let names = component_names(&json);
    assert_eq!(names.len(), 3);
}

// ─── Output to file with -o ───────────────────────────────────────────────────

#[test]
fn merge_writes_to_output_file() {
    let out_path = std::env::temp_dir().join("evidger_merge_test_output.json");

    cmd()
        .args([
            "merge",
            "-o",
            out_path.to_str().unwrap(),
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/sbom_cyclonedx_v2.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("merged 2 sources"));

    let content = std::fs::read_to_string(&out_path).expect("output file must exist");
    let json: serde_json::Value = serde_json::from_str(&content).expect("must be valid JSON");
    assert_eq!(json["bomFormat"].as_str(), Some("CycloneDX"));

    let _ = std::fs::remove_file(&out_path);
}

// ─── Error cases ─────────────────────────────────────────────────────────────

#[test]
fn merge_sbom_with_vex_fails() {
    cmd()
        .args([
            "merge",
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/vex_openvex_valid.json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0005"));
}

#[test]
fn merge_missing_file_gives_e0004() {
    cmd()
        .args([
            "merge",
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/does_not_exist.json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0004"));
}

#[test]
fn merge_glob_result_in_all_sboms_succeeds() {
    // tests/data/sbom_cyclonedx_*.json matches multiple CycloneDX files
    let out = cmd()
        .args(["merge", "tests/data/sbom_cyclonedx_*.json"])
        .output()
        .unwrap();
    // Should succeed (all are CycloneDX SBOMs)
    assert!(out.status.success(), "merge failed:\n{}", String::from_utf8_lossy(&out.stderr));
}

// Merge a single SPDX + CycloneDX file (cross-format, same kind)
#[test]
fn merge_spdx_and_cyclonedx_sboms_cross_format() {
    let json = stdout_json(&[
        "merge",
        "tests/data/sbom_spdx_valid.json",
        "tests/data/sbom_cyclonedx_v2.json",
    ]);
    // spdx_valid: log4j-core, commons-lang3
    // cyclonedx_v2: log4j-core, jackson-databind
    let names = component_names(&json);
    assert_eq!(names.len(), 3);
    assert!(names.contains(&"commons-lang3".into()));
    assert!(names.contains(&"jackson-databind".into()));
}

// ─── Output format tests ──────────────────────────────────────────────────────

#[test]
fn merged_vex_output_statements_sorted_by_id() {
    let json = stdout_json(&[
        "merge",
        "tests/data/vex_openvex_valid.json",
        "tests/data/vex_openvex_v2.json",
    ]);
    let ids = vuln_ids(&json);
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted, "statements must be sorted by CVE ID");
}

#[test]
fn merged_sbom_components_sorted_by_name() {
    let json = stdout_json(&[
        "merge",
        "tests/data/sbom_cyclonedx_valid.json",
        "tests/data/sbom_cyclonedx_v2.json",
    ]);
    let names = component_names(&json);
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "components must be sorted by name");
}

// SPDX + CSAF from different sides (3 unique VEX statements)
#[test]
fn merge_csaf_and_openvex_vexes_cross_format() {
    let json = stdout_json(&[
        "merge",
        "tests/data/vex_csaf_valid.json",
        "tests/data/vex_openvex_v2.json",
    ]);
    // csaf_valid: CVE-44228 (fixed), CVE-45046 (not_affected)
    // openvex_v2: CVE-44228 (fixed), CVE-42003 (not_affected)
    let ids = vuln_ids(&json);
    assert_eq!(ids.len(), 3, "expected 3 unique vulnerabilities; got: {ids:?}");
}

// PathBuf import needed for output file test — suppress warning
#[allow(dead_code)]
fn _use_pathbuf(_: PathBuf) {}
