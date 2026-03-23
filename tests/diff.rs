use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("evidger-cli").unwrap()
}

// ─── Identical files ─────────────────────────────────────────────────────────

#[test]
fn identical_sbom_reports_no_differences() {
    cmd()
        .args([
            "diff",
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/sbom_cyclonedx_valid.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("identical"));
}

#[test]
fn identical_vex_reports_no_differences() {
    cmd()
        .args([
            "diff",
            "tests/data/vex_openvex_valid.json",
            "tests/data/vex_openvex_valid.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("identical"));
}

// ─── SBOM component changes ───────────────────────────────────────────────────

// valid   : log4j-core@2.17.2, commons-lang3@3.12.0
// v2      : log4j-core@2.17.2, jackson-databind@2.13.4
// expected: - commons-lang3, + jackson-databind

#[test]
fn sbom_diff_shows_removed_component() {
    cmd()
        .args([
            "diff",
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/sbom_cyclonedx_v2.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("- component"))
        .stdout(predicate::str::contains("commons-lang3"));
}

#[test]
fn sbom_diff_shows_added_component() {
    cmd()
        .args([
            "diff",
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/sbom_cyclonedx_v2.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("+ component"))
        .stdout(predicate::str::contains("jackson-databind"));
}

#[test]
fn sbom_diff_common_component_not_shown_as_change() {
    // log4j-core is in both — it must NOT appear in the diff output
    let output = cmd()
        .args([
            "diff",
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/sbom_cyclonedx_v2.json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let log4j_changes = stdout
        .lines()
        .filter(|l| l.contains("log4j-core") && (l.starts_with('+') || l.starts_with('-')))
        .count();

    assert_eq!(log4j_changes, 0, "log4j-core is unchanged and must not appear in diff");
}

#[test]
fn sbom_diff_against_empty_shows_all_removed() {
    // empty SBOM has no components → everything in valid is "removed"
    let output = cmd()
        .args([
            "diff",
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/sbom_cyclonedx_empty.json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let removed = stdout.lines().filter(|l| l.starts_with('-')).count();
    assert_eq!(removed, 2, "both components must be listed as removed");
}

#[test]
fn sbom_diff_reversed_direction() {
    // Diffing v2→valid should show the inverse: + commons-lang3, - jackson-databind
    let output = cmd()
        .args([
            "diff",
            "tests/data/sbom_cyclonedx_v2.json",
            "tests/data/sbom_cyclonedx_valid.json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("+ component") && stdout.contains("commons-lang3"));
    assert!(stdout.contains("- component") && stdout.contains("jackson-databind"));
}

// ─── VEX vulnerability changes ────────────────────────────────────────────────

// valid : CVE-2021-44228, CVE-2021-45046
// v2    : CVE-2021-44228, CVE-2022-42003
// expected: - CVE-2021-45046, + CVE-2022-42003

#[test]
fn vex_diff_shows_removed_vulnerability() {
    cmd()
        .args([
            "diff",
            "tests/data/vex_openvex_valid.json",
            "tests/data/vex_openvex_v2.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("- vulnerability"))
        .stdout(predicate::str::contains("CVE-2021-45046"));
}

#[test]
fn vex_diff_shows_added_vulnerability() {
    cmd()
        .args([
            "diff",
            "tests/data/vex_openvex_valid.json",
            "tests/data/vex_openvex_v2.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("+ vulnerability"))
        .stdout(predicate::str::contains("CVE-2022-42003"));
}

#[test]
fn vex_diff_common_vulnerability_not_shown_as_change() {
    let output = cmd()
        .args([
            "diff",
            "tests/data/vex_openvex_valid.json",
            "tests/data/vex_openvex_v2.json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let cve44228_changes = stdout
        .lines()
        .filter(|l| l.contains("CVE-2021-44228") && (l.starts_with('+') || l.starts_with('-')))
        .count();

    assert_eq!(cve44228_changes, 0, "CVE-2021-44228 is unchanged and must not appear in diff");
}

// ─── SPDX SBOM diff ───────────────────────────────────────────────────────────

// valid : log4j-core@2.17.2, commons-lang3@3.12.0
// v2    : log4j-core@2.17.2, jackson-databind@2.13.4
// expected: - commons-lang3, + jackson-databind

#[test]
fn spdx_identical_sbom_reports_no_differences() {
    cmd()
        .args([
            "diff",
            "tests/data/sbom_spdx_valid.json",
            "tests/data/sbom_spdx_valid.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("identical"));
}

#[test]
fn spdx_diff_shows_removed_component() {
    cmd()
        .args([
            "diff",
            "tests/data/sbom_spdx_valid.json",
            "tests/data/sbom_spdx_v2.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("- component"))
        .stdout(predicate::str::contains("commons-lang3"));
}

#[test]
fn spdx_diff_shows_added_component() {
    cmd()
        .args([
            "diff",
            "tests/data/sbom_spdx_valid.json",
            "tests/data/sbom_spdx_v2.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("+ component"))
        .stdout(predicate::str::contains("jackson-databind"));
}

#[test]
fn spdx_diff_common_component_not_shown() {
    let output = cmd()
        .args([
            "diff",
            "tests/data/sbom_spdx_valid.json",
            "tests/data/sbom_spdx_v2.json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let log4j_changes = stdout
        .lines()
        .filter(|l| l.contains("log4j-core") && (l.starts_with('+') || l.starts_with('-')))
        .count();
    assert_eq!(log4j_changes, 0, "log4j-core is unchanged and must not appear in diff");
}

// ─── CSAF VEX diff ────────────────────────────────────────────────────────────

// valid : CVE-2021-44228 (fixed), CVE-2021-45046 (not_affected)
// v2    : CVE-2021-44228 (fixed), CVE-2022-42003 (not_affected)
// expected: - CVE-2021-45046, + CVE-2022-42003

#[test]
fn csaf_identical_vex_reports_no_differences() {
    cmd()
        .args([
            "diff",
            "tests/data/vex_csaf_valid.json",
            "tests/data/vex_csaf_valid.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("identical"));
}

#[test]
fn csaf_diff_shows_removed_vulnerability() {
    cmd()
        .args([
            "diff",
            "tests/data/vex_csaf_valid.json",
            "tests/data/vex_csaf_v2.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("- vulnerability"))
        .stdout(predicate::str::contains("CVE-2021-45046"));
}

#[test]
fn csaf_diff_shows_added_vulnerability() {
    cmd()
        .args([
            "diff",
            "tests/data/vex_csaf_valid.json",
            "tests/data/vex_csaf_v2.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("+ vulnerability"))
        .stdout(predicate::str::contains("CVE-2022-42003"));
}

#[test]
fn csaf_diff_common_vulnerability_not_shown() {
    let output = cmd()
        .args([
            "diff",
            "tests/data/vex_csaf_valid.json",
            "tests/data/vex_csaf_v2.json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let cve44228_changes = stdout
        .lines()
        .filter(|l| l.contains("CVE-2021-44228") && (l.starts_with('+') || l.starts_with('-')))
        .count();
    assert_eq!(cve44228_changes, 0, "CVE-2021-44228 is unchanged and must not appear in diff");
}

// ─── Cross-format SBOM diff (CycloneDX vs SPDX) ──────────────────────────────

#[test]
fn diff_cyclonedx_against_spdx_fails() {
    cmd()
        .args([
            "diff",
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/sbom_spdx_valid.json",
        ])
        .assert()
        // Both are SBOMs — diff should succeed (both parse as SbomDocument)
        .success();
}

// ─── SBOM version change ──────────────────────────────────────────────────────

// valid    : log4j-core@2.17.2, commons-lang3@3.12.0
// upgraded : log4j-core@2.18.0, commons-lang3@3.12.0
// expected : ~ log4j-core  2.17.2 -> 2.18.0  (commons-lang3 unchanged)

#[test]
fn sbom_diff_shows_version_change() {
    cmd()
        .args([
            "diff",
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/sbom_cyclonedx_upgraded.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("~ component"))
        .stdout(predicate::str::contains("log4j-core"))
        .stdout(predicate::str::contains("2.17.2"))
        .stdout(predicate::str::contains("2.18.0"));
}

#[test]
fn sbom_diff_unchanged_component_not_shown_as_version_change() {
    let output = cmd()
        .args([
            "diff",
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/sbom_cyclonedx_upgraded.json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    // commons-lang3 is identical in both files — must not appear at all
    assert!(
        !stdout.contains("commons-lang3"),
        "commons-lang3 is unchanged and must not appear in diff"
    );
}

// ─── VEX status change (remediation) ─────────────────────────────────────────

#[test]
fn vex_diff_shows_remediation_as_status_change() {
    cmd()
        .args([
            "diff",
            "tests/data/vex_openvex_before_remediation.json",
            "tests/data/vex_openvex_valid.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("~"))
        .stdout(predicate::str::contains("CVE-2021-44228"))
        .stdout(predicate::str::contains("affected"))
        .stdout(predicate::str::contains("fixed"));
}

// ─── VEX field changes ────────────────────────────────────────────────────────

// before_remediation : CVE-2021-44228 affected + action_statement
// valid              : CVE-2021-44228 fixed, no action_statement
// expected: StatusChanged + ActionStatementChanged for CVE-2021-44228

#[test]
fn vex_diff_shows_action_statement_change() {
    cmd()
        .args([
            "diff",
            "tests/data/vex_openvex_before_remediation.json",
            "tests/data/vex_openvex_valid.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("action:"))
        .stdout(predicate::str::contains("CVE-2021-44228"));
}

// valid                  : CVE-2021-45046 justification=vulnerable_code_not_present
// justification_updated  : CVE-2021-45046 justification=inline_mitigations_already_exist
// expected: JustificationChanged for CVE-2021-45046

#[test]
fn vex_diff_shows_justification_change() {
    cmd()
        .args([
            "diff",
            "tests/data/vex_openvex_valid.json",
            "tests/data/vex_openvex_justification_updated.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("justification:"))
        .stdout(predicate::str::contains("CVE-2021-45046"))
        .stdout(predicate::str::contains("vulnerable_code_not_present"))
        .stdout(predicate::str::contains("inline_mitigations_already_exist"));
}

// ─── Error cases ─────────────────────────────────────────────────────────────

#[test]
fn diff_sbom_against_vex_fails() {
    cmd()
        .args([
            "diff",
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/vex_openvex_valid.json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0002"));
}

#[test]
fn diff_missing_file_gives_e0004() {
    cmd()
        .args([
            "diff",
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/does_not_exist.json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0004"));
}
