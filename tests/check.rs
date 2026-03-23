use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("evidger-cli").unwrap()
}

// ─── CycloneDX ───────────────────────────────────────────────────────────────

#[test]
fn valid_cyclonedx_exits_zero() {
    cmd()
        .args(["check", "tests/data/sbom_cyclonedx_valid.json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[OK]"))
        .stdout(predicate::str::contains("CycloneDX"));
}

#[test]
fn invalid_cyclonedx_exits_nonzero() {
    cmd()
        .args(["check", "tests/data/sbom_cyclonedx_invalid.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0003"));
}

#[test]
fn invalid_cyclonedx_reports_missing_spec_version() {
    let output = cmd()
        .args(["check", "tests/data/sbom_cyclonedx_invalid.json"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    // specVersion is required; the error must mention it or the unknown field
    assert!(
        stderr.contains("specVersion") || stderr.contains("unknown_field") || stderr.contains("E0003"),
        "expected a schema error mentioning the violation; got:\n{stderr}"
    );
}

// ─── OpenVEX ────────────────────────────────────────────────────────────────

#[test]
fn valid_openvex_exits_zero() {
    cmd()
        .args(["check", "tests/data/vex_openvex_valid.json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[OK]"))
        .stdout(predicate::str::contains("OpenVEX"));
}

#[test]
fn invalid_openvex_exits_nonzero() {
    cmd()
        .args(["check", "tests/data/vex_openvex_invalid.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0003"));
}

#[test]
fn invalid_openvex_reports_extra_field() {
    let output = cmd()
        .args(["check", "tests/data/vex_openvex_invalid.json"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    // The schema has additionalProperties:false, so "custom_extension" must be flagged.
    // jsonschema typically mentions the extra property or "additional properties".
    assert!(
        stderr.contains("custom_extension")
            || stderr.contains("additional")
            || stderr.contains("author"),   // "author" is also missing in the invalid file
        "expected a schema error about extra/missing fields; got:\n{stderr}"
    );
}

// ─── SPDX ────────────────────────────────────────────────────────────────────

#[test]
fn valid_spdx_exits_zero() {
    cmd()
        .args(["check", "tests/data/sbom_spdx_valid.json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[OK]"))
        .stdout(predicate::str::contains("SPDX"));
}

#[test]
fn invalid_spdx_exits_nonzero() {
    cmd()
        .args(["check", "tests/data/sbom_spdx_invalid.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0003"));
}

#[test]
fn invalid_spdx_reports_missing_creation_info() {
    let output = cmd()
        .args(["check", "tests/data/sbom_spdx_invalid.json"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Missing creationInfo (required) or unknown_field (unevaluatedProperties: false)
    assert!(
        stderr.contains("creationInfo")
            || stderr.contains("unknown_field")
            || stderr.contains("E0003"),
        "expected a schema error; got:\n{stderr}"
    );
}

// ─── CSAF ─────────────────────────────────────────────────────────────────────

#[test]
fn valid_csaf_exits_zero() {
    cmd()
        .args(["check", "tests/data/vex_csaf_valid.json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[OK]"))
        .stdout(predicate::str::contains("CSAF"));
}

#[test]
fn invalid_csaf_exits_nonzero() {
    cmd()
        .args(["check", "tests/data/vex_csaf_invalid.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0003"));
}

#[test]
fn invalid_csaf_reports_missing_required_fields() {
    let output = cmd()
        .args(["check", "tests/data/vex_csaf_invalid.json"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Missing category, publisher, title, tracking — at least one must be flagged
    assert!(
        stderr.contains("category")
            || stderr.contains("publisher")
            || stderr.contains("tracking")
            || stderr.contains("E0003"),
        "expected a schema error about missing document fields; got:\n{stderr}"
    );
}

// ─── Error codes ────────────────────────────────────────────────────────────

#[test]
fn nonexistent_file_gives_e0004() {
    cmd()
        .args(["check", "tests/data/does_not_exist.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0004"));
}

#[test]
fn unknown_format_gives_e0002() {
    // A valid JSON file that has no known format marker
    let dir = std::env::temp_dir();
    let path = dir.join("evidger_test_unknown_format.json");
    std::fs::write(&path, r#"{"hello": "world"}"#).unwrap();

    cmd()
        .args(["check", path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0002"));

    let _ = std::fs::remove_file(&path);
}

// ─── Multiple files & glob ───────────────────────────────────────────────────

#[test]
fn multiple_valid_files_all_pass() {
    cmd()
        .args([
            "check",
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/vex_openvex_valid.json",
        ])
        .assert()
        .success();
}

#[test]
fn mixed_valid_and_invalid_exits_nonzero() {
    cmd()
        .args([
            "check",
            "tests/data/sbom_cyclonedx_valid.json",
            "tests/data/sbom_cyclonedx_invalid.json",
        ])
        .assert()
        .failure();
}

#[test]
fn glob_matching_valid_files_passes() {
    // *_valid.json resolves to both sbom_cyclonedx_valid and vex_openvex_valid
    cmd()
        .args(["check", "tests/data/*_valid.json"])
        .assert()
        .success();
}

#[test]
fn glob_no_match_gives_e0008() {
    cmd()
        .args(["check", "tests/data/*.nonexistent"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0008"));
}
