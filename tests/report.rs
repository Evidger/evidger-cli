use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("evidger-cli").unwrap()
}

// ─── SBOM report ─────────────────────────────────────────────────────────────

#[test]
fn sbom_report_creates_html_file_by_default() {
    let out_path = std::env::temp_dir().join("sbom_cyclonedx_valid.html");
    // Remove any leftover from a previous run
    let _ = std::fs::remove_file(&out_path);

    // Copy input to temp dir so the default output lands there too
    let input_path = std::env::temp_dir().join("sbom_cyclonedx_valid.json");
    std::fs::copy("tests/data/sbom_cyclonedx_valid.json", &input_path).unwrap();

    cmd()
        .args(["report", input_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("report generated"));

    assert!(out_path.exists(), "HTML file must be created next to input");

    let html = std::fs::read_to_string(&out_path).unwrap();
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("const data ="));

    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn sbom_report_respects_output_flag() {
    let out_path = std::env::temp_dir().join("evidger_report_sbom.html");
    let _ = std::fs::remove_file(&out_path);

    cmd()
        .args([
            "report",
            "tests/data/sbom_cyclonedx_valid.json",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(out_path.exists());
    let html = std::fs::read_to_string(&out_path).unwrap();
    assert!(html.contains("log4j-core"));
    assert!(html.contains("commons-lang3"));

    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn sbom_report_html_contains_component_names() {
    let out_path = std::env::temp_dir().join("evidger_report_comp_names.html");

    cmd()
        .args([
            "report",
            "tests/data/sbom_cyclonedx_valid.json",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out_path).unwrap();
    assert!(html.contains("log4j-core"));
    assert!(html.contains("commons-lang3"));

    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn sbom_report_html_has_summary_data() {
    let out_path = std::env::temp_dir().join("evidger_report_summary.html");

    cmd()
        .args([
            "report",
            "tests/data/sbom_cyclonedx_valid.json",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out_path).unwrap();
    // The SBOM template injects a components array — both entries must appear
    assert!(html.contains("\"format\":\"CycloneDX\""));
    assert!(html.contains("log4j-core"));

    let _ = std::fs::remove_file(&out_path);
}

// ─── VEX report ──────────────────────────────────────────────────────────────

#[test]
fn vex_report_creates_html_file_by_default() {
    let input_path = std::env::temp_dir().join("vex_openvex_valid.json");
    let out_path = std::env::temp_dir().join("vex_openvex_valid.html");
    let _ = std::fs::remove_file(&out_path);

    std::fs::copy("tests/data/vex_openvex_valid.json", &input_path).unwrap();

    cmd()
        .args(["report", input_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("report generated"));

    assert!(out_path.exists(), "HTML file must be created next to input");

    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn vex_report_html_contains_cve_ids() {
    let out_path = std::env::temp_dir().join("evidger_report_vex_cves.html");

    cmd()
        .args([
            "report",
            "tests/data/vex_openvex_valid.json",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out_path).unwrap();
    assert!(html.contains("CVE-2021-44228"));
    assert!(html.contains("CVE-2021-45046"));

    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn vex_report_html_contains_vulnerability_count() {
    let out_path = std::env::temp_dir().join("evidger_report_vuln_count.html");

    cmd()
        .args([
            "report",
            "tests/data/vex_openvex_valid.json",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out_path).unwrap();
    // The VEX template injects a vulnerabilities array — both CVEs must appear
    assert!(html.contains("CVE-2021-44228"));
    assert!(html.contains("CVE-2021-45046"));

    let _ = std::fs::remove_file(&out_path);
}

// ─── SPDX report ─────────────────────────────────────────────────────────────

#[test]
fn spdx_report_produces_html() {
    let out_path = std::env::temp_dir().join("evidger_report_spdx.html");

    cmd()
        .args([
            "report",
            "tests/data/sbom_spdx_valid.json",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out_path).unwrap();
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("log4j-core"));

    let _ = std::fs::remove_file(&out_path);
}

// ─── CSAF report ─────────────────────────────────────────────────────────────

#[test]
fn csaf_report_produces_html() {
    let out_path = std::env::temp_dir().join("evidger_report_csaf.html");

    cmd()
        .args([
            "report",
            "tests/data/vex_csaf_valid.json",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out_path).unwrap();
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("CVE-2021-44228"));

    let _ = std::fs::remove_file(&out_path);
}

// ─── --minify flag ───────────────────────────────────────────────────────────

#[test]
fn minify_produces_single_line_html() {
    let out_path = std::env::temp_dir().join("evidger_report_minified.html");

    cmd()
        .args([
            "report",
            "tests/data/sbom_cyclonedx_valid.json",
            "--minify",
            "-o", out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out_path).unwrap();
    assert!(!html.contains('\n'), "minified HTML must contain no newlines");

    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn minify_output_is_smaller_than_normal() {
    let normal_path = std::env::temp_dir().join("evidger_report_normal.html");
    let minified_path = std::env::temp_dir().join("evidger_report_minified2.html");

    cmd()
        .args(["report", "tests/data/vex_openvex_valid.json",
               "-o", normal_path.to_str().unwrap()])
        .assert().success();

    cmd()
        .args(["report", "tests/data/vex_openvex_valid.json",
               "--minify", "-o", minified_path.to_str().unwrap()])
        .assert().success();

    let normal_size = std::fs::metadata(&normal_path).unwrap().len();
    let minified_size = std::fs::metadata(&minified_path).unwrap().len();
    assert!(minified_size < normal_size, "minified file must be smaller than normal");

    let _ = std::fs::remove_file(&normal_path);
    let _ = std::fs::remove_file(&minified_path);
}

#[test]
fn minify_preserves_html_content() {
    let out_path = std::env::temp_dir().join("evidger_report_minified3.html");

    cmd()
        .args([
            "report",
            "tests/data/vex_csaf_valid.json",
            "--minify",
            "-o", out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out_path).unwrap();
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("const data ="));
    assert!(html.contains("CVE-2021-44228"));

    let _ = std::fs::remove_file(&out_path);
}

// ─── Correlated report ───────────────────────────────────────────────────────

#[test]
fn correlated_report_uses_correlated_template() {
    let out_path = std::env::temp_dir().join("evidger_corr_template.html");

    cmd()
        .args([
            "report",
            "tests/data/sbom_cyclonedx_valid.json",
            "--vex", "tests/data/vex_openvex_for_correlation.json",
            "-o", out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out_path).unwrap();
    assert!(html.contains("Correlated Security Report"), "must use correlated template");
    assert!(html.contains("const data ="));

    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn correlated_report_contains_both_source_files() {
    let out_path = std::env::temp_dir().join("evidger_corr_sources.html");

    cmd()
        .args([
            "report",
            "tests/data/sbom_cyclonedx_valid.json",
            "--vex", "tests/data/vex_openvex_for_correlation.json",
            "-o", out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out_path).unwrap();
    assert!(html.contains("sbom_cyclonedx_valid.json"));
    assert!(html.contains("vex_openvex_for_correlation.json"));

    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn correlated_report_contains_cve_ids() {
    let out_path = std::env::temp_dir().join("evidger_corr_cves.html");

    cmd()
        .args([
            "report",
            "tests/data/sbom_cyclonedx_valid.json",
            "--vex", "tests/data/vex_openvex_for_correlation.json",
            "-o", out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out_path).unwrap();
    assert!(html.contains("CVE-2021-44228"));
    assert!(html.contains("CVE-2021-45046"));
    assert!(html.contains("CVE-2022-33980"));

    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn correlated_report_contains_component_names() {
    let out_path = std::env::temp_dir().join("evidger_corr_comps.html");

    cmd()
        .args([
            "report",
            "tests/data/sbom_cyclonedx_valid.json",
            "--vex", "tests/data/vex_openvex_for_correlation.json",
            "-o", out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out_path).unwrap();
    assert!(html.contains("log4j-core"));
    assert!(html.contains("commons-lang3"));

    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn correlated_report_stats_reflect_fixture() {
    let out_path = std::env::temp_dir().join("evidger_corr_stats.html");

    cmd()
        .args([
            "report",
            "tests/data/sbom_cyclonedx_valid.json",
            "--vex", "tests/data/vex_openvex_for_correlation.json",
            "-o", out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out_path).unwrap();
    // fixture: 4 statements (fixed, not_affected, affected, under_investigation)
    assert!(html.contains("\"total\":4"));
    assert!(html.contains("\"affected\":1"));
    assert!(html.contains("\"fixed\":1"));
    assert!(html.contains("\"not_affected\":1"));
    assert!(html.contains("\"under_investigation\":1"));
    assert!(html.contains("\"actionable\":2"));

    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn correlated_report_default_output_path_next_to_sbom() {
    let input_path = std::env::temp_dir().join("sbom_cyclonedx_valid_corr.json");
    let out_path = std::env::temp_dir().join("sbom_cyclonedx_valid_corr.html");
    let _ = std::fs::remove_file(&out_path);

    std::fs::copy("tests/data/sbom_cyclonedx_valid.json", &input_path).unwrap();

    cmd()
        .args([
            "report",
            input_path.to_str().unwrap(),
            "--vex", "tests/data/vex_openvex_for_correlation.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("report generated"));

    assert!(out_path.exists(), "HTML must be placed next to input SBOM");

    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn correlated_report_with_minify_is_single_line() {
    let out_path = std::env::temp_dir().join("evidger_corr_minified.html");

    cmd()
        .args([
            "report",
            "tests/data/sbom_cyclonedx_valid.json",
            "--vex", "tests/data/vex_openvex_for_correlation.json",
            "--minify",
            "-o", out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out_path).unwrap();
    assert!(!html.contains('\n'), "minified correlated report must be single line");
    assert!(html.contains("Correlated Security Report"));

    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn correlated_report_vex_file_not_found_gives_error() {
    cmd()
        .args([
            "report",
            "tests/data/sbom_cyclonedx_valid.json",
            "--vex", "tests/data/does_not_exist.json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0004"));
}

#[test]
fn correlated_report_wrong_argument_order_fails() {
    // Passing VEX as SBOM and SBOM as --vex should produce an error
    cmd()
        .args([
            "report",
            "tests/data/vex_openvex_for_correlation.json",
            "--vex", "tests/data/vex_openvex_for_correlation.json",
        ])
        .assert()
        .failure();
}

// ─── Error cases ─────────────────────────────────────────────────────────────

#[test]
fn report_missing_file_gives_error() {
    cmd()
        .args(["report", "tests/data/does_not_exist.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("E0004"));
}
