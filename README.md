# evidger-cli

**A fast, self-contained CLI for validating, comparing, merging, converting, and reporting on SBOM and VEX documents.**

evidger helps security and engineering teams manage software supply chain risk by providing a unified interface for the most common SBOM and VEX standards — without any external dependencies, network calls, or heavy toolchain.

---

## Table of Contents

- [Why evidger?](#why-evidger)
- [Supported Formats](#supported-formats)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [check](#check--validate-sbom--vex-documents)
  - [diff](#diff--compare-two-documents)
  - [merge](#merge--combine-multiple-documents)
  - [convert](#convert--change-format)
  - [report](#report--generate-html-reports)
- [Use Cases](#use-cases)
- [Output & Exit Codes](#output--exit-codes)
- [Error Reference](#error-reference)
- [Architecture](#architecture)
- [Contributing](#contributing)

---

## Why evidger?

Software supply chain security requires working across multiple SBOM and VEX standards. Different tools produce different formats. Teams need to validate files before ingesting them, diff SBOMs between releases, merge VEX documents from multiple vendors, and generate human-readable reports for stakeholders.

evidger brings all of this into one binary:

- **No network access required** — JSON schemas are embedded at compile time
- **Format-agnostic** — automatically detects CycloneDX, SPDX, OpenVEX, and CSAF
- **Composable** — every command reads from files and writes to stdout or a file, pipeable with other tools
- **Strict validation** — schema-driven, catches missing fields and extra properties
- **CI-friendly** — structured exit codes, glob support, file output flags

---

## Supported Formats

| Category | Format | Version |
|----------|--------|---------|
| SBOM | [CycloneDX](https://cyclonedx.org/) | 1.6 |
| SBOM | [SPDX](https://spdx.dev/) | 3.0 JSON-LD |
| VEX | [OpenVEX](https://github.com/openvex/spec) | 0.2.0 |
| VEX | [CSAF](https://oasis-open.github.io/csaf-documentation/) | 2.0 |

Format detection is automatic — evidger inspects the JSON content, not the file extension.

---

## Installation

### From source

```bash
git clone https://github.com/your-org/evidger-cli
cd evidger-cli
cargo build --release
./target/release/evidger --help
```

### Prerequisites

- Rust 1.75+
- Cargo

---

## Quick Start

```bash
# Validate a CycloneDX SBOM
evidger check sbom.json

# Validate all JSON files in a directory
evidger check "sboms/*.json"

# Compare two SBOMs between releases
evidger diff sbom-v1.0.json sbom-v2.0.json

# Merge SBOMs from multiple services into one
evidger merge service-a.json service-b.json service-c.json -o merged.json

# Convert a CycloneDX SBOM to SPDX
evidger convert --to spdx sbom-cyclonedx.json -o sbom-spdx.json

# Generate an HTML report correlating an SBOM with VEX data
evidger report sbom.json --vex advisory.json -o report.html
```

---

## Commands

### `check` — Validate SBOM / VEX documents

Validates one or more JSON files against their official JSON Schema. Format is detected automatically.

```
evidger check <FILE>... [-o <OUTPUT>]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `<FILE>...` | One or more file paths or glob patterns to validate |
| `-o, --output <FILE>` | Write output to a file instead of stdout |

**Examples:**

```bash
# Validate a single file
evidger check sbom.json

# Validate multiple files at once
evidger check sbom.json vex.json advisory.json

# Validate all JSON files in a directory
evidger check "sboms/*.json"

# Validate and save the report
evidger check sbom.json -o validation-report.txt
```

**Output:**

```
[OK] sbom.json
[OK] vex_advisory.json
[FAIL] sbom_draft.json
  - /specVersion: "specVersion" is required
  - /metadata/component: Additional properties are not allowed ('extra_field' was unexpected)
```

**Exit codes:** `0` if all files pass, `1` if any file fails.

---

### `diff` — Compare two documents

Compares two SBOM or two VEX documents and reports what changed between them. Both files must be the same document category (SBOM vs VEX), but may use different formats (e.g., CycloneDX vs SPDX).

```
evidger diff <FILE_A> <FILE_B> [-o <OUTPUT>]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `<FILE_A>` | The baseline document (before) |
| `<FILE_B>` | The updated document (after) |
| `-o, --output <FILE>` | Write output to a file instead of stdout |

**For SBOM documents**, reports:
- Components added in FILE_B
- Components removed from FILE_A
- Components whose version changed

**For VEX documents**, reports:
- Vulnerability statements added in FILE_B
- Vulnerability statements removed from FILE_A
- Status changes (e.g., `under_investigation` → `fixed`)
- Justification, impact, and action statement changes

**Examples:**

```bash
# Compare SBOMs between two releases
evidger diff sbom-1.0.0.json sbom-1.1.0.json

# Compare VEX documents before and after remediation
evidger diff vex-before.json vex-after.json

# Save diff to file
evidger diff sbom-old.json sbom-new.json -o changelog.txt
```

**Output (SBOM):**

```
SBOM Diff: sbom-1.0.0.json → sbom-1.1.0.json

  [+] openssl@3.2.1          (added)
  [-] log4j-core@2.14.0      (removed)
  [~] commons-lang3           2.12.0 → 3.12.0  (version changed)
```

**Output (VEX):**

```
VEX Diff: vex-before.json → vex-after.json

  [+] CVE-2024-9999           (added)
  [~] CVE-2023-44487          status: under_investigation → fixed
                               action: "Apply patch from vendor advisory"
```

---

### `merge` — Combine multiple documents

Merges two or more SBOM or VEX documents into a single output document. Supports mixing formats (e.g., merging a CycloneDX and an SPDX SBOM). Deduplicates entries by component name (SBOM) or vulnerability ID (VEX). When the same entry appears in multiple files, the last file's version wins.

```
evidger merge <FILE>... [-o <OUTPUT>]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `<FILE>...` | Two or more file paths or glob patterns |
| `-o, --output <FILE>` | Write merged output to a file (default: stdout) |

**Output formats:**
- Merged SBOMs are written as **CycloneDX 1.6**
- Merged VEX documents are written as **OpenVEX 0.2.0**

**Examples:**

```bash
# Merge two SBOMs from different services
evidger merge frontend.json backend.json -o full-sbom.json

# Merge all SBOMs in a directory
evidger merge "sboms/*.json" -o merged.json

# Merge VEX documents from multiple vendors
evidger merge vendor-a.vex.json vendor-b.vex.json -o combined.vex.json

# Merge mixed formats (CycloneDX + SPDX)
evidger merge sbom-cyclonedx.json sbom-spdx.json -o merged.json
```

**Conflict resolution:** When the same component or vulnerability appears in multiple input files, the entry from the **last file** in the argument list takes precedence. Order your inputs accordingly if conflict resolution matters.

---

### `convert` — Change format

Converts an SBOM or VEX document from one format to another. The source format is detected automatically.

```
evidger convert --to <FORMAT> <FILE> [-o <OUTPUT>]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `<FILE>` | Input file to convert |
| `--to <FORMAT>` | Target format: `cyclonedx`, `spdx`, `openvex`, `csaf` |
| `-o, --output <FILE>` | Write converted output to a file (default: stdout) |

**Supported conversions:**

| From | To |
|------|----|
| CycloneDX | SPDX |
| SPDX | CycloneDX |
| OpenVEX | CSAF |
| CSAF | OpenVEX |

> Conversions between SBOM and VEX categories (e.g., CycloneDX → OpenVEX) are not supported and will return an error.

**Examples:**

```bash
# Convert a CycloneDX SBOM to SPDX
evidger convert --to spdx sbom.json -o sbom-spdx.json

# Convert an SPDX SBOM to CycloneDX
evidger convert --to cyclonedx sbom-spdx.json -o sbom-cdx.json

# Convert an OpenVEX document to CSAF
evidger convert --to csaf advisory.json -o advisory-csaf.json

# Convert to stdout and pipe to another tool
evidger convert --to spdx sbom.json | jq '.name'
```

---

### `report` — Generate HTML reports

Generates a standalone HTML report from a single SBOM or VEX document. Optionally, an SBOM and VEX document can be correlated together to produce a combined risk report.

```
evidger report <FILE> [--vex <VEX_FILE>] [--minify] [-o <OUTPUT>]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `<FILE>` | SBOM or VEX file to report on |
| `--vex <VEX_FILE>` | VEX file to correlate with the SBOM |
| `--minify` | Minify the HTML output |
| `-o, --output <FILE>` | Output file path (default: `<input>.html`) |

**SBOM report includes:**
- Document metadata (format, version, serial number)
- Full component list with name, version, and PURL

**VEX report includes:**
- Document metadata (author, timestamp, version)
- Vulnerability list with ID, description, severity, and status
- Severity distribution summary

**Correlated SBOM + VEX report includes everything above, plus:**
- Per-component risk scores based on associated vulnerabilities
- Vulnerability-to-component mapping table
- Affected / under investigation / fixed / not affected breakdown
- Noise reduction percentage (how many vulnerabilities are already triaged)

**Risk scoring:**
- `Affected` × 4
- `Under Investigation` × 2
- `Fixed` × 1
- `Not Affected` × 0

**Examples:**

```bash
# Generate an SBOM report
evidger report sbom.json

# Generate a VEX report
evidger report advisory.json -o vex-report.html

# Generate a correlated risk report
evidger report sbom.json --vex advisory.json -o risk-report.html

# Generate a minified report for embedding
evidger report sbom.json --minify -o sbom-compact.html
```

The generated HTML is fully standalone — no external fonts, scripts, or stylesheets are fetched at render time.

---

## Use Cases

### Validate SBOMs in CI

Add a validation step to your pipeline to catch malformed or non-compliant SBOMs before they are ingested:

```yaml
# GitHub Actions example
- name: Validate SBOM
  run: evidger check sbom.json
```

evidger exits with code `1` on any validation failure, blocking the pipeline automatically.

---

### Track component changes between releases

Use `diff` during release processes to produce a human-readable changelog of what components were added, removed, or updated:

```bash
evidger diff sbom-v1.2.0.json sbom-v1.3.0.json -o component-changelog.txt
```

---

### Consolidate SBOMs across a monorepo

Services in a monorepo each produce their own SBOM. Merge them into one unified document for compliance reporting:

```bash
evidger merge "services/*/sbom.json" -o consolidated-sbom.json
```

---

### Normalize formats across vendor SBOMs

Your vendors deliver SBOMs in different formats. Convert everything to a single format for your ingestion pipeline:

```bash
for f in vendor-sboms/*.json; do
  evidger convert --to cyclonedx "$f" -o "normalized/$(basename $f)"
done
```

---

### Correlate vulnerabilities to your components

You receive a VEX advisory from a vendor. Correlate it against your application's SBOM to identify which components are affected:

```bash
evidger report sbom.json --vex vendor-advisory.json -o risk-report.html
```

Open `risk-report.html` to see which components carry risk, the severity breakdown, and the percentage of vulnerabilities already triaged.

---

### Track VEX remediation progress

Monitor how a vendor's advisory evolves over time by diffing VEX snapshots:

```bash
evidger diff vex-2024-01-10.json vex-2024-02-15.json
```

This shows which vulnerabilities moved from `under_investigation` to `fixed` or `not_affected`.

---

### Merge VEX data from multiple vendors

When a component is shared and multiple vendors have published VEX statements, merge them:

```bash
evidger merge vendor-a.vex.json vendor-b.vex.json -o combined.vex.json
```

---

## Output & Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success — operation completed without errors |
| `1` | Failure — validation failed, file not found, parse error, etc. |

All human-readable messages go to **stdout**. Error details are printed to **stderr**.

The `-o, --output <FILE>` flag is available on all commands and redirects structured output (JSON, HTML) to a file instead of stdout, keeping stdout clean for piping.

---

## Error Reference

| Code | Name | Description |
|------|------|-------------|
| E0001 | `InvalidJson` | File is not valid JSON or has an unexpected structure |
| E0002 | `UnsupportedFormat` | File format could not be identified (not CycloneDX, SPDX, OpenVEX, or CSAF) |
| E0003 | `SchemaValidation` | File failed JSON Schema validation (lists all violations) |
| E0004 | `FileNotFound` | One or more input files do not exist |
| E0005 | `MergeConflict` | Reserved — conflicts are currently resolved automatically (last-wins) |
| E0006 | `CliArgument` | Invalid or missing command-line arguments |
| E0007 | `Io` | Unexpected I/O error (permissions, disk full, etc.) |
| E0008 | `NoFilesMatched` | A glob pattern matched no files |
| E0009 | `InvalidGlobPattern` | A glob pattern contains invalid syntax |

---

## Architecture

evidger is structured in four layers with strict separation of concerns:

```
CLI Layer       src/cli/           Argument parsing, user feedback, exit codes
Engine Layer    src/engine/        Business logic: check, diff, merge, convert, report
Format Layer    src/format/        Parse external formats into domain models
Model Layer     src/models/        Pure data structures (SbomDocument, VexDocument, ...)
```

Supporting modules:

| Module | Purpose |
|--------|---------|
| `registry.rs` | Format detection and schema validator compilation |
| `errors.rs` | Centralized error type with `thiserror` |
| `json.rs` | JSON file I/O utilities |
| `glob.rs` | Glob pattern expansion with deduplication |
| `schemas/` | Embedded JSON Schema files (compile-time, no network) |

**Key design decisions:**

- JSON schemas are embedded at compile time using `include_str!` — the binary is fully self-contained and works offline
- Format detection reads JSON content, not file extensions — more robust against misnamed files
- External schema `$ref` URIs are intercepted and resolved with bundled stubs — no outbound HTTP
- Merge conflicts use a last-file-wins strategy — simple and predictable
- HTML reports are fully standalone — no CDN or external assets

---

## Contributing

Contributions are welcome. Please read `ARCHITECTURE.md` before making changes to understand the layering rules and design constraints.

```bash
# Run tests
cargo test

# Run a specific test file
cargo test --test check

# Build in release mode
cargo build --release
```

All features must be accompanied by tests. Prefer integration tests (in `tests/`) over unit tests where possible, and use realistic SBOM/VEX fixtures.
