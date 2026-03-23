use crate::errors::{EvidgerError, Result};
use serde_json::Value;
use std::path::Path;

/// Read a file from disk and return its contents as a UTF-8 string.
///
/// Returns `EvidgerError::FileNotFound` when the path does not exist,
/// or `EvidgerError::Io` for any other I/O failure.
pub fn load_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            EvidgerError::FileNotFound(path.display().to_string())
        } else {
            EvidgerError::Io(e)
        }
    })
}

/// Parse a JSON string into a `serde_json::Value`.
///
/// Returns `EvidgerError::InvalidJson` on syntax or structural errors.
pub fn parse_json(content: &str) -> Result<Value> {
    serde_json::from_str(content).map_err(EvidgerError::InvalidJson)
}

/// Convenience: load a file and parse it as JSON in one step.
pub fn load_json(path: &Path) -> Result<Value> {
    let content = load_file(path)?;
    parse_json(&content)
}
