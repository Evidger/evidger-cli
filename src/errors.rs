use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvidgerError {
    /// E0001 — JSON syntax or structure is invalid
    #[error("[E0001] Invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    /// E0002 — File format cannot be identified
    #[error("[E0002] Unsupported format: {0}")]
    UnsupportedFormat(String),

    /// E0003 — JSON Schema validation failed; carries all failure messages
    #[error("[E0003] Schema validation failed:\n{0}")]
    SchemaValidation(String),

    /// E0004 — A required file does not exist on disk
    #[error("[E0004] File not found: {0}")]
    FileNotFound(String),

    /// E0005 — Merge produced an unresolvable conflict
    #[error("[E0005] Merge conflict: {0}")]
    MergeConflict(String),

    /// E0006 — Bad command-line arguments (wraps clap output)
    #[error("[E0006] Invalid argument: {0}")]
    CliArgument(String),

    /// E0007 — Unexpected I/O error (permissions, read failure, …)
    #[error("[E0007] I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// E0008 — Glob pattern matched no files
    #[error("[E0008] No files matched pattern: {0}")]
    NoFilesMatched(String),

    /// E0009 — Glob pattern is syntactically invalid
    #[error("[E0009] Invalid glob pattern '{pattern}': {reason}")]
    InvalidGlobPattern { pattern: String, reason: String },
}

pub type Result<T> = std::result::Result<T, EvidgerError>;
