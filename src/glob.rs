use crate::errors::{EvidgerError, Result};
use std::path::PathBuf;

/// Expand a list of arguments (plain paths **or** glob patterns) into a sorted,
/// deduplicated list of concrete paths.
///
/// Rules:
/// - If the argument contains `*`, `?`, or `[` it is treated as a glob.
///   - If the pattern is syntactically invalid → `E0009`
///   - If the pattern matches no files        → `E0008`
/// - Otherwise the path is passed through as-is; existence is not checked here
///   (the caller's file-loader will produce `E0004` if it is missing).
pub fn expand(patterns: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut result: Vec<PathBuf> = Vec::new();

    for pattern in patterns {
        let s = pattern.to_string_lossy();

        if !is_glob(&s) {
            result.push(pattern.clone());
            continue;
        }

        let entries = glob::glob(&s).map_err(|e| EvidgerError::InvalidGlobPattern {
            pattern: s.to_string(),
            reason: e.to_string(),
        })?;

        let mut matched = 0usize;
        for entry in entries {
            let path = entry.map_err(|e| EvidgerError::Io(e.into_error()))?;
            if !result.contains(&path) {
                result.push(path);
            }
            matched += 1;
        }

        if matched == 0 {
            return Err(EvidgerError::NoFilesMatched(s.to_string()));
        }
    }

    result.sort();
    Ok(result)
}

fn is_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn in_tempdir(f: impl FnOnce(&std::path::Path)) {
        let dir = std::env::temp_dir().join(format!(
            "evidger_glob_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        f(&dir);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plain_path_is_passed_through() {
        let paths = vec![PathBuf::from("some/file.json")];
        let expanded = expand(&paths).unwrap();
        assert_eq!(expanded, paths);
    }

    #[test]
    fn glob_expands_json_files() {
        in_tempdir(|dir| {
            fs::write(dir.join("a.json"), "{}").unwrap();
            fs::write(dir.join("b.json"), "{}").unwrap();
            fs::write(dir.join("c.txt"), "").unwrap();

            let pattern = dir.join("*.json");
            let expanded = expand(&[pattern]).unwrap();

            assert_eq!(expanded.len(), 2);
            assert!(expanded.iter().all(|p| p.extension().unwrap() == "json"));
        });
    }

    #[test]
    fn glob_no_match_returns_error() {
        in_tempdir(|dir| {
            let pattern = dir.join("*.json");
            let err = expand(&[pattern]).unwrap_err();
            assert!(matches!(err, EvidgerError::NoFilesMatched(_)));
        });
    }

    #[test]
    fn glob_deduplicates_results() {
        in_tempdir(|dir| {
            fs::write(dir.join("a.json"), "{}").unwrap();

            let pattern = dir.join("*.json");
            // Pass the same pattern twice
            let expanded = expand(&[pattern.clone(), pattern]).unwrap();
            assert_eq!(expanded.len(), 1);
        });
    }
}
