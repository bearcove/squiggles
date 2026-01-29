//! Convert test failures to LSP diagnostics.

use std::collections::HashMap;
use std::path::Path;

use tower_lsp::lsp_types::*;

use crate::lsp::find_test_functions;
use crate::nextest::{SourceLocation, TestFailure};

/// A collection of diagnostics grouped by file URI.
pub type DiagnosticsByFile = HashMap<Url, Vec<Diagnostic>>;

/// Index of test function locations in the workspace.
///
/// Maps short test name (e.g., "test_something") to (URI, line number).
pub struct TestFunctionIndex {
    /// Map from test function name to (file URI, 0-indexed line number)
    by_name: HashMap<String, (Url, u32)>,
}

impl TestFunctionIndex {
    /// Build an index by scanning all Rust files in the workspace.
    pub fn build(workspace_root: &Path) -> Self {
        let mut by_name = HashMap::new();

        // Walk the workspace looking for .rs files
        if let Ok(entries) = walkdir(workspace_root) {
            for entry in entries {
                if entry.extension().is_some_and(|e| e == "rs") {
                    if let Ok(content) = std::fs::read_to_string(&entry) {
                        if let Ok(uri) = Url::from_file_path(&entry) {
                            let tests = find_test_functions(&content);
                            for (line, name) in tests {
                                by_name.insert(name, (uri.clone(), line));
                            }
                        }
                    }
                }
            }
        }

        Self { by_name }
    }

    /// Look up a test function by its short name.
    pub fn get(&self, name: &str) -> Option<&(Url, u32)> {
        self.by_name.get(name)
    }
}

/// Walk a directory recursively, yielding file paths.
fn walkdir(root: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    walkdir_inner(root, &mut files)?;
    Ok(files)
}

fn walkdir_inner(dir: &Path, files: &mut Vec<std::path::PathBuf>) -> std::io::Result<()> {
    if dir.is_dir() {
        // Skip target directory and hidden directories
        if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
            if name == "target" || name.starts_with('.') {
                return Ok(());
            }
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                walkdir_inner(&path, files)?;
            } else {
                files.push(path);
            }
        }
    }
    Ok(())
}

/// Convert test failures to LSP diagnostics, grouped by file.
///
/// Diagnostics are placed at the test function definition, not the panic location.
/// The panic location is included as related information.
pub fn failures_to_diagnostics(
    failures: &[TestFailure],
    workspace_root: &Path,
    test_index: &TestFunctionIndex,
) -> DiagnosticsByFile {
    let mut diagnostics: DiagnosticsByFile = HashMap::new();

    for failure in failures {
        let short_name = extract_test_name(&failure.name);

        // Try to find the test function location
        let (uri, range) = if let Some((uri, line)) = test_index.get(&short_name) {
            // Found the test function - use its location
            let range = Range {
                start: Position {
                    line: *line,
                    character: 0,
                },
                end: Position {
                    line: *line,
                    character: 0,
                },
            };
            (uri.clone(), range)
        } else if let Some(ref panic_loc) = failure.panic_location {
            // Fall back to panic location if we can't find the test
            let file_path = resolve_path(&panic_loc.file, workspace_root);
            let uri = match Url::from_file_path(&file_path) {
                Ok(uri) => uri,
                Err(_) => continue,
            };
            (uri, location_to_range(panic_loc))
        } else {
            // No location at all, skip this failure
            continue;
        };

        // Build related information: panic location + backtrace frames
        let mut related_info: Vec<DiagnosticRelatedInformation> = Vec::new();

        // Add panic location as first related info (if different from test location)
        if let Some(ref panic_loc) = failure.panic_location {
            let panic_path = resolve_path(&panic_loc.file, workspace_root);
            if let Ok(panic_uri) = Url::from_file_path(&panic_path) {
                related_info.push(DiagnosticRelatedInformation {
                    location: Location {
                        uri: panic_uri,
                        range: location_to_range(panic_loc),
                    },
                    message: format!("panicked here: {}", failure.message),
                });
            }
        }

        // Add backtrace frames
        for frame in &failure.user_frames {
            let frame_path = resolve_path(&frame.location.file, workspace_root);
            if let Ok(frame_uri) = Url::from_file_path(&frame_path) {
                related_info.push(DiagnosticRelatedInformation {
                    location: Location {
                        uri: frame_uri,
                        range: location_to_range(&frame.location),
                    },
                    message: frame.function.clone(),
                });
            }
        }

        // Build a useful message - if empty, say "test failed"
        let message = if failure.message.is_empty() {
            "test failed".to_string()
        } else {
            failure.message.clone()
        };

        let diagnostic = Diagnostic {
            range,
            severity: Some(DiagnosticSeverity::ERROR),
            code: None, // No code needed - the diagnostic is on the test function itself
            code_description: None,
            source: Some("squiggles".to_string()),
            message,
            related_information: if related_info.is_empty() {
                None
            } else {
                Some(related_info)
            },
            tags: None,
            data: None,
        };

        diagnostics.entry(uri).or_default().push(diagnostic);
    }

    diagnostics
}

/// Convert a SourceLocation to an LSP Range.
///
/// LSP uses 0-indexed lines and columns, while our locations are 1-indexed.
fn location_to_range(loc: &SourceLocation) -> Range {
    let line = loc.line.saturating_sub(1);
    let col = loc.column.saturating_sub(1);

    Range {
        start: Position {
            line,
            character: col,
        },
        end: Position {
            line,
            character: col,
        },
    }
}

/// Resolve a file path relative to the workspace root.
fn resolve_path(file: &str, workspace_root: &Path) -> std::path::PathBuf {
    let file_path = Path::new(file);

    if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        let clean = file.strip_prefix("./").unwrap_or(file);
        workspace_root.join(clean)
    }
}

/// Extract the short test name from the full nextest test name.
///
/// Full name: `sample-crate::sample_crate$tests::test_panic`
/// Short name: `test_panic`
pub fn extract_test_name(full_name: &str) -> String {
    full_name
        .rsplit("::")
        .next()
        .unwrap_or(full_name)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nextest::BacktraceFrame;

    #[test]
    fn test_location_to_range() {
        let loc = SourceLocation {
            file: "src/lib.rs".to_string(),
            line: 10,
            column: 5,
        };

        let range = location_to_range(&loc);
        assert_eq!(range.start.line, 9); // 0-indexed
        assert_eq!(range.start.character, 4); // 0-indexed
    }

    #[test]
    fn test_resolve_path() {
        let workspace = Path::new("/home/user/project");

        assert_eq!(
            resolve_path("./src/lib.rs", workspace),
            Path::new("/home/user/project/src/lib.rs")
        );
        assert_eq!(
            resolve_path("src/lib.rs", workspace),
            Path::new("/home/user/project/src/lib.rs")
        );
        assert_eq!(
            resolve_path("/absolute/path.rs", workspace),
            Path::new("/absolute/path.rs")
        );
    }

    #[test]
    fn test_extract_test_name() {
        assert_eq!(
            extract_test_name("sample-crate::sample_crate$tests::test_panic"),
            "test_panic"
        );
        assert_eq!(extract_test_name("just_a_name"), "just_a_name");
    }

    #[test]
    fn test_failures_to_diagnostics_with_index() {
        // Create a mock index with the test location
        let mut by_name = HashMap::new();
        let test_uri = Url::from_file_path("/project/src/lib.rs").unwrap();
        by_name.insert("test_something".to_string(), (test_uri.clone(), 10)); // Line 10 (0-indexed)

        let test_index = TestFunctionIndex { by_name };

        let failures = vec![TestFailure {
            name: "my_crate::tests::test_something".to_string(),
            message: "assertion failed".to_string(),
            panic_location: Some(SourceLocation {
                file: "src/lib.rs".to_string(),
                line: 42,
                column: 9,
            }),
            user_frames: vec![BacktraceFrame {
                index: 0,
                function: "my_crate::helper".to_string(),
                location: SourceLocation {
                    file: "./src/helper.rs".to_string(),
                    line: 10,
                    column: 5,
                },
            }],
            full_output: "...".to_string(),
        }];

        let workspace = Path::new("/project");
        let diags = failures_to_diagnostics(&failures, workspace, &test_index);

        assert_eq!(diags.len(), 1);

        let file_diags = diags.get(&test_uri).unwrap();
        assert_eq!(file_diags.len(), 1);

        let diag = &file_diags[0];
        assert_eq!(diag.message, "assertion failed");
        assert_eq!(diag.severity, Some(DiagnosticSeverity::ERROR));
        // Should be at line 10 (the test function), not line 41 (the panic)
        assert_eq!(diag.range.start.line, 10);
        // No code - diagnostic is on the test function itself
        assert_eq!(diag.code, None);

        // Check related info includes panic location
        let related = diag.related_information.as_ref().unwrap();
        assert!(related.len() >= 1);
        assert!(related[0].message.contains("panicked here"));
    }
}
