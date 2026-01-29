//! Convert test failures to LSP diagnostics.

use std::collections::HashMap;
use std::path::Path;

use tower_lsp::lsp_types::*;

use crate::nextest::{SourceLocation, TestFailure};

/// A collection of diagnostics grouped by file URI.
pub type DiagnosticsByFile = HashMap<Url, Vec<Diagnostic>>;

/// Convert test failures to LSP diagnostics, grouped by file.
///
/// Each failure produces:
/// - A primary diagnostic at the panic location
/// - Related information for each backtrace frame in user code
pub fn failures_to_diagnostics(
    failures: &[TestFailure],
    workspace_root: &Path,
) -> DiagnosticsByFile {
    let mut diagnostics: DiagnosticsByFile = HashMap::new();

    for failure in failures {
        if let Some(ref panic_loc) = failure.panic_location {
            let file_path = resolve_path(&panic_loc.file, workspace_root);
            let uri = match Url::from_file_path(&file_path) {
                Ok(uri) => uri,
                Err(_) => continue, // Skip if we can't create a URL
            };

            // Build related information from backtrace frames
            let related_info: Vec<DiagnosticRelatedInformation> = failure
                .user_frames
                .iter()
                .filter_map(|frame| {
                    let frame_path = resolve_path(&frame.location.file, workspace_root);
                    let frame_uri = Url::from_file_path(&frame_path).ok()?;

                    Some(DiagnosticRelatedInformation {
                        location: Location {
                            uri: frame_uri,
                            range: location_to_range(&frame.location),
                        },
                        message: frame.function.clone(),
                    })
                })
                .collect();

            let diagnostic = Diagnostic {
                range: location_to_range(panic_loc),
                severity: Some(DiagnosticSeverity::ERROR),
                code: Some(NumberOrString::String(extract_test_name(&failure.name))),
                code_description: None,
                source: Some("squiggles".to_string()),
                message: failure.message.clone(),
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
        // End at the same position - editors will typically highlight the whole line
        // or we could try to find the end of the expression
        end: Position {
            line,
            character: col,
        },
    }
}

/// Resolve a file path relative to the workspace root.
///
/// Handles paths like:
/// - `./src/lib.rs` -> `{workspace}/src/lib.rs`
/// - `src/lib.rs` -> `{workspace}/src/lib.rs`
/// - `/absolute/path` -> `/absolute/path`
fn resolve_path(file: &str, workspace_root: &Path) -> std::path::PathBuf {
    let file_path = Path::new(file);

    if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        // Strip leading "./" if present
        let clean = file.strip_prefix("./").unwrap_or(file);
        workspace_root.join(clean)
    }
}

/// Extract the short test name from the full nextest test name.
///
/// Full name: `sample-crate::sample_crate$tests::test_panic`
/// Short name: `test_panic`
fn extract_test_name(full_name: &str) -> String {
    // Take everything after the last `::`
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
    fn test_failures_to_diagnostics() {
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
        let diags = failures_to_diagnostics(&failures, workspace);

        assert_eq!(diags.len(), 1);

        let uri = Url::from_file_path("/project/src/lib.rs").unwrap();
        let file_diags = diags.get(&uri).unwrap();
        assert_eq!(file_diags.len(), 1);

        let diag = &file_diags[0];
        assert_eq!(diag.message, "assertion failed");
        assert_eq!(diag.severity, Some(DiagnosticSeverity::ERROR));
        assert_eq!(diag.range.start.line, 41); // 0-indexed
        assert_eq!(
            diag.code,
            Some(NumberOrString::String("test_something".to_string()))
        );

        // Check related info
        let related = diag.related_information.as_ref().unwrap();
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].message, "my_crate::helper");
    }
}
