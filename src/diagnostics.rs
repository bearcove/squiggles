//! Convert test failures to LSP diagnostics.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use tower_lsp::lsp_types::*;

use crate::lsp::{Span, find_test_functions_detailed};
use crate::nextest::{SourceLocation, TestFailure};

/// Write debug info to /tmp/squiggles-debug.log
pub fn debug_log(msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/squiggles-debug.log")
    {
        let _ = writeln!(f, "{}", msg);
    }
}

/// A collection of diagnostics grouped by file URI.
pub type DiagnosticsByFile = HashMap<Url, Vec<Diagnostic>>;

/// Stored location of a test function.
#[derive(Debug, Clone)]
pub struct TestLocation {
    pub uri: Url,
    /// Span of the #[test] attribute (where we put the error diagnostic)
    pub attr_span: Span,
    /// Span of the function name
    pub name_span: Span,
}

/// Index of test function locations in the workspace.
///
/// Maps short test name (e.g., "test_something") to its location.
pub struct TestFunctionIndex {
    by_name: HashMap<String, TestLocation>,
}

impl TestFunctionIndex {
    /// Build an index by scanning all Rust files in the workspace.
    pub fn build(workspace_root: &Path) -> Self {
        Self::build_with_excludes(workspace_root, &[])
    }

    /// Build an index, excluding directories matching the given patterns.
    pub fn build_with_excludes(workspace_root: &Path, exclude_patterns: &[String]) -> Self {
        let mut by_name = HashMap::new();

        // Canonicalize workspace root to ensure all paths are absolute
        // (Url::from_file_path requires absolute paths)
        let workspace_root = match workspace_root.canonicalize() {
            Ok(p) => p,
            Err(_) => return Self { by_name },
        };

        // Walk the workspace looking for .rs files
        debug_log(&format!(
            "TestFunctionIndex: scanning {} with {} exclude patterns: {:?}",
            workspace_root.display(),
            exclude_patterns.len(),
            exclude_patterns
        ));
        if let Ok(entries) = walkdir(&workspace_root, exclude_patterns) {
            for entry in entries {
                if entry.extension().is_some_and(|e| e == "rs")
                    && let Ok(content) = std::fs::read_to_string(&entry)
                    && let Ok(uri) = Url::from_file_path(&entry)
                {
                    let tests = find_test_functions_detailed(&content);
                    for info in tests {
                        debug_log(&format!(
                            "TestFunctionIndex: found test '{}' at {}:{}",
                            info.name,
                            entry.display(),
                            info.name_span.line
                        ));
                        by_name.insert(
                            info.name.clone(),
                            TestLocation {
                                uri: uri.clone(),
                                attr_span: info.attr_span,
                                name_span: info.name_span,
                            },
                        );
                    }
                }
            }
        }

        Self { by_name }
    }

    /// Look up a test function by its short name.
    pub fn get(&self, name: &str) -> Option<&TestLocation> {
        self.by_name.get(name)
    }
}

/// Walk a directory recursively, yielding file paths.
fn walkdir(root: &Path, exclude_patterns: &[String]) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    walkdir_inner(root, root, &mut files, exclude_patterns)?;
    Ok(files)
}

fn walkdir_inner(
    dir: &Path,
    root: &Path,
    files: &mut Vec<std::path::PathBuf>,
    exclude_patterns: &[String],
) -> std::io::Result<()> {
    if dir.is_dir() {
        // Skip target directory and hidden directories
        if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
            if name == "target" || name.starts_with('.') {
                return Ok(());
            }
        }

        // Check exclude patterns against the relative path from root
        if let Ok(rel_path) = dir.strip_prefix(root) {
            let rel_str = rel_path.to_string_lossy();
            if exclude_patterns.iter().any(|p| {
                // Match if the relative path equals the pattern or starts with pattern/
                rel_str == *p || rel_str.starts_with(&format!("{p}/"))
            }) {
                debug_log(&format!(
                    "scan_exclude: skipping {rel_str} (matched exclude pattern)"
                ));
                return Ok(());
            }
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                walkdir_inner(&path, root, files, exclude_patterns)?;
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
/// Panic locations and backtrace frames are deduplicated with counts.
pub fn failures_to_diagnostics(
    failures: &[TestFailure],
    workspace_root: &Path,
    test_index: &TestFunctionIndex,
) -> DiagnosticsByFile {
    let mut diagnostics: DiagnosticsByFile = HashMap::new();

    // Track panic locations: (uri, line) -> list of test names
    let mut panic_locations: HashMap<(String, u32), Vec<String>> = HashMap::new();

    for failure in failures {
        let short_name = extract_test_name(&failure.name);

        // Try to find the test function location
        let (uri, range) = if let Some(loc) = test_index.get(&short_name) {
            // Found the test function - highlight the function name
            (loc.uri.clone(), loc.name_span.to_range())
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

        // Build a useful message - only first line for the diagnostic
        let full_message = if !failure.message.is_empty() {
            failure.message.clone()
        } else {
            // Try to extract something useful from full_output
            extract_failure_summary(&failure.full_output)
        };
        let message = full_message
            .lines()
            .next()
            .unwrap_or("Test failed")
            .to_string();

        // Primary diagnostic on the test function (ERROR severity)
        let primary_diagnostic = Diagnostic {
            range,
            severity: Some(DiagnosticSeverity::ERROR),
            code: None,
            code_description: None,
            source: Some("squiggles".to_string()),
            message: message.clone(),
            related_information: None,
            tags: None,
            data: None,
        };

        diagnostics
            .entry(uri.clone())
            .or_default()
            .push(primary_diagnostic);

        // Collect panic location for deduplication
        if let Some(ref panic_loc) = failure.panic_location {
            let panic_path = resolve_path(&panic_loc.file, workspace_root);
            if let Ok(panic_uri) = Url::from_file_path(&panic_path) {
                // Only track if it's a different location than the test function
                let panic_range = line_content_range(&panic_path, panic_loc.line)
                    .unwrap_or_else(|| location_to_range(panic_loc));
                if panic_uri != uri || panic_range != range {
                    let key = (panic_uri.to_string(), panic_loc.line);
                    panic_locations
                        .entry(key)
                        .or_default()
                        .push(short_name.clone());
                }
            }
        }
    }

    // Emit deduplicated WARNING diagnostics for panic locations
    for ((uri_str, line), test_names) in panic_locations {
        let uri = match Url::parse(&uri_str) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let file_path = match uri.to_file_path() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let panic_range = line_content_range(&file_path, line).unwrap_or_else(|| Range {
            start: Position {
                line: line.saturating_sub(1),
                character: 0,
            },
            end: Position {
                line: line.saturating_sub(1),
                character: 0,
            },
        });

        let message = if test_names.len() == 1 {
            format!("panicked here (from `{}`)", test_names[0])
        } else {
            format!("{} tests panicked here", test_names.len())
        };

        let panic_diagnostic = Diagnostic {
            range: panic_range,
            severity: Some(DiagnosticSeverity::WARNING),
            code: None,
            code_description: None,
            source: Some("squiggles".to_string()),
            message,
            related_information: None,
            tags: None,
            data: None,
        };
        diagnostics.entry(uri).or_default().push(panic_diagnostic);
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

/// Compute a range that covers the non-whitespace content of a line.
///
/// Reads the file to find the actual line content, then returns a range
/// from the first non-whitespace character to the end of the line.
fn line_content_range(file_path: &Path, line_number: u32) -> Option<Range> {
    let content = std::fs::read_to_string(file_path).ok()?;
    let line_idx = line_number.saturating_sub(1) as usize;
    let line = content.lines().nth(line_idx)?;

    // Find first non-whitespace character
    let start_col = line.chars().take_while(|c| c.is_whitespace()).count() as u32;
    let end_col = line.len() as u32;

    // If line is all whitespace, just return a point
    if start_col >= end_col {
        return Some(Range {
            start: Position {
                line: line_idx as u32,
                character: 0,
            },
            end: Position {
                line: line_idx as u32,
                character: 0,
            },
        });
    }

    Some(Range {
        start: Position {
            line: line_idx as u32,
            character: start_col,
        },
        end: Position {
            line: line_idx as u32,
            character: end_col,
        },
    })
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

/// Extract a useful summary from test failure output when panic message is empty.
///
/// Looks for common patterns in test output like assertion failures,
/// "left/right" comparisons, etc.
fn extract_failure_summary(output: &str) -> String {
    // Look for "assertion `left == right` failed" pattern
    if let Some(idx) = output.find("assertion `")
        && let Some(end) = output[idx..].find("` failed")
    {
        let assertion = &output[idx..idx + end + "` failed".len()];
        return assertion.to_string();
    }

    // Look for "assertion failed:" pattern
    if let Some(idx) = output.find("assertion failed:") {
        let rest = &output[idx + "assertion failed:".len()..];
        if let Some(line) = rest.lines().next() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                return format!("assertion failed: {trimmed}");
            }
        }
        return "assertion failed".to_string();
    }

    // Look for "panicked at" without a message (explicit panic)
    if output.contains("panicked at") {
        // Check if there's a "Message:" line (color-backtrace format)
        if let Some(idx) = output.find("Message:") {
            let rest = &output[idx + "Message:".len()..];
            if let Some(line) = rest.lines().next() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && trimmed != "explicit panic" {
                    return trimmed.to_string();
                }
            }
        }
        return "panic".to_string();
    }

    // Look for left/right comparison in assertion output
    if output.contains("left:") && output.contains("right:") {
        return "assertion failed (values differ)".to_string();
    }

    "test failed".to_string()
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
        use crate::lsp::Span;

        // Create a mock index with the test location
        let mut by_name = HashMap::new();
        let test_uri = Url::from_file_path("/project/src/lib.rs").unwrap();
        by_name.insert(
            "test_something".to_string(),
            TestLocation {
                uri: test_uri.clone(),
                attr_span: Span {
                    line: 9,
                    col: 4,
                    len: 7, // "#[test]".len()
                },
                name_span: Span {
                    line: 10,
                    col: 4,
                    len: 14, // "test_something".len()
                },
            },
        );

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

        // Should have diagnostics for the test file (at test location)
        // Note: panic location diagnostic would go to a different file (src/lib.rs at line 42)
        // but since that file doesn't exist, we can't compute its content range
        let file_diags = diags.get(&test_uri).unwrap();
        assert!(!file_diags.is_empty());

        // Find the ERROR diagnostic (test failure)
        let error_diag = file_diags
            .iter()
            .find(|d| d.severity == Some(DiagnosticSeverity::ERROR))
            .expect("should have an ERROR diagnostic");

        assert_eq!(error_diag.message, "assertion failed");
        // Should be at line 10, column 4, spanning the function name
        assert_eq!(error_diag.range.start.line, 10);
        assert_eq!(error_diag.range.start.character, 4);
        assert_eq!(error_diag.range.end.character, 18); // 4 + 14
        assert_eq!(error_diag.code, None);
    }

    #[test]
    fn test_extract_failure_summary() {
        // Assertion with backticks
        assert_eq!(
            extract_failure_summary("assertion `left == right` failed\nleft: 1\nright: 2"),
            "assertion `left == right` failed"
        );

        // Assertion failed with message
        assert_eq!(
            extract_failure_summary("assertion failed: x > 0"),
            "assertion failed: x > 0"
        );

        // Panic with Message
        assert_eq!(
            extract_failure_summary("panicked at foo.rs:10\nMessage: something went wrong"),
            "something went wrong"
        );

        // Just left/right
        assert_eq!(
            extract_failure_summary("left: 1\nright: 2"),
            "assertion failed (values differ)"
        );

        // Nothing useful
        assert_eq!(extract_failure_summary("some random output"), "test failed");
    }
}
