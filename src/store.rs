//! Single source of truth for test results.
//!
//! All LSP features (diagnostics, inlay hints, hover) derive from this store.
//! This ensures atomic updates and prevents state synchronization bugs.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use tower_lsp::Client;
use tower_lsp::lsp_types::*;

use crate::diagnostics::{
    TestFunctionIndex, TestLocation, extract_failure_summary, extract_test_name,
};
use crate::metadata::WorkspaceMetadata;
use crate::nextest::{SourceLocation, TestFailure};

/// Single source of truth for all test results.
///
/// All LSP features (diagnostics, inlay hints, hover) derive from this store.
#[derive(Debug, Clone)]
pub struct TestResultStore {
    /// All test results indexed by full test name (e.g., "crate::module::test_name").
    results: HashMap<String, TestResultEntry>,

    /// Test function index for resolving test names to source locations.
    test_index: TestFunctionIndex,

    /// Workspace root for path resolution.
    workspace_root: PathBuf,

    /// Workspace metadata for crate path resolution (reserved for future use).
    #[allow(dead_code)]
    workspace_metadata: Option<WorkspaceMetadata>,
}

/// A single test result with all associated data.
#[derive(Debug, Clone)]
pub struct TestResultEntry {
    /// The full test name (e.g., "sample-crate::sample_crate$tests::test_foo").
    pub full_name: String,

    /// The short test name (e.g., "test_foo").
    pub short_name: String,

    /// The test outcome.
    pub outcome: TestOutcome,

    /// Source location of the test function (for diagnostics/inlay hints).
    pub test_location: Option<TestLocation>,
}

/// The outcome of a test.
#[derive(Debug, Clone)]
pub enum TestOutcome {
    /// Test passed.
    Passed,
    /// Test failed with details.
    Failed {
        /// The parsed failure data.
        failure: TestFailure,
    },
}

impl TestResultStore {
    /// Create a new store for a test run.
    ///
    /// The test index is built once and reused for all updates in this run.
    pub fn new(
        workspace_root: PathBuf,
        workspace_metadata: Option<WorkspaceMetadata>,
        scan_exclude: &[String],
    ) -> Self {
        let test_index = TestFunctionIndex::build_with_excludes(&workspace_root, scan_exclude);
        Self {
            results: HashMap::new(),
            test_index,
            workspace_root,
            workspace_metadata,
        }
    }

    /// Record a test pass.
    pub fn record_pass(&mut self, full_name: String) {
        let short_name = extract_test_name(&full_name);
        let test_location = self.test_index.get(&short_name).cloned();

        self.results.insert(
            full_name.clone(),
            TestResultEntry {
                full_name,
                short_name,
                outcome: TestOutcome::Passed,
                test_location,
            },
        );
    }

    /// Record a test failure.
    pub fn record_failure(&mut self, failure: TestFailure) {
        let full_name = failure.name.clone();
        let short_name = extract_test_name(&full_name);
        let test_location = self.test_index.get(&short_name).cloned();

        self.results.insert(
            full_name.clone(),
            TestResultEntry {
                full_name,
                short_name,
                outcome: TestOutcome::Failed { failure },
                test_location,
            },
        );
    }

    /// Clear all results.
    pub fn clear(&mut self) {
        self.results.clear();
    }

    /// Get all files that have test results.
    pub fn affected_files(&self) -> HashSet<Url> {
        self.results
            .values()
            .filter_map(|entry| entry.test_location.as_ref())
            .map(|loc| loc.uri.clone())
            .collect()
    }

    /// Get all files that have failures.
    pub fn files_with_failures(&self) -> HashSet<Url> {
        self.results
            .values()
            .filter(|entry| matches!(entry.outcome, TestOutcome::Failed { .. }))
            .filter_map(|entry| entry.test_location.as_ref())
            .map(|loc| loc.uri.clone())
            .collect()
    }

    // === DIAGNOSTICS ===

    /// Compute diagnostics for a specific file.
    ///
    /// Returns ERROR diagnostics at test function locations,
    /// plus WARNING diagnostics at panic locations.
    pub fn diagnostics_for_file(&self, uri: &Url) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        // Track panic locations for deduplication: (line) -> list of test names
        let mut panic_locations: HashMap<u32, Vec<String>> = HashMap::new();

        for entry in self.results.values() {
            let TestOutcome::Failed { ref failure } = entry.outcome else {
                continue;
            };

            // Primary diagnostic at test function
            if let Some(ref loc) = entry.test_location
                && &loc.uri == uri
            {
                let message = if !failure.message.is_empty() {
                    failure
                        .message
                        .lines()
                        .next()
                        .unwrap_or("Test failed")
                        .to_string()
                } else {
                    extract_failure_summary(&failure.full_output)
                };

                diagnostics.push(Diagnostic {
                    range: loc.name_span.to_range(),
                    severity: Some(DiagnosticSeverity::ERROR),
                    code: None,
                    code_description: None,
                    source: Some("squiggles".to_string()),
                    message,
                    related_information: None,
                    tags: None,
                    data: None,
                });
            }

            // Collect panic location for deduplication
            if let Some(ref panic_loc) = failure.panic_location
                && let Some(panic_uri) = self.resolve_panic_uri(panic_loc)
                && &panic_uri == uri
            {
                // Check it's not the same location as the test function
                let is_same_location = entry.test_location.as_ref().is_some_and(|loc| {
                    loc.uri == panic_uri && loc.name_span.line + 1 == panic_loc.line
                });

                if !is_same_location {
                    panic_locations
                        .entry(panic_loc.line)
                        .or_default()
                        .push(entry.short_name.clone());
                }
            }
        }

        // Add deduplicated WARNING diagnostics for panic locations
        for (line, test_names) in panic_locations {
            let message = if test_names.len() == 1 {
                format!("panicked here (from `{}`)", test_names[0])
            } else {
                format!("{} tests panicked here", test_names.len())
            };

            let panic_range = self.line_content_range(uri, line);

            diagnostics.push(Diagnostic {
                range: panic_range,
                severity: Some(DiagnosticSeverity::WARNING),
                code: None,
                code_description: None,
                source: Some("squiggles".to_string()),
                message,
                related_information: None,
                tags: None,
                data: None,
            });
        }

        diagnostics
    }

    // === INLAY HINTS ===

    /// Get test result for inlay hint display.
    ///
    /// Returns the result matching by test name suffix.
    pub fn result_for_test_name(&self, short_name: &str) -> Option<&TestResultEntry> {
        self.results
            .values()
            .find(|entry| entry.short_name == short_name)
    }

    // === HOVER ===

    /// Find a failure at the given position for hover.
    ///
    /// Checks both test function locations and panic locations.
    pub fn failure_at_position(&self, uri: &Url, position: Position) -> Option<&TestFailure> {
        for entry in self.results.values() {
            let TestOutcome::Failed { ref failure } = entry.outcome else {
                continue;
            };

            // Check test function location (name span)
            if let Some(ref loc) = entry.test_location
                && &loc.uri == uri
                && contains_position(&loc.name_span.to_range(), position)
            {
                return Some(failure);
            }

            // Check panic location
            if let Some(ref panic_loc) = failure.panic_location
                && let Some(panic_uri) = self.resolve_panic_uri(panic_loc)
                && &panic_uri == uri
            {
                let panic_range = location_to_range(panic_loc);
                if contains_position(&panic_range, position) {
                    return Some(failure);
                }
            }
        }
        None
    }

    // === HELPERS ===

    /// Resolve a panic location to a URI.
    fn resolve_panic_uri(&self, loc: &SourceLocation) -> Option<Url> {
        let file_path = self.resolve_path(&loc.file);
        Url::from_file_path(&file_path).ok()
    }

    /// Resolve a file path relative to the workspace root.
    fn resolve_path(&self, file: &str) -> PathBuf {
        let file_path = Path::new(file);

        if file_path.is_absolute() {
            file_path.to_path_buf()
        } else {
            let clean = file.strip_prefix("./").unwrap_or(file);
            self.workspace_root.join(clean)
        }
    }

    /// Compute a range that covers the non-whitespace content of a line.
    fn line_content_range(&self, uri: &Url, line_number: u32) -> Range {
        let default_range = Range {
            start: Position {
                line: line_number.saturating_sub(1),
                character: 0,
            },
            end: Position {
                line: line_number.saturating_sub(1),
                character: 0,
            },
        };

        let Ok(file_path) = uri.to_file_path() else {
            return default_range;
        };

        let Ok(content) = std::fs::read_to_string(&file_path) else {
            return default_range;
        };

        let line_idx = line_number.saturating_sub(1) as usize;
        let Some(line) = content.lines().nth(line_idx) else {
            return default_range;
        };

        // Find first non-whitespace character
        let start_col = line.chars().take_while(|c| c.is_whitespace()).count() as u32;
        let end_col = line.len() as u32;

        // If line is all whitespace, just return a point
        if start_col >= end_col {
            return default_range;
        }

        Range {
            start: Position {
                line: line_idx as u32,
                character: start_col,
            },
            end: Position {
                line: line_idx as u32,
                character: end_col,
            },
        }
    }
}

/// Convert a SourceLocation to an LSP Range.
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

/// Check if a range contains a position.
fn contains_position(range: &Range, pos: Position) -> bool {
    if pos.line < range.start.line || pos.line > range.end.line {
        return false;
    }
    if pos.line == range.start.line && pos.character < range.start.character {
        return false;
    }
    if pos.line == range.end.line && pos.character > range.end.character {
        return false;
    }
    true
}

/// Handles atomic publishing of all LSP features from a TestResultStore.
pub struct LspPublisher {
    client: Client,
    /// Track which files currently have diagnostics (for clearing stale ones).
    files_with_diagnostics: HashSet<String>,
}

impl LspPublisher {
    /// Create a new publisher.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            files_with_diagnostics: HashSet::new(),
        }
    }

    /// Atomically publish all LSP features from the store.
    ///
    /// This:
    /// 1. Clears diagnostics from files that no longer have failures
    /// 2. Publishes diagnostics for files with failures
    ///
    /// Inlay hints are pull-based, so they'll automatically get the new data
    /// on the next request.
    pub async fn publish_all(&mut self, store: &TestResultStore) {
        let new_files = store.files_with_failures();
        let new_file_strings: HashSet<String> = new_files.iter().map(|u| u.to_string()).collect();

        // Clear stale diagnostics
        for uri_str in self.files_with_diagnostics.difference(&new_file_strings) {
            if let Ok(uri) = Url::parse(uri_str) {
                self.client.publish_diagnostics(uri, vec![], None).await;
            }
        }

        // Publish new diagnostics
        for uri in &new_files {
            let diagnostics = store.diagnostics_for_file(uri);
            self.client
                .publish_diagnostics(uri.clone(), diagnostics, None)
                .await;
        }

        // Update tracking
        self.files_with_diagnostics = new_file_strings;
    }

    /// Publish diagnostics for a single file (incremental update).
    ///
    /// Used during streaming test results.
    pub async fn publish_file(&mut self, store: &TestResultStore, uri: &Url) {
        let diagnostics = store.diagnostics_for_file(uri);
        let uri_str = uri.to_string();

        if diagnostics.is_empty() {
            self.files_with_diagnostics.remove(&uri_str);
        } else {
            self.files_with_diagnostics.insert(uri_str);
        }

        self.client
            .publish_diagnostics(uri.clone(), diagnostics, None)
            .await;
    }

    /// Clear all diagnostics.
    pub async fn clear_all(&mut self) {
        for uri_str in self.files_with_diagnostics.drain() {
            if let Ok(uri) = Url::parse(&uri_str) {
                self.client.publish_diagnostics(uri, vec![], None).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_position() {
        let range = Range {
            start: Position {
                line: 5,
                character: 10,
            },
            end: Position {
                line: 5,
                character: 20,
            },
        };

        // Inside
        assert!(contains_position(
            &range,
            Position {
                line: 5,
                character: 15
            }
        ));

        // At start
        assert!(contains_position(
            &range,
            Position {
                line: 5,
                character: 10
            }
        ));

        // At end
        assert!(contains_position(
            &range,
            Position {
                line: 5,
                character: 20
            }
        ));

        // Before
        assert!(!contains_position(
            &range,
            Position {
                line: 5,
                character: 5
            }
        ));

        // After
        assert!(!contains_position(
            &range,
            Position {
                line: 5,
                character: 25
            }
        ));

        // Wrong line
        assert!(!contains_position(
            &range,
            Position {
                line: 4,
                character: 15
            }
        ));
    }
}
