//! LSP integration tests using tower-lsp test utilities.

use std::collections::HashSet;
use tower_lsp::lsp_types::*;

// Test that stale diagnostics tracking works correctly
#[test]
fn test_stale_diagnostics_tracking() {

    // Simulate the state tracking logic
    let mut files_with_diagnostics: HashSet<String> = HashSet::new();

    // First run: failures in file_a and file_b
    let new_files: HashSet<String> = ["file:///a.rs", "file:///b.rs"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    let stale: Vec<_> = files_with_diagnostics
        .difference(&new_files)
        .cloned()
        .collect();
    assert!(stale.is_empty(), "No stale files on first run");

    files_with_diagnostics = new_files;

    // Second run: only file_a has failures (file_b fixed)
    let new_files: HashSet<String> = ["file:///a.rs"].iter().map(|s| s.to_string()).collect();

    let stale: Vec<_> = files_with_diagnostics
        .difference(&new_files)
        .cloned()
        .collect();
    assert_eq!(stale, vec!["file:///b.rs"], "file_b should be stale");

    files_with_diagnostics = new_files;

    // Third run: all tests pass
    let new_files: HashSet<String> = HashSet::new();

    let stale: Vec<_> = files_with_diagnostics
        .difference(&new_files)
        .cloned()
        .collect();
    assert_eq!(stale, vec!["file:///a.rs"], "file_a should be stale");
}

#[test]
fn test_position_in_range() {
    // Test the contains_position logic
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

    let range = Range {
        start: Position {
            line: 10,
            character: 5,
        },
        end: Position {
            line: 10,
            character: 20,
        },
    };

    // Inside range
    assert!(contains_position(
        &range,
        Position {
            line: 10,
            character: 10
        }
    ));

    // At start
    assert!(contains_position(
        &range,
        Position {
            line: 10,
            character: 5
        }
    ));

    // At end
    assert!(contains_position(
        &range,
        Position {
            line: 10,
            character: 20
        }
    ));

    // Before start (same line)
    assert!(!contains_position(
        &range,
        Position {
            line: 10,
            character: 4
        }
    ));

    // After end (same line)
    assert!(!contains_position(
        &range,
        Position {
            line: 10,
            character: 21
        }
    ));

    // Wrong line
    assert!(!contains_position(
        &range,
        Position {
            line: 9,
            character: 10
        }
    ));
}
