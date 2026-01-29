//! LSP integration tests using tower-lsp test utilities.

use std::collections::{HashMap, HashSet};
use tower_lsp::lsp_types::*;

use squiggles::diagnostics::extract_test_name;
use squiggles::lsp::{StoredFailure, find_test_functions_detailed};
use squiggles::nextest::{NextestMessage, parse_message};

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

/// Regression test: failures must be stored at the test function location for hover to work.
///
/// This test uses the ACTUAL source file from styx and the ACTUAL failure JSON
/// to ensure we can find the test function and store the failure at the right location.
#[test]
fn test_failure_stored_at_function_name_for_hover() {
    // Actual JSON from a real test failure in styx
    let json = r#"{"type":"test","event":"failed","name":"facet-styx::facet_styx$error::tests::test_ariadne_config_respects_no_color_env","exec_time":0.006927333,"stdout":"NO_COLOR is set: true\nOutput: \"Error: test error\\n   ╭─[ test.styx:1:1 ]\\n   │\\n 1 │ test input\\n   │ ──┬─  \\n   │   ╰─── here\\n───╯\\n\"\n\nthread 'error::tests::test_ariadne_config_respects_no_color_env' (43515166) panicked at crates/facet-styx/src/error.rs:255:9:\nWith NO_COLOR set, output should not contain ANSI escape codes:\n\"Error: test error\\n   ╭─[ test.styx:1:1 ]\\n   │\\n 1 │ test input\\n   │ ──┬─  \\n   │   ╰─── here\\n───╯\\n\"\nnote: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n"}"#;

    // The ACTUAL source file from styx (copied as fixture)
    let source_code =
        std::fs::read_to_string("test-fixtures/styx-failure/error.rs").expect("fixture exists");

    // Parse the failure
    let msg = parse_message(json).expect("should parse");
    let failure = match msg {
        NextestMessage::Test(test_event) => test_event
            .parse_failure()
            .expect("should be a failure event"),
        other => panic!("expected Test event, got {:?}", other),
    };

    // Extract short name - this is what the LSP does
    let short_name = extract_test_name(&failure.name);
    assert_eq!(short_name, "test_ariadne_config_respects_no_color_env");

    // Find ALL test functions in source - this is what TestFunctionIndex.build() does
    let tests = find_test_functions_detailed(&source_code);

    // Should find multiple tests in this file
    assert!(
        tests.len() >= 5,
        "should find at least 5 test functions, found {}",
        tests.len()
    );

    // The test names should include our target
    let test_names: Vec<_> = tests.iter().map(|t| t.name.as_str()).collect();
    assert!(
        test_names.contains(&"test_ariadne_config_respects_no_color_env"),
        "should find test_ariadne_config_respects_no_color_env in {:?}",
        test_names
    );

    // Look up by short name - this is what test_index.get(&short_name) does
    let test_info = tests
        .iter()
        .find(|t| t.name == short_name)
        .expect("test function MUST be found by short name for hover to work");

    // The function is on line 227 (1-indexed) = line 226 (0-indexed)
    assert_eq!(
        test_info.name_span.line, 226,
        "test function should be on line 226 (0-indexed)"
    );
    assert!(test_info.name_span.len > 0, "name span should have length");

    // When storing for hover, we store at the function name location
    let stored = StoredFailure {
        failure: failure.clone(),
        range: test_info.name_span.to_range(),
    };

    // Verify the range is on the correct line
    assert_eq!(stored.range.start.line, 226);
    assert_eq!(stored.range.end.line, 226);

    // Simulate hover lookup: position on the function name should find the failure
    let hover_position = Position {
        line: 226,
        character: 10, // somewhere in "test_ariadne_config_respects_no_color_env"
    };

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

    assert!(
        contains_position(&stored.range, hover_position),
        "hover on function name (line {}, char {}) should find failure stored at {:?}",
        hover_position.line,
        hover_position.character,
        stored.range
    );
}

/// Test that the test index correctly finds test functions by short name.
#[test]
fn test_index_finds_test_by_short_name() {
    let source = r#"
mod tests {
    #[test]
    fn test_something() {
        assert!(true);
    }

    #[test]
    fn test_another_thing() {
        assert!(false);
    }
}
"#;

    let tests = find_test_functions_detailed(source);
    assert_eq!(tests.len(), 2);

    // Build a name -> info map like TestFunctionIndex does
    let by_name: HashMap<_, _> = tests.iter().map(|t| (t.name.clone(), t)).collect();

    // Look up by short name (what extract_test_name returns)
    assert!(by_name.contains_key("test_something"));
    assert!(by_name.contains_key("test_another_thing"));

    // The full nextest name would be "crate::binary$tests::test_something"
    // extract_test_name should give us just "test_something"
    let full_name = "my_crate::my_binary$tests::test_something";
    let short_name = extract_test_name(full_name);
    assert_eq!(short_name, "test_something");
    assert!(
        by_name.contains_key(&short_name),
        "index should find test by short name"
    );
}
