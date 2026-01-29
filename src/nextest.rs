//! Nextest JSON output parsing.
//!
//! Parses the `libtest-json-plus` format from `cargo nextest run --message-format libtest-json-plus`.
//!
//! The format uses nested internal tagging:
//! - Outer tag: `"type"` = `"suite"` | `"test"`
//! - Inner tag: `"event"` = `"started"` | `"ok"` | `"failed"`

use facet::Facet;

/// Nextest-specific metadata attached to suite events.
#[derive(Facet, Debug, Clone, PartialEq)]
pub struct NextestMeta {
    /// Crate name
    #[facet(rename = "crate")]
    pub crate_name: String,
    /// Test binary name
    pub test_binary: String,
    /// Binary kind: "lib", "bin", "test", etc.
    pub kind: String,
}

/// Suite-level event from nextest.
#[derive(Facet, Debug, Clone, PartialEq)]
#[facet(tag = "event", rename_all = "snake_case")]
#[repr(u8)]
pub enum SuiteEvent {
    /// Suite started
    Started {
        test_count: u32,
        nextest: NextestMeta,
    },
    /// Suite finished with failures
    Failed {
        passed: u32,
        failed: u32,
        ignored: u32,
        #[facet(default)]
        measured: Option<u32>,
        #[facet(default)]
        filtered_out: Option<u32>,
        exec_time: f64,
        nextest: NextestMeta,
    },
    /// Suite finished successfully
    Ok {
        passed: u32,
        failed: u32,
        ignored: u32,
        #[facet(default)]
        measured: Option<u32>,
        #[facet(default)]
        filtered_out: Option<u32>,
        exec_time: f64,
        nextest: NextestMeta,
    },
}

/// Test-level event from nextest.
#[derive(Facet, Debug, Clone, PartialEq)]
#[facet(tag = "event", rename_all = "snake_case")]
#[repr(u8)]
pub enum TestEvent {
    /// Test started
    Started {
        /// Full test name: `{crate}::{binary}${module}::{test_name}`
        name: String,
    },
    /// Test passed
    Ok { name: String, exec_time: f64 },
    /// Test failed
    Failed {
        name: String,
        exec_time: f64,
        /// Test output including panic message and backtrace
        stdout: String,
    },
}

/// A single line of nextest JSON output.
///
/// Nextest outputs newline-delimited JSON (JSONL) where each line is one of:
/// - Suite started/finished events
/// - Test started/passed/failed events
///
/// The JSON uses nested internal tagging:
/// - `"type": "suite"` or `"type": "test"` for the outer enum
/// - `"event": "started"` | `"ok"` | `"failed"` for the inner enum
#[derive(Facet, Debug, Clone, PartialEq)]
#[facet(tag = "type", rename_all = "snake_case")]
#[repr(u8)]
pub enum NextestMessage {
    /// Suite-level event (started or finished)
    Suite(SuiteEvent),
    /// Test-level event (started, ok, failed)
    Test(TestEvent),
}

/// A source location extracted from panic output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLocation {
    /// File path (relative or absolute)
    pub file: String,
    /// Line number (1-indexed)
    pub line: u32,
    /// Column number (1-indexed)
    pub column: u32,
}

/// A parsed test failure with extracted locations.
#[derive(Debug, Clone)]
pub struct TestFailure {
    /// Full test name
    pub name: String,
    /// Panic message (first line after "panicked at")
    pub message: String,
    /// Primary panic location
    pub panic_location: Option<SourceLocation>,
    /// Backtrace frames in user code (files starting with `./`)
    pub user_frames: Vec<BacktraceFrame>,
    /// Full stdout for hover display
    pub full_output: String,
}

/// A single frame from the backtrace.
#[derive(Debug, Clone)]
pub struct BacktraceFrame {
    /// Frame number
    pub index: u32,
    /// Function name
    pub function: String,
    /// Source location
    pub location: SourceLocation,
}

impl TestEvent {
    /// Returns true if this is a test failure.
    pub fn is_failure(&self) -> bool {
        matches!(self, TestEvent::Failed { .. })
    }

    /// Parse a test failure from this event.
    /// Returns None if this is not a failure.
    pub fn parse_failure(&self) -> Option<TestFailure> {
        match self {
            TestEvent::Failed {
                name,
                stdout,
                exec_time: _,
            } => {
                let (message, panic_location) = parse_panic_header(stdout);
                let user_frames = parse_backtrace_frames(stdout);

                Some(TestFailure {
                    name: name.clone(),
                    message,
                    panic_location,
                    user_frames,
                    full_output: strip_ansi_codes(stdout),
                })
            }
            _ => None,
        }
    }
}

/// Parse the panic header to extract message and location.
///
/// Supports multiple formats:
/// 1. Standard: `thread '...' (...) panicked at {file}:{line}:{col}:\n{message}`
/// 2. color-backtrace: `Location: {file}:{line}\n` (no column)
fn parse_panic_header(stdout: &str) -> (String, Option<SourceLocation>) {
    // Try standard format first: "panicked at {file}:{line}:{col}:"
    if let Some(panicked_idx) = stdout.find("panicked at ") {
        let after_panicked = &stdout[panicked_idx + "panicked at ".len()..];

        // Find the colon after column number (before the message)
        // Format: file:line:col:\nmessage
        let mut colons = 0;
        let mut location_end = 0;
        for (i, c) in after_panicked.char_indices() {
            if c == ':' {
                colons += 1;
                if colons == 3 {
                    location_end = i;
                    break;
                }
            }
        }

        if colons >= 3 {
            let location_str = &after_panicked[..location_end];
            let location = parse_location(location_str);

            // Message is after the location, skip ":\n"
            let message_start = location_end + 1;
            let message = after_panicked
                .get(message_start..)
                .map(|s| s.trim_start_matches('\n'))
                .and_then(|s| s.lines().next())
                .unwrap_or("")
                .to_string();

            return (message, location);
        }
    }

    // Try color-backtrace format: "Location: {file}:{line}\n"
    // This format doesn't include column
    if let Some(location_idx) = stdout.find("Location: ") {
        let after_location = &stdout[location_idx + "Location: ".len()..];
        // Strip ANSI codes - location might be colorized
        let clean = strip_ansi_codes(after_location);

        // Take until newline
        if let Some(newline_idx) = clean.find('\n') {
            let location_str = clean[..newline_idx].trim();
            // Parse file:line format (no column)
            if let Some(location) = parse_location_no_column(location_str) {
                // Try to extract message from "Message:" if present
                let message = extract_color_backtrace_message(stdout);
                return (message, Some(location));
            }
        }
    }

    (String::new(), None)
}

/// Extract the message from color-backtrace format.
///
/// Handles two formats:
/// 1. Single line: `Message:  {text}\n`
/// 2. Multi-line: `Message:\n{multi-line content}\nLocation:`
fn extract_color_backtrace_message(stdout: &str) -> String {
    let Some(msg_idx) = stdout.find("Message:") else {
        return String::new();
    };

    let after_msg = &stdout[msg_idx + "Message:".len()..];

    // Find where the message ends (at "Location:" line)
    let msg_end = after_msg.find("\nLocation:").unwrap_or(after_msg.len());

    let raw_message = &after_msg[..msg_end];

    // Strip ANSI codes and clean up
    let clean = strip_ansi_codes(raw_message);
    let trimmed = clean.trim();

    if trimmed.is_empty() {
        return String::new();
    }

    trimmed.to_string()
}

/// Strip ANSI escape codes from a string.
fn strip_ansi_codes(s: &str) -> String {
    let stripped = strip_ansi_escapes::strip(s);
    String::from_utf8_lossy(&stripped).into_owned()
}

/// Parse a location string like "file:line" (no column).
fn parse_location_no_column(s: &str) -> Option<SourceLocation> {
    let colon_idx = s.rfind(':')?;
    let file = s[..colon_idx].to_string();
    let line: u32 = s[colon_idx + 1..].parse().ok()?;

    Some(SourceLocation {
        file,
        line,
        column: 1, // Default to column 1
    })
}

/// Parse a location string like "src/lib.rs:10:5" or "./src/lib.rs:10:5"
fn parse_location(s: &str) -> Option<SourceLocation> {
    let parts: Vec<&str> = s.rsplitn(3, ':').collect();
    if parts.len() != 3 {
        return None;
    }

    let column: u32 = parts[0].parse().ok()?;
    let line: u32 = parts[1].parse().ok()?;
    let file = parts[2].to_string();

    Some(SourceLocation { file, line, column })
}

/// Parse backtrace frames from test output.
///
/// Supports two formats:
/// 1. Standard Rust backtrace: `   2: fn_name\n             at ./src/lib.rs:10:5`
/// 2. color-backtrace: `14: fn_name\n    at /absolute/path/src/lib.rs:35`
///
/// Filters to user code only (paths containing `/src/` but not in `.rustup` or `/rustc/`).
fn parse_backtrace_frames(stdout: &str) -> Vec<BacktraceFrame> {
    let mut frames = Vec::new();

    // Strip ANSI codes first - color-backtrace output is heavily colorized
    let clean_stdout = strip_ansi_codes(stdout);

    let mut current_index: Option<u32> = None;
    let mut current_function: Option<String> = None;

    for line in clean_stdout.lines() {
        let trimmed = line.trim();

        // Check for frame header: "2: function_name" or "14: function_name"
        if trimmed
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            // Parse index and function
            if let Some((idx_str, func)) = trimmed.split_once(':') {
                if let Ok(idx) = idx_str.trim().parse::<u32>() {
                    current_index = Some(idx);
                    current_function = Some(func.trim().to_string());
                }
            }
        }
        // Check for location line: "at ./src/lib.rs:10:5" or "at /abs/path:35"
        else if let Some(location_str) = trimmed.strip_prefix("at ") {
            // Filter to user code:
            // - Include paths starting with "./"
            // - Include absolute paths containing "/src/" but not standard library
            let is_user_code = location_str.starts_with("./")
                || (location_str.contains("/src/")
                    && !location_str.contains(".rustup")
                    && !location_str.contains("/rustc/"));

            if is_user_code {
                if let (Some(idx), Some(func)) = (current_index.take(), current_function.take()) {
                    // Try parsing with column first, then without
                    let location = parse_location(location_str)
                        .or_else(|| parse_location_no_column(location_str));

                    if let Some(location) = location {
                        frames.push(BacktraceFrame {
                            index: idx,
                            function: func,
                            location,
                        });
                    }
                }
            }
        }
    }

    frames
}

/// Parse a single line of nextest JSONL output.
pub fn parse_message(line: &str) -> Result<NextestMessage, facet_json::DeserializeError> {
    facet_json::from_str(line)
}

/// Parse all messages from nextest JSONL output.
pub fn parse_messages(output: &str) -> Vec<Result<NextestMessage, facet_json::DeserializeError>> {
    output.lines().map(parse_message).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../test-fixtures/nextest-output-with-backtrace.jsonl");

    #[test]
    fn parse_all_messages() {
        let messages: Vec<_> = parse_messages(FIXTURE).into_iter().collect();

        // Should parse all 14 lines
        assert_eq!(messages.len(), 14);

        // All should parse successfully
        for (i, msg) in messages.iter().enumerate() {
            assert!(msg.is_ok(), "Line {} failed to parse: {:?}", i + 1, msg);
        }
    }

    #[test]
    fn parse_suite_started() {
        let line = r#"{"type":"suite","event":"started","test_count":6,"nextest":{"crate":"sample-crate","test_binary":"sample_crate","kind":"lib"}}"#;
        let msg = parse_message(line).unwrap();

        match msg {
            NextestMessage::Suite(SuiteEvent::Started {
                test_count,
                nextest,
            }) => {
                assert_eq!(test_count, 6);
                assert_eq!(nextest.crate_name, "sample-crate");
                assert_eq!(nextest.test_binary, "sample_crate");
                assert_eq!(nextest.kind, "lib");
            }
            _ => panic!("Expected Suite(Started) event"),
        }
    }

    #[test]
    fn parse_test_passed() {
        let line = r#"{"type":"test","event":"ok","name":"sample-crate::sample_crate$tests::test_passing","exec_time":0.006157125}"#;
        let msg = parse_message(line).unwrap();

        match msg {
            NextestMessage::Test(TestEvent::Ok { name, exec_time }) => {
                assert_eq!(name, "sample-crate::sample_crate$tests::test_passing");
                assert!((exec_time - 0.006157125).abs() < 0.0001);
            }
            _ => panic!("Expected Test(Ok) event"),
        }
    }

    #[test]
    fn parse_test_failed_with_backtrace() {
        // Find a failed test line in the fixture
        let line = FIXTURE
            .lines()
            .find(|l| l.contains("test_panic_in_nested_call") && l.contains("failed"))
            .unwrap();

        let msg = parse_message(line).unwrap();

        match msg {
            NextestMessage::Test(test_event) => {
                let failure = test_event.parse_failure().unwrap();
                assert_eq!(failure.message, "something went wrong in inner function");

                // Check panic location
                let loc = failure.panic_location.unwrap();
                assert_eq!(loc.file, "src/lib.rs");
                assert_eq!(loc.line, 10);
                assert_eq!(loc.column, 5);

                // Check we got user frames
                assert!(!failure.user_frames.is_empty());

                // First user frame should be inner_panic
                let first_frame = &failure.user_frames[0];
                assert!(first_frame.function.contains("inner_panic"));
                assert_eq!(first_frame.location.file, "./src/lib.rs");
                assert_eq!(first_frame.location.line, 10);
            }
            _ => panic!("Expected Test event"),
        }
    }

    #[test]
    fn parse_assertion_failure() {
        let line = FIXTURE
            .lines()
            .find(|l| l.contains("test_assertion_failure") && l.contains("failed"))
            .unwrap();

        let msg = parse_message(line).unwrap();

        match msg {
            NextestMessage::Test(test_event) => {
                let failure = test_event.parse_failure().unwrap();
                assert!(failure.message.contains("assertion"));
                assert!(failure.message.contains("left == right"));
            }
            _ => panic!("Expected Test event"),
        }
    }

    #[test]
    fn extract_all_failures() {
        let failures: Vec<TestFailure> = parse_messages(FIXTURE)
            .into_iter()
            .filter_map(|r| r.ok())
            .filter_map(|msg| match msg {
                NextestMessage::Test(test_event) => test_event.parse_failure(),
                _ => None,
            })
            .collect();

        // Should have 5 failures
        assert_eq!(failures.len(), 5);

        // All should have panic locations
        for failure in &failures {
            assert!(
                failure.panic_location.is_some(),
                "Missing panic location for {}",
                failure.name
            );
        }
    }

    // Color-backtrace corpus tests
    mod color_backtrace_corpus {
        use super::*;

        const CORPUS: &str =
            include_str!("../test-fixtures/parse-corpus/color-backtrace-failures.jsonl");

        fn get_failure(test_name: &str) -> TestFailure {
            CORPUS
                .lines()
                .filter_map(|line| parse_message(line).ok())
                .filter_map(|msg| match msg {
                    NextestMessage::Test(test_event) => test_event.parse_failure(),
                    _ => None,
                })
                .find(|f| f.name.contains(test_name))
                .unwrap_or_else(|| panic!("Test {} not found in corpus", test_name))
        }

        #[test]
        fn parse_all_color_backtrace_messages() {
            let failures: Vec<TestFailure> = parse_messages(CORPUS)
                .into_iter()
                .filter_map(|r| r.ok())
                .filter_map(|msg| match msg {
                    NextestMessage::Test(test_event) => test_event.parse_failure(),
                    _ => None,
                })
                .collect();

            // Should have 14 failures
            assert_eq!(failures.len(), 14, "Expected 14 failures in corpus");

            // All should have panic locations
            for failure in &failures {
                assert!(
                    failure.panic_location.is_some(),
                    "Missing panic location for {}",
                    failure.name
                );
            }

            // All should have non-empty messages
            for failure in &failures {
                assert!(
                    !failure.message.is_empty(),
                    "Empty message for {}",
                    failure.name
                );
            }
        }

        #[test]
        fn simple_panic_message() {
            let f = get_failure("test_simple_panic");
            assert_eq!(f.message, "simple panic message");
            assert_eq!(f.panic_location.as_ref().unwrap().file, "src/lib.rs");
            assert_eq!(f.panic_location.as_ref().unwrap().line, 35);
        }

        #[test]
        fn assertion_eq_with_message() {
            let f = get_failure("test_assertion_failure");
            assert!(
                f.message.contains("assertion `left == right` failed"),
                "message was: {}",
                f.message
            );
            assert!(f.message.contains("values should match"));
        }

        #[test]
        fn assertion_ne_with_message() {
            let f = get_failure("test_assert_ne");
            assert!(
                f.message.contains("assertion `left != right` failed"),
                "message was: {}",
                f.message
            );
            assert!(f.message.contains("vectors should be different"));
        }

        #[test]
        fn assert_no_message() {
            let f = get_failure("test_assert_no_message");
            assert!(
                f.message.contains("assertion failed"),
                "message was: {}",
                f.message
            );
        }

        #[test]
        fn assert_with_format() {
            let f = get_failure("test_assert_with_format");
            assert!(
                f.message.contains("should be greater than 10"),
                "message was: {}",
                f.message
            );
        }

        #[test]
        fn unwrap_none() {
            let f = get_failure("test_unwrap_none");
            assert!(
                f.message.contains("Option::unwrap()") && f.message.contains("None"),
                "message was: {}",
                f.message
            );
        }

        #[test]
        fn unwrap_err() {
            let f = get_failure("test_unwrap_err");
            assert!(
                f.message.contains("Result::unwrap()") && f.message.contains("Err"),
                "message was: {}",
                f.message
            );
            assert!(f.message.contains("something went wrong"));
        }

        #[test]
        fn expect_none() {
            let f = get_failure("test_expect_none");
            assert!(
                f.message.contains("expected a value but got None"),
                "message was: {}",
                f.message
            );
        }

        #[test]
        fn index_out_of_bounds() {
            let f = get_failure("test_index_out_of_bounds");
            assert!(
                f.message.contains("index out of bounds"),
                "message was: {}",
                f.message
            );
            assert!(f.message.contains("len is 3") && f.message.contains("index is 10"));
        }

        #[test]
        fn unreachable() {
            let f = get_failure("test_unreachable");
            assert!(
                f.message.contains("unreachable code"),
                "message was: {}",
                f.message
            );
        }

        #[test]
        fn todo() {
            let f = get_failure("test_todo");
            assert!(
                f.message.contains("not yet implemented"),
                "message was: {}",
                f.message
            );
            assert!(f.message.contains("implement this later"));
        }

        #[test]
        fn unimplemented() {
            let f = get_failure("test_unimplemented");
            assert!(
                f.message.contains("not implemented"),
                "message was: {}",
                f.message
            );
            assert!(f.message.contains("not yet done"));
        }

        #[test]
        fn backtrace_frames_are_parsed() {
            let f = get_failure("test_with_color_backtrace");
            // Should have user frames from the test crate
            assert!(
                !f.user_frames.is_empty(),
                "No user frames parsed for {}",
                f.name
            );

            // Should include frames from our test file
            let has_test_frame = f.user_frames.iter().any(|frame| {
                frame.location.file.contains("color-backtrace-crate")
                    || frame.location.file.contains("src/lib.rs")
            });
            assert!(
                has_test_frame,
                "No frame from test file. Frames: {:?}",
                f.user_frames
            );
        }
    }

    // Tests for multi-line message format (rediff/ariadne output)
    mod multiline_message_corpus {
        use super::*;

        const CORPUS: &str =
            include_str!("../test-fixtures/parse-corpus/styx-multiline-failures.jsonl");

        fn get_failure(test_name: &str) -> TestFailure {
            CORPUS
                .lines()
                .filter_map(|line| parse_message(line).ok())
                .filter_map(|msg| match msg {
                    NextestMessage::Test(test_event) => test_event.parse_failure(),
                    _ => None,
                })
                .find(|f| f.name.contains(test_name))
                .unwrap_or_else(|| panic!("Test {} not found in corpus", test_name))
        }

        #[test]
        fn multiline_message_extracted() {
            let f = get_failure("test_reopen_closed_path_error");

            // The message should contain the error diff, not be empty
            assert!(
                !f.message.is_empty(),
                "Message should not be empty for multiline format"
            );

            // Should contain the actual error content
            assert!(
                f.message.contains("EXPECTED ERRORS") || f.message.contains("Error:"),
                "Message should contain error content, got: {}",
                f.message
            );
        }

        #[test]
        fn multiline_location_parsed() {
            let f = get_failure("test_reopen_closed_path_error");

            let loc = f
                .panic_location
                .as_ref()
                .expect("Should have panic location");
            assert!(
                loc.file.contains("styx-testhelpers") || loc.file.contains("lib.rs"),
                "Location file should be styx-testhelpers, got: {}",
                loc.file
            );
            assert_eq!(loc.line, 140);
        }

        #[test]
        fn multiline_backtrace_frames() {
            let f = get_failure("test_reopen_closed_path_error");

            assert!(
                !f.user_frames.is_empty(),
                "Should have backtrace frames, got none"
            );

            // Should include styx frames
            let has_styx_frame = f
                .user_frames
                .iter()
                .any(|frame| frame.location.file.contains("styx"));
            assert!(
                has_styx_frame,
                "Should have styx frames. Frames: {:?}",
                f.user_frames
            );
        }
    }
}
