//! Integration tests for squiggles.
//!
//! These tests call the runner and other components directly,
//! running real `cargo nextest` on test fixtures.

use std::path::PathBuf;

use tower_lsp::lsp_types::*;

use squiggles::config::Config;

/// Get the path to a test fixture crate.
fn fixture_path(name: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("test-fixtures").join(name)
}

/// Test the runner directly - build failure case
#[tokio::test]
async fn test_runner_build_failure() {
    use squiggles::runner::{RunOutcome, run_tests};

    let temp_dir = tempfile::tempdir().unwrap();
    let crate_path = temp_dir.path();

    // Create a broken crate
    std::fs::write(
        crate_path.join("Cargo.toml"),
        r#"[package]
name = "broken"
version = "0.1.0"
edition = "2021"
"#,
    )
    .unwrap();

    std::fs::create_dir_all(crate_path.join("src")).unwrap();
    std::fs::write(
        crate_path.join("src/lib.rs"),
        "fn broken( { }", // Syntax error
    )
    .unwrap();

    let config = Config {
        enabled: true,
        include: None,
        exclude: None,
        debounce_ms: 0,
        max_diagnostics: 50,
    };

    let outcome = run_tests(crate_path, &config).await;

    match outcome {
        RunOutcome::BuildFailed(stderr, stats) => {
            assert!(
                stderr.contains("error") || stderr.contains("unclosed"),
                "Build failure should mention error: {stderr}"
            );
            assert!(stats.elapsed_ms > 0, "Should have elapsed time");
            assert!(stats.exit_code.is_some(), "Should have exit code");
        }
        other => panic!("Expected BuildFailed, got: {other:?}"),
    }
}

/// Test the runner directly - all tests pass
#[tokio::test]
async fn test_runner_all_pass() {
    use squiggles::runner::{RunOutcome, run_tests};

    let temp_dir = tempfile::tempdir().unwrap();
    let crate_path = temp_dir.path();

    std::fs::write(
        crate_path.join("Cargo.toml"),
        r#"[package]
name = "passing"
version = "0.1.0"
edition = "2021"
"#,
    )
    .unwrap();

    std::fs::create_dir_all(crate_path.join("src")).unwrap();
    std::fs::write(
        crate_path.join("src/lib.rs"),
        r#"
#[test]
fn test_pass() {
    assert!(true);
}

#[test]
fn test_math() {
    assert_eq!(2 + 2, 4);
}
"#,
    )
    .unwrap();

    let config = Config {
        enabled: true,
        include: None,
        exclude: None,
        debounce_ms: 0,
        max_diagnostics: 50,
    };

    let outcome = run_tests(crate_path, &config).await;

    match outcome {
        RunOutcome::Tests(result, stats) => {
            assert_eq!(result.failed, 0, "No tests should fail");
            assert!(result.passed >= 2, "At least 2 tests should pass");
            assert!(result.failures.is_empty(), "No failures expected");
            assert!(
                result.passed_tests.len() >= 2,
                "Should track passed test names"
            );
            assert!(stats.json_messages > 0, "Should have parsed JSON");
            assert!(stats.exit_code == Some(0), "Should exit successfully");
        }
        other => panic!("Expected Tests, got: {other:?}"),
    }
}

/// Test the runner directly - test failures
#[tokio::test]
async fn test_runner_with_failures() {
    use squiggles::runner::{RunOutcome, run_tests};

    let fixture = fixture_path("sample-crate");
    if !fixture.exists() {
        eprintln!("Skipping: fixture not found at {:?}", fixture);
        return;
    }

    let config = Config {
        enabled: true,
        include: None,
        exclude: None,
        debounce_ms: 0,
        max_diagnostics: 50,
    };

    let outcome = run_tests(&fixture, &config).await;

    match outcome {
        RunOutcome::Tests(result, stats) => {
            assert!(result.failed > 0, "Should have failing tests");
            assert!(result.passed > 0, "Should have passing tests too");
            assert!(!result.failures.is_empty(), "Should have failure details");

            // Check that failures have panic locations
            for failure in &result.failures {
                assert!(
                    failure.panic_location.is_some(),
                    "Failure should have panic location: {:?}",
                    failure
                );
            }

            assert!(stats.json_messages > 0, "Should have parsed JSON");
        }
        other => panic!("Expected Tests with failures, got: {other:?}"),
    }
}

/// Test diagnostics conversion
#[tokio::test]
async fn test_diagnostics_conversion() {
    use squiggles::diagnostics::failures_to_diagnostics;
    use squiggles::nextest::{SourceLocation, TestFailure};

    let failures = vec![
        TestFailure {
            name: "my_crate::tests::test_foo".to_string(),
            message: "assertion failed: x == y".to_string(),
            panic_location: Some(SourceLocation {
                file: "src/lib.rs".to_string(),
                line: 42,
                column: 9,
            }),
            user_frames: vec![],
            full_output: "thread panicked...".to_string(),
        },
        TestFailure {
            name: "my_crate::tests::test_bar".to_string(),
            message: "explicit panic".to_string(),
            panic_location: Some(SourceLocation {
                file: "src/lib.rs".to_string(),
                line: 55,
                column: 5,
            }),
            user_frames: vec![],
            full_output: "panic!".to_string(),
        },
    ];

    let workspace = PathBuf::from("/workspace");
    let diagnostics = failures_to_diagnostics(&failures, &workspace);

    // Should have diagnostics for lib.rs
    let lib_uri = Url::from_file_path("/workspace/src/lib.rs").unwrap();
    let lib_diags = diagnostics
        .get(&lib_uri)
        .expect("Should have lib.rs diagnostics");

    assert_eq!(lib_diags.len(), 2, "Should have 2 diagnostics");

    // Check first diagnostic
    assert_eq!(lib_diags[0].range.start.line, 41); // 0-indexed
    assert_eq!(lib_diags[0].severity, Some(DiagnosticSeverity::ERROR));
    assert!(lib_diags[0].message.contains("assertion failed"));

    // Check second diagnostic
    assert_eq!(lib_diags[1].range.start.line, 54); // 0-indexed
    assert!(lib_diags[1].message.contains("explicit panic"));
}

/// Test finding test functions in source code
#[test]
fn test_find_test_functions() {
    use squiggles::lsp::find_test_functions;

    let code = r#"
fn helper() {}

#[test]
fn test_one() {
    assert!(true);
}

#[test]
fn test_two() {
    assert_eq!(1, 1);
}

#[tokio::test]
async fn test_async() {
    // async test
}
"#;

    let tests = find_test_functions(code);

    assert_eq!(tests.len(), 3, "Should find 3 test functions");

    let names: Vec<_> = tests.iter().map(|(_, name)| name.as_str()).collect();
    assert!(names.contains(&"test_one"));
    assert!(names.contains(&"test_two"));
    assert!(names.contains(&"test_async"));
}

/// Test that runner doesn't hang on empty output
#[tokio::test]
async fn test_runner_no_hang_on_empty() {
    use squiggles::runner::{RunOutcome, run_tests};
    use std::time::Duration;

    let temp_dir = tempfile::tempdir().unwrap();
    let crate_path = temp_dir.path();

    // Create minimal crate with no tests
    std::fs::write(
        crate_path.join("Cargo.toml"),
        r#"[package]
name = "empty"
version = "0.1.0"
edition = "2021"
"#,
    )
    .unwrap();

    std::fs::create_dir_all(crate_path.join("src")).unwrap();
    std::fs::write(crate_path.join("src/lib.rs"), "// no tests").unwrap();

    let config = Config {
        enabled: true,
        include: None,
        exclude: None,
        debounce_ms: 0,
        max_diagnostics: 50,
    };

    // This should complete quickly, not hang
    let result =
        tokio::time::timeout(Duration::from_secs(60), run_tests(crate_path, &config)).await;

    assert!(result.is_ok(), "Runner should not hang");

    match result.unwrap() {
        RunOutcome::Tests(r, stats) => {
            assert_eq!(r.total, 0, "Should have 0 tests");
            assert_eq!(r.failed, 0);
            assert_eq!(r.passed, 0);
            assert!(stats.elapsed_ms > 0, "Should have elapsed time");
        }
        RunOutcome::BuildFailed(_, _) => {
            // Also acceptable - build might fail for other reasons
        }
        RunOutcome::ProcessFailed(msg) => {
            panic!("Process failed unexpectedly: {msg}");
        }
    }
}
