//! Test runner - spawns nextest and parses streaming output.

use std::path::Path;
use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::config::Config;
use crate::nextest::{self, NextestMessage, TestFailure};

/// Result of a test run.
#[derive(Debug)]
pub struct TestRunResult {
    /// All test failures with parsed locations.
    pub failures: Vec<TestFailure>,
    /// Names of all tests that passed.
    pub passed_tests: Vec<String>,
    /// Total tests run.
    pub total: u32,
    /// Tests passed.
    pub passed: u32,
    /// Tests failed.
    pub failed: u32,
}

/// The current phase of the test run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunPhase {
    /// Starting up, spawning process.
    Starting,
    /// Compiling the project.
    Compiling,
    /// Running tests.
    Testing,
    /// Completed (successfully or with test failures).
    Done,
}

/// Outcome of a test run - either success/test failures, or a build/run error.
#[derive(Debug)]
pub enum RunOutcome {
    /// Tests ran (possibly with failures).
    Tests(TestRunResult),
    /// Build failed - contains stderr output.
    BuildFailed(String),
    /// Process failed to start or crashed.
    ProcessFailed(String),
}

/// Run tests and collect failures.
///
/// Spawns `cargo nextest run` with JSON output and parses the streaming results.
/// Respects include/exclude filters from config.
///
/// This function reads both stdout and stderr concurrently, so it won't hang
/// even if the build fails and produces no JSON output.
pub async fn run_tests(workspace_root: &Path, config: &Config) -> RunOutcome {
    let mut cmd = Command::new("cargo");
    cmd.arg("nextest")
        .arg("run")
        .arg("--message-format")
        .arg("libtest-json-plus")
        .arg("--no-fail-fast") // Run all tests even if some fail
        .current_dir(workspace_root)
        .env("NEXTEST_EXPERIMENTAL_LIBTEST_JSON", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Add filter expressions if configured
    if let Some(ref include) = config.include {
        if !include.is_empty() {
            // Nextest uses -E for filter expressions
            // Convert glob patterns to nextest filter syntax
            let filter = build_filter_expression(include, &config.exclude);
            if !filter.is_empty() {
                cmd.arg("-E").arg(&filter);
            }
        }
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return RunOutcome::ProcessFailed(format!("failed to spawn cargo nextest: {e}"));
        }
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            return RunOutcome::ProcessFailed("failed to capture stdout".to_string());
        }
    };

    let stderr = match child.stderr.take() {
        Some(s) => s,
        None => {
            return RunOutcome::ProcessFailed("failed to capture stderr".to_string());
        }
    };

    // Read stdout and stderr concurrently
    let stdout_handle = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        let mut failures = Vec::new();
        let mut passed_tests = Vec::new();
        let mut total = 0u32;
        let mut passed = 0u32;
        let mut failed = 0u32;
        let mut got_any_json = false;

        while let Ok(Some(line)) = reader.next_line().await {
            match nextest::parse_message(&line) {
                Ok(msg) => {
                    got_any_json = true;
                    match msg {
                        NextestMessage::Suite(suite_event) => match suite_event {
                            crate::nextest::SuiteEvent::Started { test_count, .. } => {
                                total = test_count;
                            }
                            crate::nextest::SuiteEvent::Failed {
                                passed: p,
                                failed: f,
                                ..
                            }
                            | crate::nextest::SuiteEvent::Ok {
                                passed: p,
                                failed: f,
                                ..
                            } => {
                                passed = p;
                                failed = f;
                            }
                        },
                        NextestMessage::Test(test_event) => match &test_event {
                            nextest::TestEvent::Ok { name, .. } => {
                                passed_tests.push(name.clone());
                            }
                            nextest::TestEvent::Failed { .. } => {
                                if let Some(failure) = test_event.parse_failure() {
                                    failures.push(failure);
                                }
                            }
                            nextest::TestEvent::Started { .. } => {}
                        },
                    }
                }
                Err(_) => {
                    // Non-JSON line, ignore (could be cargo output)
                }
            }
        }

        (
            TestRunResult {
                failures,
                passed_tests,
                total,
                passed,
                failed,
            },
            got_any_json,
        )
    });

    let stderr_handle = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        let mut stderr_output = String::new();

        while let Ok(Some(line)) = reader.next_line().await {
            if !stderr_output.is_empty() {
                stderr_output.push('\n');
            }
            stderr_output.push_str(&line);
        }

        stderr_output
    });

    // Wait for both to complete
    let (stdout_result, stderr_result) = tokio::join!(stdout_handle, stderr_handle);

    let (test_result, got_json) = stdout_result.unwrap_or_else(|_| {
        (
            TestRunResult {
                failures: vec![],
                passed_tests: vec![],
                total: 0,
                passed: 0,
                failed: 0,
            },
            false,
        )
    });

    let stderr_output = stderr_result.unwrap_or_default();

    // Wait for process to finish
    let status = match child.wait().await {
        Ok(s) => s,
        Err(e) => {
            return RunOutcome::ProcessFailed(format!("failed to wait for process: {e}"));
        }
    };

    // Determine outcome based on what we got
    if got_json {
        // We got JSON output, so tests ran (even if some failed)
        RunOutcome::Tests(test_result)
    } else if !status.success() {
        // No JSON and non-zero exit - build failed
        if stderr_output.is_empty() {
            RunOutcome::BuildFailed(format!(
                "cargo nextest exited with code {:?} but produced no output",
                status.code()
            ))
        } else {
            RunOutcome::BuildFailed(stderr_output)
        }
    } else {
        // Success but no JSON? Weird, but return empty result
        RunOutcome::Tests(test_result)
    }
}

/// Build a nextest filter expression from include/exclude patterns.
///
/// Nextest filter syntax: https://nexte.st/docs/filtersets
/// - `test(pattern)` matches test names
/// - `&` for AND, `|` for OR, `!` for NOT
fn build_filter_expression(include: &[String], exclude: &Option<Vec<String>>) -> String {
    let mut parts = Vec::new();

    // Include patterns (OR together)
    if !include.is_empty() {
        let include_expr: Vec<String> = include
            .iter()
            .map(|p| format!("test({})", glob_to_regex(p)))
            .collect();
        parts.push(format!("({})", include_expr.join(" | ")));
    }

    // Exclude patterns (AND NOT each one)
    if let Some(exclude) = exclude {
        for pattern in exclude {
            parts.push(format!("!test({})", glob_to_regex(pattern)));
        }
    }

    if parts.is_empty() {
        String::new()
    } else {
        parts.join(" & ")
    }
}

/// Convert a glob pattern to a regex pattern for nextest.
///
/// Basic conversion:
/// - `*` -> `.*` (match anything)
/// - `?` -> `.` (match single char)
/// - Escape regex metacharacters
fn glob_to_regex(glob: &str) -> String {
    let mut regex = String::with_capacity(glob.len() * 2);
    regex.push('/'); // nextest patterns are regex, wrap in slashes

    for c in glob.chars() {
        match c {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            '.' | '+' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' => {
                regex.push('\\');
                regex.push(c);
            }
            _ => regex.push(c),
        }
    }

    regex.push('/');
    regex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_to_regex() {
        assert_eq!(glob_to_regex("tests::*"), "/tests::.*/");
        assert_eq!(glob_to_regex("*::slow_*"), "/.*::slow_.*/");
        assert_eq!(glob_to_regex("exact::name"), "/exact::name/");
        assert_eq!(glob_to_regex("foo.bar"), "/foo\\.bar/");
    }

    #[test]
    fn test_build_filter_expression() {
        // Include only
        let include = vec!["tests::unit::*".to_string()];
        let expr = build_filter_expression(&include, &None);
        assert_eq!(expr, "(test(/tests::unit::.*/))");

        // Include multiple
        let include = vec!["tests::unit::*".to_string(), "my_crate::*".to_string()];
        let expr = build_filter_expression(&include, &None);
        assert_eq!(expr, "(test(/tests::unit::.*/) | test(/my_crate::.*/))");

        // Include + exclude
        let include = vec!["*".to_string()];
        let exclude = Some(vec!["*::slow_*".to_string()]);
        let expr = build_filter_expression(&include, &exclude);
        assert_eq!(expr, "(test(/.*/)) & !test(/.*::slow_.*/)");
    }
}
