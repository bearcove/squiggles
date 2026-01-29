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
    /// Total tests run.
    pub total: u32,
    /// Tests passed.
    pub passed: u32,
    /// Tests failed.
    pub failed: u32,
}

/// Run tests and collect failures.
///
/// Spawns `cargo nextest run` with JSON output and parses the streaming results.
/// Respects include/exclude filters from config.
pub async fn run_tests(workspace_root: &Path, config: &Config) -> Result<TestRunResult, RunError> {
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

    let mut child = cmd.spawn().map_err(|e| RunError::Spawn(e.to_string()))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| RunError::Spawn("failed to capture stdout".to_string()))?;

    let mut reader = BufReader::new(stdout).lines();
    let mut failures = Vec::new();
    let mut total = 0u32;
    let mut passed = 0u32;
    let mut failed = 0u32;

    while let Some(line) = reader.next_line().await.map_err(RunError::Io)? {
        match nextest::parse_message(&line) {
            Ok(msg) => match msg {
                NextestMessage::Suite(suite_event) => {
                    // Extract final counts from suite finished event
                    match suite_event {
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
                    }
                }
                NextestMessage::Test(test_event) => {
                    if let Some(failure) = test_event.parse_failure() {
                        failures.push(failure);
                    }
                }
            },
            Err(e) => {
                // Log parse errors but continue - nextest might emit non-JSON lines
                tracing::warn!("Failed to parse nextest output: {e}");
            }
        }
    }

    // Wait for the process to finish
    let status = child.wait().await.map_err(RunError::Io)?;

    // Non-zero exit is expected when tests fail - that's the whole point!
    // Only treat it as an error if we got no output at all
    if !status.success() && failures.is_empty() && total == 0 {
        return Err(RunError::NexTestFailed(status.code()));
    }

    Ok(TestRunResult {
        failures,
        total,
        passed,
        failed,
    })
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

/// Errors that can occur during test runs.
#[derive(Debug)]
pub enum RunError {
    /// Failed to spawn the nextest process.
    Spawn(String),
    /// IO error reading output.
    Io(std::io::Error),
    /// Nextest exited with an error (and no test output).
    NexTestFailed(Option<i32>),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Spawn(msg) => write!(f, "failed to spawn nextest: {msg}"),
            RunError::Io(e) => write!(f, "IO error: {e}"),
            RunError::NexTestFailed(code) => {
                if let Some(code) = code {
                    write!(f, "nextest failed with exit code {code}")
                } else {
                    write!(f, "nextest failed (killed by signal)")
                }
            }
        }
    }
}

impl std::error::Error for RunError {}

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
