//! Test runner - spawns nextest and parses streaming output.

use std::path::Path;
use std::process::Stdio;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

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

/// Statistics about a test run for logging.
#[derive(Debug, Clone)]
pub struct RunStats {
    /// The command that was run.
    pub command: String,
    /// Working directory.
    pub cwd: String,
    /// How long the run took in milliseconds.
    pub elapsed_ms: u64,
    /// Exit code of the process.
    pub exit_code: Option<i32>,
    /// Number of lines read from stdout.
    pub stdout_lines: usize,
    /// Number of lines read from stderr.
    pub stderr_lines: usize,
    /// Number of JSON messages parsed.
    pub json_messages: usize,
}

/// Outcome of a test run - either success/test failures, or a build/run error.
#[derive(Debug)]
pub enum RunOutcome {
    /// Tests ran (possibly with failures).
    Tests(TestRunResult, RunStats),
    /// Build failed - contains stderr output.
    BuildFailed(String, RunStats),
    /// Process failed to start or crashed.
    ProcessFailed(String),
}

/// A log event emitted during a test run.
#[derive(Debug, Clone)]
pub enum RunLogEvent {
    /// Starting the command.
    Starting { command: String, cwd: String },
    /// A line from stdout was processed.
    Stdout {
        line: String,
        parsed: Result<String, String>,
    },
    /// A line from stderr was received with parsed build progress.
    Stderr {
        line: String,
        progress: Option<BuildProgress>,
    },
    /// The run completed.
    Completed { stats: RunStats },
}

/// Build progress parsed from cargo stderr output.
#[derive(Debug, Clone)]
pub enum BuildProgress {
    /// Compiling a crate: "Compiling {crate} v{version}"
    Compiling { krate: String },
    /// Waiting for a lock: "Blocking waiting for file lock on {thing}"
    WaitingForLock { target: String },
    /// Build finished: "Finished ..."
    Finished,
    /// Running tests (from nextest): "Starting {n} tests..."
    StartingTests { count: u32 },
}

/// Parse a stderr line to extract build progress information.
fn parse_build_progress(line: &str) -> Option<BuildProgress> {
    let trimmed = line.trim();

    // "   Compiling foo v1.0.0 (/path/to/foo)"
    if let Some(rest) = trimmed.strip_prefix("Compiling ") {
        // Extract crate name (before the version)
        let krate = rest.split_whitespace().next()?.to_string();
        return Some(BuildProgress::Compiling { krate });
    }

    // "Blocking waiting for file lock on package cache"
    if let Some(rest) = trimmed.strip_prefix("Blocking waiting for file lock on ") {
        return Some(BuildProgress::WaitingForLock {
            target: rest.to_string(),
        });
    }

    // "    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.23s"
    if trimmed.starts_with("Finished ") {
        return Some(BuildProgress::Finished);
    }

    // "    Starting 48 tests across 4 binaries"
    if let Some(rest) = trimmed.strip_prefix("Starting ") {
        // Parse "48 tests..."
        if let Some(count_str) = rest.split_whitespace().next() {
            if let Ok(count) = count_str.parse::<u32>() {
                return Some(BuildProgress::StartingTests { count });
            }
        }
    }

    None
}

/// Run tests and collect failures.
///
/// Spawns `cargo nextest run` with JSON output and parses the streaming results.
/// Respects include/exclude filters from config.
///
/// This function reads both stdout and stderr concurrently, so it won't hang
/// even if the build fails and produces no JSON output.
pub async fn run_tests(workspace_root: &Path, config: &Config) -> RunOutcome {
    run_tests_verbose(workspace_root, config, None).await
}

/// Run tests with verbose logging via a channel.
///
/// If `log_tx` is provided, log events will be sent as they happen.
pub async fn run_tests_verbose(
    workspace_root: &Path,
    config: &Config,
    log_tx: Option<mpsc::Sender<RunLogEvent>>,
) -> RunOutcome {
    let start_time = Instant::now();

    let mut args = vec![
        "nextest".to_string(),
        "run".to_string(),
        "--message-format".to_string(),
        "libtest-json-plus".to_string(),
        "--no-fail-fast".to_string(),
    ];

    // Add filter expressions if configured
    if let Some(ref include) = config.include {
        if !include.is_empty() {
            let filter = build_filter_expression(include, &config.exclude);
            if !filter.is_empty() {
                args.push("-E".to_string());
                args.push(filter);
            }
        }
    }

    let command_str = format!("cargo {}", args.join(" "));
    let cwd_str = workspace_root.display().to_string();

    // Log start
    if let Some(ref tx) = log_tx {
        let _ = tx
            .send(RunLogEvent::Starting {
                command: command_str.clone(),
                cwd: cwd_str.clone(),
            })
            .await;
    }

    info!(
        cwd = %workspace_root.display(),
        command = %command_str,
        "Starting test run"
    );

    let mut cmd = Command::new("cargo");
    cmd.args(&args)
        .current_dir(workspace_root)
        .env("NEXTEST_EXPERIMENTAL_LIBTEST_JSON", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            warn!(
                error = %e,
                command = %command_str,
                cwd = %workspace_root.display(),
                "Failed to spawn cargo nextest"
            );
            return RunOutcome::ProcessFailed(format!("failed to spawn cargo nextest: {e}"));
        }
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            warn!("Failed to capture stdout");
            return RunOutcome::ProcessFailed("failed to capture stdout".to_string());
        }
    };

    let stderr = match child.stderr.take() {
        Some(s) => s,
        None => {
            warn!("Failed to capture stderr");
            return RunOutcome::ProcessFailed("failed to capture stderr".to_string());
        }
    };

    // Clone log_tx for the spawned tasks
    let stdout_log_tx = log_tx.clone();
    let stderr_log_tx = log_tx.clone();

    // Read stdout and stderr concurrently
    let stdout_handle = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        let mut failures = Vec::new();
        let mut passed_tests = Vec::new();
        let mut total = 0u32;
        let mut passed = 0u32;
        let mut failed = 0u32;
        let mut got_any_json = false;
        let mut stdout_lines = 0usize;
        let mut json_lines = 0usize;

        while let Ok(Some(line)) = reader.next_line().await {
            stdout_lines += 1;
            match nextest::parse_message(&line) {
                Ok(msg) => {
                    got_any_json = true;
                    json_lines += 1;

                    let description = match &msg {
                        NextestMessage::Suite(suite_event) => match suite_event {
                            crate::nextest::SuiteEvent::Started { test_count, .. } => {
                                // Accumulate test counts from all binaries
                                total += *test_count;
                                format!(
                                    "suite:started test_count={test_count} (total now: {total})"
                                )
                            }
                            crate::nextest::SuiteEvent::Failed {
                                passed: p,
                                failed: f,
                                ..
                            } => {
                                // Accumulate results from all binaries
                                passed += *p;
                                failed += *f;
                                format!(
                                    "suite:failed passed={p} failed={f} (totals: passed={passed} failed={failed})"
                                )
                            }
                            crate::nextest::SuiteEvent::Ok {
                                passed: p,
                                failed: f,
                                ..
                            } => {
                                // Accumulate results from all binaries
                                passed += *p;
                                failed += *f;
                                format!(
                                    "suite:ok passed={p} failed={f} (totals: passed={passed} failed={failed})"
                                )
                            }
                        },
                        NextestMessage::Test(test_event) => match test_event {
                            nextest::TestEvent::Ok { name, .. } => {
                                passed_tests.push(name.clone());
                                format!("test:ok {name}")
                            }
                            nextest::TestEvent::Failed { name, stdout, .. } => {
                                if let Some(failure) = test_event.parse_failure() {
                                    let loc_info = if let Some(ref loc) = failure.panic_location {
                                        format!(" at {}:{}:{}", loc.file, loc.line, loc.column)
                                    } else {
                                        " (no panic location found)".to_string()
                                    };
                                    failures.push(failure);
                                    format!("test:failed {name}{loc_info}")
                                } else {
                                    // Log first 200 chars of stdout to help debug why we couldn't parse
                                    let preview: String = stdout.chars().take(200).collect();
                                    format!(
                                        "test:failed {name} (parse_failure returned None, stdout preview: {preview})"
                                    )
                                }
                            }
                            nextest::TestEvent::Started { name, .. } => {
                                format!("test:started {name}")
                            }
                        },
                    };

                    if let Some(ref tx) = stdout_log_tx {
                        let _ = tx
                            .send(RunLogEvent::Stdout {
                                line: line.clone(),
                                parsed: Ok(description),
                            })
                            .await;
                    }
                }
                Err(e) => {
                    if let Some(ref tx) = stdout_log_tx {
                        let _ = tx
                            .send(RunLogEvent::Stdout {
                                line: line.clone(),
                                parsed: Err(format!("{e}")),
                            })
                            .await;
                    }
                    debug!(line = %line, "Non-JSON stdout line");
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
            stdout_lines,
            json_lines,
        )
    });

    let stderr_handle = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        let mut stderr_output = String::new();
        let mut stderr_lines = 0usize;

        while let Ok(Some(line)) = reader.next_line().await {
            stderr_lines += 1;

            let progress = parse_build_progress(&line);

            if let Some(ref tx) = stderr_log_tx {
                let _ = tx
                    .send(RunLogEvent::Stderr {
                        line: line.clone(),
                        progress,
                    })
                    .await;
            }

            debug!(line = %line, "stderr");
            if !stderr_output.is_empty() {
                stderr_output.push('\n');
            }
            stderr_output.push_str(&line);
        }

        (stderr_output, stderr_lines)
    });

    // Wait for both to complete
    let (stdout_result, stderr_result) = tokio::join!(stdout_handle, stderr_handle);

    let (test_result, got_json, stdout_lines, json_lines) = stdout_result.unwrap_or_else(|e| {
        warn!(error = %e, "stdout task panicked");
        (
            TestRunResult {
                failures: vec![],
                passed_tests: vec![],
                total: 0,
                passed: 0,
                failed: 0,
            },
            false,
            0,
            0,
        )
    });

    let (stderr_output, stderr_lines) = stderr_result.unwrap_or_else(|e| {
        warn!(error = %e, "stderr task panicked");
        (String::new(), 0)
    });

    // Wait for process to finish
    let status = match child.wait().await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "Failed to wait for process");
            return RunOutcome::ProcessFailed(format!("failed to wait for process: {e}"));
        }
    };

    let elapsed = start_time.elapsed();
    let exit_code = status.code();

    let stats = RunStats {
        command: command_str.clone(),
        cwd: cwd_str,
        elapsed_ms: elapsed.as_millis() as u64,
        exit_code,
        stdout_lines,
        stderr_lines,
        json_messages: json_lines,
    };

    // Log completion
    if let Some(ref tx) = log_tx {
        let _ = tx
            .send(RunLogEvent::Completed {
                stats: stats.clone(),
            })
            .await;
    }

    info!(
        elapsed_ms = stats.elapsed_ms,
        exit_code = ?exit_code,
        stdout_lines,
        stderr_lines,
        json_lines,
        got_json,
        cwd = %workspace_root.display(),
        command = %command_str,
        "Test run completed"
    );

    // Determine outcome based on what we got
    if got_json {
        // We got JSON output, so tests ran (even if some failed)
        info!(
            total = test_result.total,
            passed = test_result.passed,
            failed = test_result.failed,
            failures = test_result.failures.len(),
            "Tests completed"
        );
        RunOutcome::Tests(test_result, stats)
    } else if !status.success() {
        // No JSON and non-zero exit - build failed
        let msg = if stderr_output.is_empty() {
            format!(
                "cargo nextest exited with code {:?} but produced no output",
                exit_code
            )
        } else {
            stderr_output.clone()
        };
        warn!(
            exit_code = ?exit_code,
            stderr_lines,
            stderr_preview = %stderr_output.lines().next().unwrap_or(""),
            "Build failed"
        );
        RunOutcome::BuildFailed(msg, stats)
    } else {
        // Success but no JSON? Weird, but return empty result
        warn!(
            exit_code = ?exit_code,
            stdout_lines,
            stderr_lines,
            "No JSON output but process succeeded"
        );
        RunOutcome::Tests(test_result, stats)
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
