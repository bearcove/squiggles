# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/bearcove/squiggles/compare/squiggles-v0.0.0...squiggles-v0.1.0) - 2026-01-31

### Added

- Implement package mode in LSP test runner
- Add workspace and package-specific test configuration
- add captain mode for shared target directory
- implement pull diagnostics (textDocument/diagnostic)
- add format_failure_hover for clean hover content
- improved inlay hints with backtrace frames
- real-time progress updates during build and test
- parse cargo build progress from stderr
- place diagnostics at test function, not panic location
- add verbose real-time logging for test runs
- add detailed logging for test runs
- watch for config file when disabled, auto-start when created
- add inlay hints for test status using rustc_lexer

### Fixed

- fixes
- canonicalize workspace root in TestFunctionIndex::build
- clear panic location diagnostics when tests pass
- re-publish diagnostics when a file is opened
- strip ANSI codes before finding message boundaries
- parse color-backtrace output correctly
- highlight test function name, improve failure messages
- simplify diagnostic message, remove redundant test name
- strip ANSI codes from full_output in hover display
- use strip-ansi-escapes crate for proper ANSI code stripping
- parse color-backtrace panic format
- accumulate test results from all binaries in workspace
- load config from workspace root, not cwd
- prevent runner from hanging on build failures
- stay running when disabled instead of exiting
- use SQUIGGLES env prefix, remove strict env mode

### Other

- Clippyisms
- Centralize test results store + publication
- Config reload fixes
- workspace vs package tests semantics
- Show pre-panic logs on hover
- Fix clippy lints
- Run tests only for the saved file's package and its rdeps
- Update diagnostics in real-time as tests complete
- Cancel running tests when new save triggers a run
- Replace include/exclude with direct nextest filter expression
- Fix ANSI escape codes in hover messages, fix exclude filter without include
- Config hot reload
- Respect enabled false, wrap test output
- Better backtrace show-off
- backtrace file fixes
- Introduce scan_exclude
- Add regression tests for hover on test function names
- store failures on both locations
- Clippy fixes
- Introduce squiggles-config crate
- READMEEEE
- centralize diagnostic building in StoredFailure::to_diagnostic
- don't clear inlay hints
- More diag improvements
- add integration tests for runner and diagnostics
- Embed config schema in binary
- Add subcommand support with figue
- Exclude zed-squiggles from workspace
- Add stale diagnostics clearing and LSP tests
- Add xtask for local installation and Zed extension
- Implement full LSP functionality
- Add tower-lsp skeleton and nextest parsing
- figue integration, release-plz
- Start parsing libtest output
