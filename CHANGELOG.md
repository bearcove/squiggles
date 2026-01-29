# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/bearcove/squiggles/compare/squiggles-v0.0.0...squiggles-v0.1.0) - 2026-01-29

### Added

- real-time progress updates during build and test
- parse cargo build progress from stderr
- place diagnostics at test function, not panic location
- add verbose real-time logging for test runs
- add detailed logging for test runs
- watch for config file when disabled, auto-start when created
- add inlay hints for test status using rustc_lexer

### Fixed

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
