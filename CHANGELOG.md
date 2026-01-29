# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/bearcove/squiggles/compare/squiggles-v0.0.0...squiggles-v0.1.0) - 2026-01-29

### Added

- watch for config file when disabled, auto-start when created
- add inlay hints for test status using rustc_lexer

### Fixed

- stay running when disabled instead of exiting
- use SQUIGGLES env prefix, remove strict env mode

### Other

- Embed config schema in binary
- Add subcommand support with figue
- Exclude zed-squiggles from workspace
- Add stale diagnostics clearing and LSP tests
- Add xtask for local installation and Zed extension
- Implement full LSP functionality
- Add tower-lsp skeleton and nextest parsing
- figue integration, release-plz
- Start parsing libtest output
