//! Squiggles - Continuous Cargo Test LSP
//!
//! This crate provides an LSP server that continuously runs cargo tests
//! and surfaces failures as editor diagnostics.

pub mod config;
pub mod diagnostics;
pub mod lsp;
pub mod metadata;
pub mod nextest;
pub mod progress;
pub mod runner;
pub mod watcher;
