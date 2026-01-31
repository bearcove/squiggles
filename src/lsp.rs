//! LSP server implementation using tower-lsp.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::{RwLock, mpsc};
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

use crate::config::Config;
use crate::metadata::WorkspaceMetadata;
use crate::nextest::TestFailure;
use crate::progress::ProgressHandle;
use crate::watcher::{FileWatcher, WatcherEvent};

/// A stored failure for hover lookup.
#[derive(Debug, Clone)]
pub struct StoredFailure {
    /// The test failure data.
    pub failure: TestFailure,
    /// The range in the file where the diagnostic appears.
    pub range: Range,
}

impl StoredFailure {
    /// Build an LSP Diagnostic from this stored failure.
    pub fn to_diagnostic(&self) -> Diagnostic {
        let message = if !self.failure.message.is_empty() {
            self.failure
                .message
                .lines()
                .next()
                .unwrap_or("Test failed")
                .to_string()
        } else {
            "Test failed".to_string()
        };

        Diagnostic {
            range: self.range,
            severity: Some(DiagnosticSeverity::ERROR),
            code: None,
            code_description: None,
            source: Some("squiggles".to_string()),
            message,
            related_information: None,
            tags: None,
            data: None,
        }
    }
}

/// Result of a single test (pass or fail).
#[derive(Debug, Clone)]
pub enum TestResult {
    /// Test passed.
    Passed,
    /// Test failed with details.
    Failed(StoredFailure),
}

/// Shared state for the LSP server.
pub struct ServerState {
    /// Configuration loaded at startup.
    pub config: Config,
    /// Workspace root path (set during initialization).
    pub workspace_root: Option<PathBuf>,
    /// Cargo workspace metadata for resolving crate-relative paths.
    pub workspace_metadata: Option<WorkspaceMetadata>,
    /// Test failures indexed by file URI for hover lookup.
    /// Maps URI string -> list of failures in that file.
    pub failures: HashMap<String, Vec<StoredFailure>>,
    /// URIs that currently have published diagnostics.
    /// Used to clear stale diagnostics when tests pass.
    pub files_with_diagnostics: HashSet<String>,
    /// All test results indexed by full test name (e.g., "crate::module::test_name").
    /// Used for inlay hints.
    pub test_results: HashMap<String, TestResult>,
}

impl ServerState {
    /// Store failures for hover lookup.
    /// Returns URIs that previously had diagnostics but no longer do (need clearing).
    pub fn store_failures(&mut self, failures: Vec<(Url, StoredFailure)>) -> Vec<Url> {
        // Track which files have failures now
        let mut new_files: HashSet<String> = HashSet::new();

        // Clear old failures
        self.failures.clear();

        // Index by file
        for (uri, failure) in failures {
            let uri_str = uri.to_string();
            new_files.insert(uri_str.clone());
            self.failures.entry(uri_str).or_default().push(failure);
        }

        // Find files that had diagnostics before but don't now
        let stale: Vec<Url> = self
            .files_with_diagnostics
            .difference(&new_files)
            .filter_map(|s| Url::parse(s).ok())
            .collect();

        // Update tracking
        self.files_with_diagnostics = new_files;

        stale
    }

    /// Find a failure at the given position for hover.
    pub fn find_failure_at(&self, uri: &Url, position: Position) -> Option<&StoredFailure> {
        let failures = self.failures.get(&uri.to_string())?;
        failures
            .iter()
            .find(|f| contains_position(&f.range, position))
    }
}

/// Check if a range contains a position.
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

/// The squiggles LSP backend.
pub struct Backend {
    /// LSP client for sending notifications/requests to the editor.
    client: Client,
    /// Shared server state.
    state: Arc<RwLock<ServerState>>,
    /// Channel to trigger test runs (sent when files are saved).
    /// Contains the path of the file that was saved, or None for a full run.
    test_trigger: mpsc::Sender<Option<PathBuf>>,
}

impl Backend {
    /// Create a new backend with the given client and configuration.
    pub fn new(
        client: Client,
        config: Config,
        test_trigger: mpsc::Sender<Option<PathBuf>>,
    ) -> Self {
        Self {
            client,
            state: Arc::new(RwLock::new(ServerState {
                config,
                workspace_root: None,
                workspace_metadata: None,
                failures: HashMap::new(),
                files_with_diagnostics: HashSet::new(),
                test_results: HashMap::new(),
            })),
            test_trigger,
        }
    }

    /// Get a clone of the state for use in spawned tasks.
    pub fn state(&self) -> Arc<RwLock<ServerState>> {
        Arc::clone(&self.state)
    }

    /// Get a clone of the client for use in spawned tasks.
    pub fn client(&self) -> Client {
        self.client.clone()
    }

    /// Publish diagnostics to the client.
    #[allow(dead_code)]
    pub async fn publish_diagnostics(&self, uri: Url, diagnostics: Vec<Diagnostic>) {
        self.client
            .publish_diagnostics(uri, diagnostics, None)
            .await;
    }

    /// Clear all diagnostics for a file.
    #[allow(dead_code)]
    pub async fn clear_diagnostics(&self, uri: Url) {
        self.client.publish_diagnostics(uri, vec![], None).await;
    }

    /// Log a message to the client.
    #[allow(dead_code)]
    pub async fn log_message(&self, message: impl Into<String>) {
        self.client
            .log_message(MessageType::INFO, message.into())
            .await;
    }

    /// Start watching for file changes and running tests.
    async fn start_watching(&self) {
        self.client
            .log_message(MessageType::INFO, "squiggles LSP initialized")
            .await;

        // Start file watcher if we have a workspace root
        let state = self.state.read().await;
        if let Some(ref root) = state.workspace_root {
            let debounce_ms = state.config.debounce_ms;
            let root = root.clone();
            drop(state);

            match FileWatcher::new(&root, debounce_ms) {
                Ok(mut watcher) => {
                    let test_trigger = self.test_trigger.clone();
                    let client = self.client.clone();
                    let state = self.state.clone();

                    // Spawn task to handle watcher events
                    tokio::spawn(async move {
                        while let Some(event) = watcher.rx.recv().await {
                            match event {
                                WatcherEvent::FileSaved(path) => {
                                    // Check if this is the config file
                                    if path.ends_with(".config/squiggles/config.styx") {
                                        Self::reload_config(&state, &client, &path).await;
                                        continue;
                                    }

                                    // Check if enabled before triggering test run
                                    let enabled = {
                                        let state = state.read().await;
                                        state.config.enabled
                                    };
                                    if !enabled {
                                        continue;
                                    }

                                    client
                                        .log_message(
                                            MessageType::INFO,
                                            format!("File changed (debounced): {}", path.display()),
                                        )
                                        .await;
                                    // Trigger test run with the saved file path
                                    let _ = test_trigger.send(Some(path)).await;
                                }
                                WatcherEvent::Error(e) => {
                                    client
                                        .log_message(
                                            MessageType::ERROR,
                                            format!("Watcher error: {e}"),
                                        )
                                        .await;
                                }
                            }
                        }
                    });

                    self.client
                        .log_message(MessageType::INFO, format!("Watching: {}", root.display()))
                        .await;
                }
                Err(e) => {
                    self.client
                        .log_message(
                            MessageType::ERROR,
                            format!("Failed to start file watcher: {e}"),
                        )
                        .await;
                }
            }
        }

        // Trigger initial test run (full workspace)
        let _ = self.test_trigger.send(None).await;
    }

    /// Reload config from disk and update state.
    async fn reload_config(state: &Arc<RwLock<ServerState>>, client: &Client, config_path: &Path) {
        let content = match tokio::fs::read_to_string(config_path).await {
            Ok(c) => c,
            Err(e) => {
                client
                    .log_message(
                        MessageType::ERROR,
                        format!("squiggles: failed to read config: {e}"),
                    )
                    .await;
                return;
            }
        };

        let config: crate::config::Config = match facet_styx::from_str(&content) {
            Ok(c) => c,
            Err(e) => {
                client
                    .log_message(
                        MessageType::ERROR,
                        format!("squiggles: failed to parse config: {e}"),
                    )
                    .await;
                return;
            }
        };

        let was_enabled = {
            let state = state.read().await;
            state.config.enabled
        };

        {
            let mut state = state.write().await;
            state.config = config.clone();
        }

        let mode = if config.is_package_mode() {
            "package"
        } else if config.workspace.is_some() {
            "workspace"
        } else {
            "default"
        };

        client
            .log_message(
                MessageType::INFO,
                format!(
                    "squiggles: config reloaded (enabled: {} -> {}, mode: {})",
                    was_enabled, config.enabled, mode
                ),
            )
            .await;
    }

    /// Watch for config file to be created, then start up.
    async fn watch_for_config(&self, workspace_root: PathBuf) {
        use notify::{Event, EventKind, RecursiveMode, Watcher};

        let config_dir = workspace_root.join(".config/squiggles");
        let config_file = config_dir.join("config.styx");

        // Create channel for config file events
        let (tx, mut rx) = mpsc::channel::<notify::Result<Event>>(16);

        let watcher = notify::recommended_watcher(move |res| {
            let _ = tx.blocking_send(res);
        });

        let mut watcher = match watcher {
            Ok(w) => w,
            Err(e) => {
                self.client
                    .log_message(
                        MessageType::WARNING,
                        format!("Cannot watch for config file: {e}"),
                    )
                    .await;
                return;
            }
        };

        // Watch the .config directory (or workspace root if it doesn't exist)
        let watch_path = if config_dir.exists() {
            &config_dir
        } else {
            &workspace_root
        };

        if let Err(e) = watcher.watch(watch_path, RecursiveMode::Recursive) {
            self.client
                .log_message(
                    MessageType::WARNING,
                    format!("Cannot watch for config file: {e}"),
                )
                .await;
            return;
        }

        self.client
            .log_message(
                MessageType::INFO,
                format!("Waiting for config file: {}", config_file.display()),
            )
            .await;

        let client = self.client.clone();
        let state = self.state.clone();
        let test_trigger = self.test_trigger.clone();

        // Spawn task to watch for config file
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let Ok(event) = event else { continue };

                // Check if the event is for our config file
                let is_config_related = event.paths.iter().any(|p| {
                    p.ends_with("config.styx")
                        || p.ends_with(".config/squiggles")
                        || p.ends_with(".config")
                });

                if !is_config_related {
                    continue;
                }

                // Check if it's a create or modify event
                let is_create_or_modify =
                    matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_));

                if !is_create_or_modify || !config_file.exists() {
                    continue;
                }

                // Try to read and parse the config
                let content = match tokio::fs::read_to_string(&config_file).await {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                // Parse with facet-styx
                let config: std::result::Result<crate::config::Config, _> =
                    facet_styx::from_str(&content);
                let Ok(config) = config else { continue };

                if !config.enabled {
                    continue;
                }

                // Config is now enabled! Update state and start watching
                client
                    .log_message(MessageType::INFO, "Config file detected, starting up...")
                    .await;

                {
                    let mut state_guard = state.write().await;
                    state_guard.config = config;
                }

                // Start the file watcher for tests
                let state_guard = state.read().await;
                if let Some(ref root) = state_guard.workspace_root {
                    let debounce_ms = state_guard.config.debounce_ms;
                    let root = root.clone();
                    drop(state_guard);

                    if let Ok(mut file_watcher) = FileWatcher::new(&root, debounce_ms) {
                        let test_trigger = test_trigger.clone();
                        let watcher_client = client.clone();

                        tokio::spawn(async move {
                            while let Some(event) = file_watcher.rx.recv().await {
                                match event {
                                    WatcherEvent::FileSaved(path) => {
                                        watcher_client
                                            .log_message(
                                                MessageType::INFO,
                                                format!(
                                                    "File changed (debounced): {}",
                                                    path.display()
                                                ),
                                            )
                                            .await;
                                        let _ = test_trigger.send(Some(path)).await;
                                    }
                                    WatcherEvent::Error(e) => {
                                        watcher_client
                                            .log_message(
                                                MessageType::ERROR,
                                                format!("Watcher error: {e}"),
                                            )
                                            .await;
                                    }
                                }
                            }
                        });

                        client
                            .log_message(MessageType::INFO, format!("Watching: {}", root.display()))
                            .await;
                    }
                }

                // Trigger initial test run (full workspace)
                let _ = test_trigger.send(None).await;

                // Stop watching for config - we're now active
                break;
            }

            // Keep watcher alive until we break
            drop(watcher);
        });
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        // Store workspace root and load cargo metadata
        if let Some(root_uri) = params.root_uri
            && let Ok(path) = root_uri.to_file_path()
        {
            let mut state = self.state.write().await;
            state.workspace_metadata = WorkspaceMetadata::load(&path);
            state.workspace_root = Some(path);
        }

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                // We provide diagnostics (test failures as squiggles)
                diagnostic_provider: Some(DiagnosticServerCapabilities::Options(
                    DiagnosticOptions {
                        identifier: Some("squiggles".to_string()),
                        inter_file_dependencies: false,
                        workspace_diagnostics: true,
                        work_done_progress_options: WorkDoneProgressOptions::default(),
                    },
                )),
                // We'll watch for file saves to trigger test runs
                text_document_sync: Some(TextDocumentSyncCapability::Options(
                    TextDocumentSyncOptions {
                        open_close: Some(true),
                        change: Some(TextDocumentSyncKind::NONE), // We don't need content changes
                        save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions {
                            include_text: Some(false),
                        })),
                        ..Default::default()
                    },
                )),
                // Hover to show full panic output
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                // Inlay hints showing test pass/fail status
                inlay_hint_provider: Some(OneOf::Left(true)),
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "squiggles".to_string(),
                version: option_env!("CARGO_PKG_VERSION").map(|s| s.to_string()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        let workspace_root = {
            let state = self.state.read().await;
            state.workspace_root.clone()
        };

        let Some(workspace_root) = workspace_root else {
            self.client
                .log_message(
                    MessageType::WARNING,
                    "squiggles: no workspace root, cannot load config",
                )
                .await;
            return;
        };

        // Try to load config from workspace root
        let config_path = workspace_root.join(".config/squiggles/config.styx");
        let config = if config_path.exists() {
            match tokio::fs::read_to_string(&config_path).await {
                Ok(content) => match facet_styx::from_str::<crate::config::Config>(&content) {
                    Ok(config) => {
                        self.client
                            .log_message(
                                MessageType::INFO,
                                format!("squiggles: loaded config from {}", config_path.display()),
                            )
                            .await;
                        Some(config)
                    }
                    Err(e) => {
                        self.client
                            .log_message(
                                MessageType::ERROR,
                                format!(
                                    "squiggles: failed to parse {}: {e}",
                                    config_path.display()
                                ),
                            )
                            .await;
                        None
                    }
                },
                Err(e) => {
                    self.client
                        .log_message(
                            MessageType::ERROR,
                            format!("squiggles: failed to read {}: {e}", config_path.display()),
                        )
                        .await;
                    None
                }
            }
        } else {
            None
        };

        // Update state with loaded config
        if let Some(config) = config {
            let mut state = self.state.write().await;
            state.config = config;
        }

        let enabled = {
            let state = self.state.read().await;
            state.config.enabled
        };

        if !enabled {
            self.client
                .log_message(
                    MessageType::INFO,
                    format!(
                        "squiggles: disabled (create {} with {{enabled true}})",
                        config_path.display()
                    ),
                )
                .await;

            // Watch for config file to appear
            self.watch_for_config(workspace_root).await;
            return;
        }

        self.start_watching().await;
    }

    async fn shutdown(&self) -> Result<()> {
        // TODO: Stop file watcher
        // TODO: Cancel any running tests
        Ok(())
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let state = self.state.read().await;
        if !state.config.enabled {
            return;
        }
        drop(state);

        let uri = params.text_document.uri;
        self.client
            .log_message(MessageType::INFO, format!("File saved: {uri}"))
            .await;

        // The file watcher handles debouncing, but we also trigger here
        // in case the watcher missed it (e.g., external editor)
        let path = uri.to_file_path().ok();
        let _ = self.test_trigger.send(path).await;
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;

        // Re-publish diagnostics for this file if we have any
        let state = self.state.read().await;
        if let Some(failures) = state.failures.get(&uri.to_string()) {
            let diagnostics: Vec<Diagnostic> =
                failures.iter().map(StoredFailure::to_diagnostic).collect();

            drop(state); // Release lock before async call
            self.client
                .publish_diagnostics(uri, diagnostics, None)
                .await;
        }
    }

    async fn did_close(&self, _params: DidCloseTextDocumentParams) {
        // File closed - could clear diagnostics if desired
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        let state = self.state.read().await;
        if let Some(stored) = state.find_failure_at(&uri, position) {
            let workspace_root = state.workspace_root.as_deref();
            let workspace_metadata = state.workspace_metadata.as_ref();
            let content = format_failure_hover(&stored.failure, workspace_root, workspace_metadata);

            return Ok(Some(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: content,
                }),
                range: Some(stored.range),
            }));
        }

        Ok(None)
    }

    async fn diagnostic(
        &self,
        params: DocumentDiagnosticParams,
    ) -> Result<DocumentDiagnosticReportResult> {
        let uri = params.text_document.uri;

        // Get diagnostics we've already computed for this file
        let state = self.state.read().await;
        let items: Vec<Diagnostic> = state
            .failures
            .get(&uri.to_string())
            .into_iter()
            .flatten()
            .map(StoredFailure::to_diagnostic)
            .collect();

        Ok(DocumentDiagnosticReportResult::Report(
            DocumentDiagnosticReport::Full(RelatedFullDocumentDiagnosticReport {
                related_documents: None,
                full_document_diagnostic_report: FullDocumentDiagnosticReport {
                    result_id: None,
                    items,
                },
            }),
        ))
    }

    async fn inlay_hint(&self, params: InlayHintParams) -> Result<Option<Vec<InlayHint>>> {
        let uri = &params.text_document.uri;

        // Read the file to find #[test] functions
        let file_path = match uri.to_file_path() {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };

        let content = match tokio::fs::read_to_string(&file_path).await {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };

        let state = self.state.read().await;

        // If no test results yet, return empty
        if state.test_results.is_empty() {
            return Ok(None);
        }

        // Find all #[test] functions with detailed span info
        let test_functions = find_test_functions_detailed(&content);
        let mut hints = Vec::new();

        for info in test_functions {
            // Skip if outside requested range
            if info.name_span.line < params.range.start.line
                || info.name_span.line > params.range.end.line
            {
                continue;
            }

            // Try to find matching test result
            // Test names in nextest are: `{crate}::{binary}${module}::{fn_name}`
            // We match by suffix since we only have the function name
            let result = state.test_results.iter().find(|(name, _)| {
                // Match the function name at the end after ::
                name.ends_with(&format!("::{}", info.name))
                    || name.ends_with(&format!("${}", info.name))
                    || **name == info.name
            });

            if let Some((_, test_result)) = result {
                match test_result {
                    TestResult::Passed => {
                        // Simple pass hint after the #[test] attribute
                        hints.push(InlayHint {
                            position: Position {
                                line: info.attr_span.line,
                                character: info.attr_span.col + info.attr_span.len,
                            },
                            label: InlayHintLabel::String(" ✓ pass".to_string()),
                            kind: None,
                            text_edits: None,
                            tooltip: Some(InlayHintTooltip::String("Test passed".to_string())),
                            padding_left: Some(false),
                            padding_right: Some(true),
                            data: None,
                        });
                    }
                    TestResult::Failed(stored) => {
                        // Fail hint after the #[test] attribute
                        hints.push(InlayHint {
                            position: Position {
                                line: info.attr_span.line,
                                character: info.attr_span.col + info.attr_span.len,
                            },
                            label: InlayHintLabel::String(" ✗ fail".to_string()),
                            kind: None,
                            text_edits: None,
                            tooltip: Some(InlayHintTooltip::String(format!(
                                "Test failed: {}",
                                stored.failure.message
                            ))),
                            padding_left: Some(false),
                            padding_right: Some(true),
                            data: None,
                        });

                        // Full error message above the #[test] attribute
                        // (without backtrace, just the message)
                        if !stored.failure.message.is_empty() {
                            // Match the indentation of the #[test] attribute
                            let indent = " ".repeat(info.attr_span.col as usize);
                            // Wavy vertical border characters
                            let wavy = ["│", "╎", "┊", "╏", "┆"];

                            // Wrap lines at 80 characters (accounting for indent + border + spacing)
                            const MAX_WIDTH: usize = 80;
                            let content_width = MAX_WIDTH.saturating_sub(indent.len() + 3); // 3 for "│  "

                            // Format the message with proper indentation, wrapping, and wavy left border
                            let formatted_lines: Vec<String> = stored
                                .failure
                                .message
                                .lines()
                                .flat_map(|line| wrap_line(line, content_width))
                                .enumerate()
                                .map(|(i, line)| {
                                    let border = wavy[i % wavy.len()];
                                    format!("{}{}  {}", indent, border, line)
                                })
                                .collect();

                            // Box width is fixed at 80 chars
                            let wave_len = MAX_WIDTH.saturating_sub(indent.len() + 6);

                            // Build the full hint with box drawing top/bottom
                            let hint_text = format!(
                                "{}╭─ FAILED {}\n{}\n{}│  (hover function name for full backtrace)\n{}╰{}\n",
                                indent,
                                "─".repeat(wave_len),
                                formatted_lines.join("\n"),
                                indent,
                                indent,
                                "─".repeat(wave_len + 9) // +9 for " FAILED "
                            );

                            hints.push(InlayHint {
                                position: Position {
                                    line: info.attr_span.line,
                                    character: 0,
                                },
                                label: InlayHintLabel::String(hint_text),
                                kind: None,
                                text_edits: None,
                                tooltip: None,
                                padding_left: Some(false),
                                padding_right: Some(false),
                                data: None,
                            });
                        }
                    }
                }
            }
        }

        if hints.is_empty() {
            Ok(None)
        } else {
            Ok(Some(hints))
        }
    }
}

/// Find all `#[test]` functions in a Rust file using proper tokenization.
///
/// Returns a list of (line_number, function_name) pairs.
/// Line numbers are 0-indexed.
///
/// Note: This uses rustc_lexer for proper tokenization but cannot expand macros,
/// so macro-generated tests won't be detected.
///
/// A span in source code (0-indexed line and column).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub line: u32,
    pub col: u32,
    pub len: u32,
}

impl Span {
    /// Convert to an LSP Range.
    pub fn to_range(self) -> Range {
        Range {
            start: Position {
                line: self.line,
                character: self.col,
            },
            end: Position {
                line: self.line,
                character: self.col + self.len,
            },
        }
    }
}

/// Information about a test function found in source code.
#[derive(Debug, Clone)]
pub struct TestFunctionInfo {
    /// Span of the `#[test]` attribute
    pub attr_span: Span,
    /// Span of the function name
    pub name_span: Span,
    /// The function name
    pub name: String,
}

/// Find all test functions in source code.
///
/// Returns detailed info including the range of the function name for diagnostics.
pub fn find_test_functions_detailed(content: &str) -> Vec<TestFunctionInfo> {
    use rustc_lexer::{TokenKind, tokenize};

    // Build line number lookup: byte offset -> (line number, column)
    let line_starts: Vec<usize> = std::iter::once(0)
        .chain(content.match_indices('\n').map(|(i, _)| i + 1))
        .collect();

    let offset_to_line_col = |offset: usize| -> (u32, u32) {
        let line = match line_starts.binary_search(&offset) {
            Ok(line) => line,
            Err(line) => line.saturating_sub(1),
        };
        let col = offset - line_starts[line];
        (line as u32, col as u32)
    };

    let _offset_to_line = |offset: usize| -> u32 { offset_to_line_col(offset).0 };

    // Tokenize and collect with offsets
    let mut tokens: Vec<(usize, TokenKind, &str)> = Vec::new();
    let mut offset = 0usize;
    for token in tokenize(content) {
        let text = &content[offset..offset + token.len];
        tokens.push((offset, token.kind, text));
        offset += token.len;
    }

    let mut results = Vec::new();
    let mut i = 0;

    while i < tokens.len() {
        // Look for # starting an attribute
        if matches!(tokens[i].1, TokenKind::Pound) {
            let attr_offset = tokens[i].0;
            i += 1;

            // Skip whitespace
            while i < tokens.len() && matches!(tokens[i].1, TokenKind::Whitespace) {
                i += 1;
            }

            // Expect [
            if i >= tokens.len() || !matches!(tokens[i].1, TokenKind::OpenBracket) {
                continue;
            }
            i += 1;

            // Scan inside the attribute for "test" identifier
            let mut depth = 1;
            let mut has_test = false;
            let mut attr_end_offset = attr_offset + 1; // Default to just after '#'

            while i < tokens.len() && depth > 0 {
                match tokens[i].1 {
                    TokenKind::OpenBracket | TokenKind::OpenParen => depth += 1,
                    TokenKind::CloseBracket | TokenKind::CloseParen => {
                        depth -= 1;
                        if depth == 0 {
                            // Record the end of the attribute (after the ']')
                            attr_end_offset = tokens[i].0 + tokens[i].2.len();
                        }
                    }
                    TokenKind::Ident if tokens[i].2 == "test" => has_test = true,
                    _ => {}
                }
                i += 1;
            }

            if !has_test {
                continue;
            }

            // Found a test attribute, now look for the fn declaration
            // Skip whitespace, comments, and other attributes
            while i < tokens.len() {
                match tokens[i].1 {
                    TokenKind::Whitespace
                    | TokenKind::LineComment
                    | TokenKind::BlockComment { .. } => {
                        i += 1;
                    }
                    TokenKind::Pound => {
                        // Another attribute, skip it entirely
                        i += 1;
                        while i < tokens.len() && matches!(tokens[i].1, TokenKind::Whitespace) {
                            i += 1;
                        }
                        if i < tokens.len() && matches!(tokens[i].1, TokenKind::OpenBracket) {
                            let mut attr_depth = 1;
                            i += 1;
                            while i < tokens.len() && attr_depth > 0 {
                                match tokens[i].1 {
                                    TokenKind::OpenBracket => attr_depth += 1,
                                    TokenKind::CloseBracket => attr_depth -= 1,
                                    _ => {}
                                }
                                i += 1;
                            }
                        }
                    }
                    TokenKind::Ident => {
                        let ident = tokens[i].2;
                        if ident == "fn" {
                            // Found fn keyword, next ident is the function name
                            i += 1;
                            while i < tokens.len() && matches!(tokens[i].1, TokenKind::Whitespace) {
                                i += 1;
                            }
                            if i < tokens.len() && matches!(tokens[i].1, TokenKind::Ident) {
                                let fn_name_offset = tokens[i].0;
                                let fn_name = tokens[i].2;
                                let (name_line, name_col) = offset_to_line_col(fn_name_offset);
                                let (attr_line, attr_col) = offset_to_line_col(attr_offset);
                                let attr_len = (attr_end_offset - attr_offset) as u32;
                                results.push(TestFunctionInfo {
                                    attr_span: Span {
                                        line: attr_line,
                                        col: attr_col,
                                        len: attr_len,
                                    },
                                    name_span: Span {
                                        line: name_line,
                                        col: name_col,
                                        len: fn_name.len() as u32,
                                    },
                                    name: fn_name.to_string(),
                                });
                            }
                            break;
                        } else if matches!(ident, "pub" | "async" | "const" | "unsafe" | "extern") {
                            // Skip function modifiers
                            i += 1;
                        } else {
                            // Unknown identifier, stop looking for fn
                            break;
                        }
                    }
                    _ => break,
                }
            }
            continue;
        }
        i += 1;
    }

    results
}

/// Find all test functions in source code (simple version for backward compatibility).
///
/// Returns (line, name) pairs. Line numbers are 0-indexed.
pub fn find_test_functions(content: &str) -> Vec<(u32, String)> {
    find_test_functions_detailed(content)
        .into_iter()
        .map(|info| (info.attr_span.line, info.name))
        .collect()
}

/// Run the LSP server on stdin/stdout.
pub async fn run(config: Config) {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    // Channel for triggering test runs (carries the saved file path, or None for full run)
    let (test_tx, test_rx) = mpsc::channel::<Option<PathBuf>>(16);

    let (service, socket) = LspService::build(|client| {
        let backend = Backend::new(client, config, test_tx);
        let state = backend.state();
        let client = backend.client();

        // Spawn the test runner task
        // The primary agent will implement the actual test running logic
        tokio::spawn(test_runner_loop(test_rx, state, client));

        backend
    })
    .finish();

    Server::new(stdin, stdout, socket).serve(service).await;
}

/// Background task that runs tests when triggered.
///
/// This receives signals from the file watcher (debounced) and did_save,
/// runs cargo nextest, parses the output, and publishes diagnostics.
async fn test_runner_loop(
    mut rx: mpsc::Receiver<Option<PathBuf>>,
    state: Arc<RwLock<ServerState>>,
    client: Client,
) {
    use crate::diagnostics::{TestFunctionIndex, extract_test_name, failures_to_diagnostics};
    use crate::runner::{RunLogEvent, RunOutcome, run_tests_verbose};
    use tokio_util::sync::CancellationToken;

    // Token to cancel the current test run
    let mut current_cancel: Option<CancellationToken> = None;

    while let Some(saved_file) = rx.recv().await {
        // Cancel any running test
        if let Some(cancel) = current_cancel.take() {
            cancel.cancel();
        }
        // Drain any pending triggers and keep the most recent file path
        let mut saved_file = saved_file;
        while let Ok(newer) = rx.try_recv() {
            if newer.is_some() {
                saved_file = newer;
            }
        }

        // Get workspace root, config, and metadata
        let (workspace_root, config, workspace_metadata) = {
            let state_guard = state.read().await;
            match &state_guard.workspace_root {
                Some(root) => (
                    root.clone(),
                    state_guard.config.clone(),
                    state_guard.workspace_metadata.clone(),
                ),
                None => {
                    client
                        .log_message(
                            MessageType::WARNING,
                            "No workspace root set, skipping test run",
                        )
                        .await;
                    continue;
                }
            }
        };

        // Determine which package to test based on the saved file
        let package_filter: Option<String> = saved_file.as_ref().and_then(|path| {
            workspace_metadata
                .as_ref()
                .and_then(|meta| meta.package_for_file(path))
        });

        if let Some(ref pkg) = package_filter {
            client
                .log_message(
                    MessageType::INFO,
                    format!("Running tests for package: {pkg} (and rdeps)"),
                )
                .await;
        }

        // Start progress indicator
        let progress =
            ProgressHandle::begin(client.clone(), "Squiggles", Some("Starting...".into())).await;
        let progress = Arc::new(progress);

        // Set up verbose logging channel
        let (log_tx, mut log_rx) = mpsc::channel::<RunLogEvent>(4096);
        let log_client = client.clone();
        let log_progress = Arc::clone(&progress);
        let log_state = Arc::clone(&state);
        let log_workspace_root = workspace_root.clone();
        let scan_exclude: Vec<String> = config.scan_exclude.clone().unwrap_or_default();

        // Track test progress
        let mut tests_completed = 0u32;
        let mut tests_total = 0u32;

        // Build test function index once at the start for incremental updates
        let test_index = TestFunctionIndex::build_with_excludes(&log_workspace_root, &scan_exclude);

        // Spawn a task to forward log events to the LSP client and update progress
        let log_task = tokio::spawn(async move {
            while let Some(event) = log_rx.recv().await {
                match event {
                    RunLogEvent::Starting { command, cwd } => {
                        log_client
                            .log_message(
                                MessageType::INFO,
                                format!("[squiggles] STARTING: {command}\n  cwd: {cwd}"),
                            )
                            .await;
                    }
                    RunLogEvent::Stdout { line, parsed } => {
                        let status = match &parsed {
                            Ok(desc) => {
                                // Parse test results to update progress
                                if desc.starts_with("suite:started") {
                                    // Extract test_count from "suite:started test_count=N"
                                    if let Some(count_str) = desc
                                        .split("test_count=")
                                        .nth(1)
                                        .and_then(|s| s.split_whitespace().next())
                                        && let Ok(count) = count_str.parse::<u32>()
                                    {
                                        tests_total += count;
                                        log_progress
                                            .report(format!("Running tests (0/{tests_total})"))
                                            .await;
                                    }
                                } else if desc.starts_with("test:ok")
                                    || desc.starts_with("test:failed")
                                {
                                    tests_completed += 1;
                                    if tests_total > 0 {
                                        let pct = (tests_completed * 100 / tests_total).min(100);
                                        log_progress
                                            .report_percent(
                                                format!("Running tests ({tests_completed}/{tests_total})"),
                                                pct,
                                            )
                                            .await;
                                    }
                                }
                                format!("OK: {desc}")
                            }
                            Err(e) => format!("PARSE_ERROR: {e}\n  line: {line}"),
                        };
                        log_client
                            .log_message(MessageType::LOG, format!("[squiggles] stdout: {status}"))
                            .await;
                    }
                    RunLogEvent::Stderr { line, progress } => {
                        // Log the raw line
                        log_client
                            .log_message(MessageType::LOG, format!("[squiggles] stderr: {line}"))
                            .await;

                        // Update work done progress based on build status
                        if let Some(prog) = progress {
                            use crate::runner::BuildProgress;
                            let msg = match prog {
                                BuildProgress::Compiling { krate } => {
                                    format!("Building {krate}...")
                                }
                                BuildProgress::WaitingForLock { target } => {
                                    format!("Waiting for lock on {target}...")
                                }
                                BuildProgress::Finished => {
                                    "Build finished, running tests...".to_string()
                                }
                                BuildProgress::StartingTests { count } => {
                                    tests_total = count;
                                    format!("Running tests (0/{count})")
                                }
                            };
                            log_progress.report(msg).await;
                        }
                    }
                    RunLogEvent::TestPassed { name } => {
                        // Check if this test previously failed - if so, clear its diagnostic
                        let short_name = extract_test_name(&name);
                        if let Some(test_loc) = test_index.get(&short_name) {
                            let uri = Some(test_loc.uri.clone());

                            let mut state_guard = log_state.write().await;
                            // Check if it was previously failed
                            if let Some(TestResult::Failed(_)) = state_guard.test_results.get(&name)
                            {
                                // Update to passed
                                state_guard
                                    .test_results
                                    .insert(name.clone(), TestResult::Passed);

                                // Rebuild diagnostics for this file
                                if let Some(uri) = uri {
                                    let diagnostics =
                                        rebuild_diagnostics_for_file(&state_guard, &uri);
                                    drop(state_guard);
                                    log_client.publish_diagnostics(uri, diagnostics, None).await;
                                }
                            } else {
                                // Just mark as passed
                                state_guard
                                    .test_results
                                    .insert(name.clone(), TestResult::Passed);
                            }
                        }
                    }
                    RunLogEvent::TestFailed { failure } => {
                        // Immediately publish diagnostic for this failure
                        let short_name = extract_test_name(&failure.name);
                        if let Some(test_loc) = test_index.get(&short_name) {
                            let uri = Some(test_loc.uri.clone());

                            let mut state_guard = log_state.write().await;
                            // Store the failure
                            state_guard.test_results.insert(
                                failure.name.clone(),
                                TestResult::Failed(StoredFailure {
                                    failure: failure.clone(),
                                    range: test_loc.name_span.to_range(),
                                }),
                            );

                            // Rebuild diagnostics for this file
                            if let Some(uri) = uri {
                                let diagnostics = rebuild_diagnostics_for_file(&state_guard, &uri);
                                drop(state_guard);
                                log_client.publish_diagnostics(uri, diagnostics, None).await;
                            }
                        }
                    }
                    RunLogEvent::Completed { stats } => {
                        log_client
                            .log_message(
                                MessageType::INFO,
                                format!(
                                    "[squiggles] COMPLETED: elapsed={}ms exit={:?} stdout={} stderr={} json={}",
                                    stats.elapsed_ms,
                                    stats.exit_code,
                                    stats.stdout_lines,
                                    stats.stderr_lines,
                                    stats.json_messages,
                                ),
                            )
                            .await;
                    }
                }
            }
        });

        // Create cancellation token for this run
        let cancel = CancellationToken::new();
        current_cancel = Some(cancel.clone());

        // Run tests - this always completes, never hangs
        let outcome = run_tests_verbose(
            &workspace_root,
            &config,
            Some(log_tx),
            cancel,
            package_filter.as_deref(),
        )
        .await;

        // Wait for log task to finish
        let _ = log_task.await;

        match outcome {
            RunOutcome::Tests(result, _stats) => {
                let summary = if result.failed == 0 {
                    format!("✓ {}/{} passed", result.passed, result.total)
                } else {
                    format!(
                        "✗ {} failed, {} passed ({} total)",
                        result.failed, result.passed, result.total
                    )
                };

                client.log_message(MessageType::INFO, &summary).await;

                // Build test function index and convert failures to diagnostics
                let scan_exclude = config.scan_exclude.as_deref().unwrap_or(&[]);
                let test_index =
                    TestFunctionIndex::build_with_excludes(&workspace_root, scan_exclude);
                let diagnostics_by_file =
                    failures_to_diagnostics(&result.failures, &workspace_root, &test_index);

                // Store failures for hover lookup and get stale files
                // We store at BOTH the function name location AND the panic location
                // so hover works on either.
                let stale_uris = {
                    let mut state_guard = state.write().await;
                    let mut stored: Vec<(Url, StoredFailure)> = Vec::new();

                    for f in &result.failures {
                        let short_name = extract_test_name(&f.name);

                        // Store at the test function location (for hovering on fn name)
                        if let Some(loc) = test_index.get(&short_name) {
                            stored.push((
                                loc.uri.clone(),
                                StoredFailure {
                                    failure: f.clone(),
                                    range: loc.name_span.to_range(),
                                },
                            ));
                        }

                        // Also store at the panic location (for hovering on panic site)
                        if let Some(panic_loc) = f.panic_location.as_ref() {
                            let file_path = resolve_path(&panic_loc.file, &workspace_root);
                            if let Ok(uri) = Url::from_file_path(&file_path) {
                                stored.push((
                                    uri,
                                    StoredFailure {
                                        failure: f.clone(),
                                        range: location_to_range(panic_loc),
                                    },
                                ));
                            }
                        }
                    }

                    // Build new test results map first, then swap atomically
                    // (avoids clearing results while inlay hints might be requested)
                    let mut new_test_results = HashMap::new();
                    for name in &result.passed_tests {
                        new_test_results.insert(name.clone(), TestResult::Passed);
                    }
                    for failure in &result.failures {
                        let short_name = extract_test_name(&failure.name);
                        if let Some(test_loc) = test_index.get(&short_name) {
                            new_test_results.insert(
                                failure.name.clone(),
                                TestResult::Failed(StoredFailure {
                                    failure: failure.clone(),
                                    range: test_loc.name_span.to_range(),
                                }),
                            );
                        } else if let Some(loc) = &failure.panic_location {
                            let file_path = resolve_path(&loc.file, &workspace_root);
                            if let Ok(_uri) = Url::from_file_path(&file_path) {
                                new_test_results.insert(
                                    failure.name.clone(),
                                    TestResult::Failed(StoredFailure {
                                        failure: failure.clone(),
                                        range: location_to_range(loc),
                                    }),
                                );
                            }
                        }
                    }
                    // Atomic swap
                    state_guard.test_results = new_test_results;

                    state_guard.store_failures(stored)
                };

                // Clear diagnostics from files that no longer have failures
                for uri in stale_uris {
                    client.publish_diagnostics(uri, vec![], None).await;
                }

                // Publish diagnostics for each file with failures
                // Also track these URIs so we can clear them later
                {
                    let mut state_guard = state.write().await;
                    for (uri, diags) in diagnostics_by_file {
                        state_guard.files_with_diagnostics.insert(uri.to_string());
                        client.publish_diagnostics(uri, diags, None).await;
                    }
                }

                // End progress with summary
                progress.end(Some(summary)).await;
            }
            RunOutcome::BuildFailed(stderr, _stats) => {
                // Build failed - show the error to the user
                let first_line = stderr.lines().next().unwrap_or("Build failed");
                let summary = format!("⚠ Build failed: {first_line}");

                client
                    .log_message(MessageType::ERROR, format!("Build failed:\n{stderr}"))
                    .await;

                // Clear all test results since we couldn't run tests
                {
                    let mut state_guard = state.write().await;
                    state_guard.test_results.clear();
                    // Clear stored failures too
                    let stale_uris = state_guard.store_failures(vec![]);
                    drop(state_guard);

                    // Clear diagnostics from all files that had them
                    for uri in stale_uris {
                        client.publish_diagnostics(uri, vec![], None).await;
                    }
                }

                progress.end(Some(summary)).await;
            }
            RunOutcome::ProcessFailed(msg) => {
                // Process failed to start or crashed
                let summary = format!("⚠ {msg}");

                client
                    .log_message(MessageType::ERROR, format!("Process failed: {msg}"))
                    .await;

                // Clear all test results
                {
                    let mut state_guard = state.write().await;
                    state_guard.test_results.clear();
                    let stale_uris = state_guard.store_failures(vec![]);
                    drop(state_guard);

                    for uri in stale_uris {
                        client.publish_diagnostics(uri, vec![], None).await;
                    }
                }

                progress.end(Some(summary)).await;
            }
            RunOutcome::Cancelled => {
                // Test run was cancelled (new run starting)
                // Don't clear diagnostics - they'll be updated by the new run
                progress.end(Some("Cancelled".to_string())).await;
            }
        }
    }
}

/// Rebuild all diagnostics for a single file based on current state.
///
/// This is used for incremental updates when test results stream in.
fn rebuild_diagnostics_for_file(state: &ServerState, uri: &Url) -> Vec<Diagnostic> {
    use crate::diagnostics::extract_failure_summary;

    let mut diagnostics = Vec::new();

    // Check the failures map which is keyed by URI string
    if let Some(failures) = state.failures.get(&uri.to_string()) {
        for stored in failures {
            let message = extract_failure_summary(&stored.failure.full_output);
            diagnostics.push(Diagnostic {
                range: stored.range,
                severity: Some(DiagnosticSeverity::ERROR),
                source: Some("squiggles".to_string()),
                message,
                ..Default::default()
            });
        }
    }

    diagnostics
}

/// Format a test failure for hover display.
///
/// Extracts the relevant information from color-backtrace or standard backtrace output
/// and formats it as markdown for the hover popup with clickable file links.
fn format_failure_hover(
    failure: &TestFailure,
    workspace_root: Option<&std::path::Path>,
    workspace_metadata: Option<&WorkspaceMetadata>,
) -> String {
    use std::path::Path;

    let output = &failure.full_output;
    let mut result = String::new();

    // Extract the message
    let message = if !failure.message.is_empty() {
        failure.message.clone()
    } else if let Some(msg) = extract_color_backtrace_message(output) {
        msg
    } else {
        "Test failed".to_string()
    };

    // Extract pre-panic output (everything before the panic/crash line)
    let pre_panic_output = extract_pre_panic_output(output);

    result.push_str("```\n");
    result.push_str(&message);
    result.push_str("\n```\n\n");

    // Helper to resolve a crate-relative path using workspace metadata
    let resolve_path = |file: &str, function: Option<&str>| -> Option<std::path::PathBuf> {
        // If already absolute and exists, use it
        if Path::new(file).is_absolute() && Path::new(file).exists() {
            return Some(file.into());
        }

        // Try using workspace metadata to resolve via crate name
        if let Some(meta) = workspace_metadata
            && let Some(func) = function
            && let Some(resolved) = meta.resolve_frame_path(func, file)
        {
            crate::diagnostics::debug_log(&format!(
                "resolve_path: '{}' via function '{}' -> {}",
                file,
                func,
                resolved.display()
            ));
            return Some(resolved);
        }

        // Fall back to workspace root join
        if let Some(root) = workspace_root {
            let clean = file.strip_prefix("./").unwrap_or(file);
            let joined = root.join(clean);
            if joined.exists() {
                return Some(joined);
            }
        }

        crate::diagnostics::debug_log(&format!("resolve_path: '{}' -> not found", file));
        None
    };

    // Helper to make path relative to workspace for display
    let relative_path = |path: &Path| -> String {
        if let Some(root) = workspace_root
            && let Ok(rel) = path.strip_prefix(root)
        {
            return rel.display().to_string();
        }
        path.display().to_string()
    };

    // Helper to read a complete expression from a file starting at a line.
    // Uses rustc_lexer to find balanced parentheses/brackets/braces.
    // Preserves indentation and caps at 3 lines.
    let read_expression = |path: &Path, line: u32| -> Option<String> {
        use rustc_lexer::{TokenKind, tokenize};

        let content = std::fs::read_to_string(path).ok()?;
        let lines: Vec<&str> = content.lines().collect();
        let line_idx = line.saturating_sub(1) as usize;

        if line_idx >= lines.len() {
            return None;
        }

        // Get the starting line (preserve original indentation)
        let first_line = lines[line_idx];

        // Tokenize the first line to see if parens are balanced
        let mut depth = 0i32;
        for token in tokenize(first_line) {
            match token.kind {
                TokenKind::OpenParen | TokenKind::OpenBracket | TokenKind::OpenBrace => {
                    depth += 1;
                }
                TokenKind::CloseParen | TokenKind::CloseBracket | TokenKind::CloseBrace => {
                    depth -= 1;
                }
                _ => {}
            }
        }

        // If balanced, just return the single line
        if depth == 0 {
            return Some(first_line.to_string());
        }

        // Otherwise, accumulate lines until balanced (max 3 lines)
        let mut result_lines = vec![first_line];
        let mut current_line = line_idx + 1;
        const MAX_LINES: usize = 3;

        while depth > 0 && current_line < lines.len() && result_lines.len() < MAX_LINES {
            let next_line = lines[current_line];
            result_lines.push(next_line);

            for token in tokenize(next_line) {
                match token.kind {
                    TokenKind::OpenParen | TokenKind::OpenBracket | TokenKind::OpenBrace => {
                        depth += 1;
                    }
                    TokenKind::CloseParen | TokenKind::CloseBracket | TokenKind::CloseBrace => {
                        depth -= 1;
                    }
                    _ => {}
                }
            }
            current_line += 1;
        }

        // If we hit the limit and still unbalanced, add ellipsis
        let mut result = result_lines.join("\n");
        if depth > 0 {
            result.push_str("\n    ...");
        }

        Some(result)
    };

    // Helper to make a clickable file link
    let make_link = |path: &Path, line: u32| -> String {
        let rel = relative_path(path);
        let abs = path.display();
        format!("[{}:{}](file://{}#{})", rel, line, abs, line)
    };

    // Add location if available
    if let Some(ref loc) = failure.panic_location {
        // For panic location, use the first user frame's function name if available
        let func = failure.user_frames.first().map(|f| f.function.as_str());
        if let Some(path) = resolve_path(&loc.file, func) {
            result.push_str(&format!("at {}\n\n", make_link(&path, loc.line)));
        } else {
            // Fallback to raw path
            let clean = loc.file.strip_prefix("./").unwrap_or(&loc.file);
            result.push_str(&format!("at {}:{}\n\n", clean, loc.line));
        }
    }

    // Add relevant backtrace frames (user code only)
    if !failure.user_frames.is_empty() {
        result.push_str("**Backtrace:**\n\n");
        for frame in &failure.user_frames {
            let short_fn = frame.function.split("::").last().unwrap_or(&frame.function);

            if let Some(path) = resolve_path(&frame.location.file, Some(&frame.function)) {
                result.push_str(&format!(
                    "◈ #{} `{}` at {}\n",
                    frame.index,
                    short_fn,
                    make_link(&path, frame.location.line)
                ));
                if let Some(expr) = read_expression(&path, frame.location.line) {
                    // Format as blockquote with code block inside
                    result.push_str("> ```rust\n");
                    for line in expr.lines() {
                        result.push_str("> ");
                        result.push_str(line);
                        result.push('\n');
                    }
                    result.push_str("> ```\n");
                }
            } else {
                // Fallback to raw path
                let clean = frame
                    .location
                    .file
                    .strip_prefix("./")
                    .unwrap_or(&frame.location.file);
                result.push_str(&format!(
                    "◈ #{} `{}` at {}:{}\n",
                    frame.index, short_fn, clean, frame.location.line
                ));
            }
            result.push('\n');
        }
    }

    // Add pre-panic output at the bottom if present
    if !pre_panic_output.is_empty() {
        result.push_str("\n---\n\n");
        result.push_str("*Keep scrolling for full test output*\n\n");
        result.push_str("```\n");
        result.push_str(&pre_panic_output);
        result.push_str("\n```\n");
    }

    result
}

/// Extract output that appeared before the panic.
///
/// This captures any println!, logging, or other output the test produced
/// before it crashed, which can be useful debugging context.
fn extract_pre_panic_output(output: &str) -> String {
    // Find where the panic starts
    // Standard format: "thread '...' panicked at"
    // Color-backtrace format: "The application panicked (crashed)."
    let panic_start = output
        .find("panicked at ")
        .or_else(|| output.find("The application panicked"))
        .unwrap_or(output.len());

    // Also check for "thread '" which precedes the panic message
    let thread_start = output.find("thread '").unwrap_or(panic_start);
    let start = thread_start.min(panic_start);

    if start == 0 {
        return String::new();
    }

    // Get everything before the panic, trimmed
    let pre_panic = output[..start].trim();

    if pre_panic.is_empty() {
        return String::new();
    }

    pre_panic.to_string()
}

/// Extract the message from color-backtrace format output.
///
/// Color-backtrace outputs:
/// ```text
/// The application panicked (crashed).
/// Message:  {message}
///   {optional extra lines for assertion failures}
/// Location: {file}:{line}
/// ```
fn extract_color_backtrace_message(output: &str) -> Option<String> {
    // Look for "Message:" prefix
    let msg_start = output.find("Message:")?;
    let after_msg = &output[msg_start + "Message:".len()..];

    // Find where the message ends (at "Location:" or blank line)
    let msg_end = after_msg
        .find("\nLocation:")
        .or_else(|| after_msg.find("\n\n"))
        .unwrap_or(after_msg.len());

    let message = after_msg[..msg_end].trim();

    if message.is_empty() {
        None
    } else {
        Some(message.to_string())
    }
}

/// Wrap a line at the specified width, breaking at word boundaries where possible.
fn wrap_line(line: &str, max_width: usize) -> Vec<String> {
    if line.chars().count() <= max_width {
        return vec![line.to_string()];
    }

    let mut result = Vec::new();
    let mut current_line = String::new();
    let mut current_width = 0;

    for word in line.split_inclusive(char::is_whitespace) {
        let word_width = word.chars().count();

        if current_width + word_width > max_width && !current_line.is_empty() {
            result.push(current_line.trim_end().to_string());
            current_line = String::new();
            current_width = 0;
        }

        // Handle words longer than max_width by hard-breaking them
        if word_width > max_width {
            let mut chars = word.chars().peekable();
            while chars.peek().is_some() {
                let remaining = max_width - current_width;
                let chunk: String = chars.by_ref().take(remaining).collect();
                current_line.push_str(&chunk);
                current_width += chunk.chars().count();

                if current_width >= max_width {
                    result.push(current_line.trim_end().to_string());
                    current_line = String::new();
                    current_width = 0;
                }
            }
        } else {
            current_line.push_str(word);
            current_width += word_width;
        }
    }

    if !current_line.is_empty() {
        result.push(current_line.trim_end().to_string());
    }

    result
}

/// Resolve a file path relative to the workspace root.
fn resolve_path(file: &str, workspace_root: &std::path::Path) -> std::path::PathBuf {
    let file_path = std::path::Path::new(file);
    if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        let clean = file.strip_prefix("./").unwrap_or(file);
        workspace_root.join(clean)
    }
}

/// Convert a SourceLocation to an LSP Range.
fn location_to_range(loc: &crate::nextest::SourceLocation) -> Range {
    let line = loc.line.saturating_sub(1);
    let col = loc.column.saturating_sub(1);
    Range {
        start: Position {
            line,
            character: col,
        },
        end: Position {
            line,
            character: col,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::find_test_functions;

    #[test]
    fn simple_test_function() {
        let code = r#"
#[test]
fn my_test() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(1, "my_test".to_string())]);
    }

    #[test]
    fn test_with_pub() {
        let code = r#"
#[test]
pub fn my_test() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(1, "my_test".to_string())]);
    }

    #[test]
    fn async_test() {
        let code = r#"
#[test]
async fn my_async_test() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(1, "my_async_test".to_string())]);
    }

    #[test]
    fn pub_async_test() {
        let code = r#"
#[test]
pub async fn my_pub_async_test() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(1, "my_pub_async_test".to_string())]);
    }

    #[test]
    fn tokio_test() {
        let code = r#"
#[tokio::test]
async fn my_tokio_test() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(1, "my_tokio_test".to_string())]);
    }

    #[test]
    fn async_std_test() {
        let code = r#"
#[async_std::test]
async fn my_async_std_test() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(1, "my_async_std_test".to_string())]);
    }

    #[test]
    fn multiple_tests() {
        let code = r#"
#[test]
fn test_one() {}

#[test]
fn test_two() {}

#[test]
fn test_three() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(
            results,
            vec![
                (1, "test_one".to_string()),
                (4, "test_two".to_string()),
                (7, "test_three".to_string()),
            ]
        );
    }

    #[test]
    fn test_with_other_attributes() {
        let code = r#"
#[test]
#[should_panic]
fn panicking_test() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(1, "panicking_test".to_string())]);
    }

    #[test]
    fn test_with_cfg_attribute() {
        let code = r#"
#[cfg(test)]
#[test]
fn cfg_test() {}
"#;
        let results = find_test_functions(code);
        // #[cfg(test)] contains "test" identifier, so it matches on line 1
        assert_eq!(results, vec![(1, "cfg_test".to_string())]);
    }

    #[test]
    fn test_with_ignore() {
        let code = r#"
#[test]
#[ignore]
fn ignored_test() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(1, "ignored_test".to_string())]);
    }

    #[test]
    fn test_with_ignore_reason() {
        let code = r#"
#[test]
#[ignore = "not ready yet"]
fn ignored_with_reason() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(1, "ignored_with_reason".to_string())]);
    }

    #[test]
    fn no_tests_in_file() {
        let code = r#"
fn regular_function() {}

pub fn another_function() {}
"#;
        let results = find_test_functions(code);
        assert!(results.is_empty());
    }

    #[test]
    fn test_in_string_not_detected() {
        let code = r##"
fn foo() {
    let s = "#[test]
fn fake_test() {}";
}
"##;
        let results = find_test_functions(code);
        assert!(results.is_empty());
    }

    #[test]
    fn test_in_comment_not_detected() {
        let code = r#"
// #[test]
// fn commented_test() {}

fn real_function() {}
"#;
        let results = find_test_functions(code);
        assert!(results.is_empty());
    }

    #[test]
    fn test_in_block_comment_not_detected() {
        let code = r#"
/*
#[test]
fn block_commented_test() {}
*/

fn real_function() {}
"#;
        let results = find_test_functions(code);
        assert!(results.is_empty());
    }

    #[test]
    fn test_with_doc_comment() {
        let code = r#"
/// This is a documented test
#[test]
fn documented_test() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(2, "documented_test".to_string())]);
    }

    #[test]
    fn test_with_multiline_doc_comment() {
        let code = r#"
/// First line
/// Second line
/// Third line
#[test]
fn multi_doc_test() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(4, "multi_doc_test".to_string())]);
    }

    #[test]
    fn unsafe_test() {
        let code = r#"
#[test]
unsafe fn unsafe_test() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(1, "unsafe_test".to_string())]);
    }

    #[test]
    fn const_fn_not_test() {
        // const fn can't be a test, but we handle the modifier anyway
        let code = r#"
#[test]
const fn const_test() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(1, "const_test".to_string())]);
    }

    #[test]
    fn test_case_attribute() {
        // test_case macro uses #[test_case(...)]
        let code = r#"
#[test_case(1, 2)]
#[test_case(3, 4)]
fn parameterized_test(a: i32, b: i32) {}
"#;
        let results = find_test_functions(code);
        // "test_case" is a single identifier, not "test" - so not detected
        assert!(results.is_empty());
    }

    #[test]
    fn rstest_attribute() {
        let code = r#"
#[rstest]
fn rstest_fn() {}
"#;
        let results = find_test_functions(code);
        // rstest doesn't contain "test" as an identifier, so not detected
        assert!(results.is_empty());
    }

    #[test]
    fn mixed_tests_and_functions() {
        let code = r#"
fn helper() {}

#[test]
fn test_one() {}

fn another_helper() {}

#[test]
fn test_two() {}

impl Foo {
    fn method(&self) {}
}
"#;
        let results = find_test_functions(code);
        assert_eq!(
            results,
            vec![(3, "test_one".to_string()), (8, "test_two".to_string()),]
        );
    }

    #[test]
    fn test_with_generics() {
        let code = r#"
#[test]
fn generic_test<T: Default>() {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(1, "generic_test".to_string())]);
    }

    #[test]
    fn test_with_where_clause() {
        let code = r#"
#[test]
fn where_test<T>() where T: Clone {}
"#;
        let results = find_test_functions(code);
        assert_eq!(results, vec![(1, "where_test".to_string())]);
    }

    #[test]
    fn test_attribute_with_parens() {
        let code = r#"
#[test()]
fn test_with_parens() {}
"#;
        let results = find_test_functions(code);
        // #[test()] still has "test" identifier
        assert!(results.is_empty() || results == vec![(1, "test_with_parens".to_string())]);
    }

    #[test]
    fn empty_file() {
        let code = "";
        let results = find_test_functions(code);
        assert!(results.is_empty());
    }

    #[test]
    fn whitespace_only() {
        let code = "   \n\n   \t\t\n";
        let results = find_test_functions(code);
        assert!(results.is_empty());
    }

    mod hover_format {
        use super::super::{
            extract_color_backtrace_message, extract_pre_panic_output, format_failure_hover,
        };
        use crate::nextest::{BacktraceFrame, SourceLocation, TestFailure};

        #[test]
        fn extract_simple_message() {
            let output = "The application panicked (crashed).\nMessage:  simple panic message\nLocation: src/lib.rs:35\n";
            let msg = extract_color_backtrace_message(output);
            assert_eq!(msg, Some("simple panic message".to_string()));
        }

        #[test]
        fn extract_multiline_assertion_message() {
            let output = "The application panicked (crashed).\nMessage:  assertion `left == right` failed: values should match\n  left: 42\n right: 41\nLocation: src/lib.rs:30\n";
            let msg = extract_color_backtrace_message(output);
            assert_eq!(
                msg,
                Some(
                    "assertion `left == right` failed: values should match\n  left: 42\n right: 41"
                        .to_string()
                )
            );
        }

        #[test]
        fn format_failure_with_message_and_location() {
            let failure = TestFailure {
                name: "test::my_test".to_string(),
                message: "assertion failed".to_string(),
                panic_location: Some(SourceLocation {
                    file: "src/lib.rs".to_string(),
                    line: 42,
                    column: 5,
                }),
                user_frames: vec![],
                full_output: String::new(),
            };

            let hover = format_failure_hover(&failure, None, None);
            assert!(hover.contains("assertion failed"));
            assert!(hover.contains("src/lib.rs:42"));
        }

        #[test]
        fn format_failure_with_backtrace() {
            let failure = TestFailure {
                name: "test::my_test".to_string(),
                message: "panicked".to_string(),
                panic_location: Some(SourceLocation {
                    file: "src/lib.rs".to_string(),
                    line: 10,
                    column: 5,
                }),
                user_frames: vec![
                    BacktraceFrame {
                        index: 14,
                        function: "my_crate::helper::inner_fn".to_string(),
                        location: SourceLocation {
                            file: "./src/helper.rs".to_string(),
                            line: 20,
                            column: 9,
                        },
                    },
                    BacktraceFrame {
                        index: 15,
                        function: "my_crate::tests::my_test".to_string(),
                        location: SourceLocation {
                            file: "./src/lib.rs".to_string(),
                            line: 10,
                            column: 5,
                        },
                    },
                ],
                full_output: String::new(),
            };

            let hover = format_failure_hover(&failure, None, None);
            assert!(hover.contains("**Backtrace:**"));
            assert!(hover.contains("#14"));
            assert!(hover.contains("`inner_fn`"));
            assert!(hover.contains("src/helper.rs:20")); // relative_path strips ./
        }

        #[test]
        fn format_failure_extracts_color_backtrace_message() {
            let failure = TestFailure {
                name: "test::my_test".to_string(),
                message: String::new(), // Empty, should fall back to extraction
                panic_location: None,
                user_frames: vec![],
                full_output: "The application panicked (crashed).\nMessage:  custom error from color-backtrace\nLocation: src/lib.rs:5\n".to_string(),
            };

            let hover = format_failure_hover(&failure, None, None);
            assert!(hover.contains("custom error from color-backtrace"));
        }

        #[test]
        fn extract_pre_panic_output_with_println() {
            let output = "some debug output\nmore logging here\nthread 'test::my_test' panicked at src/lib.rs:10:5:\nassertion failed";
            let pre = extract_pre_panic_output(output);
            assert_eq!(pre, "some debug output\nmore logging here");
        }

        #[test]
        fn extract_pre_panic_output_color_backtrace() {
            let output =
                "debug line 1\ndebug line 2\nThe application panicked (crashed).\nMessage:  oops";
            let pre = extract_pre_panic_output(output);
            assert_eq!(pre, "debug line 1\ndebug line 2");
        }

        #[test]
        fn extract_pre_panic_output_empty_when_panic_at_start() {
            let output = "thread 'test' panicked at src/lib.rs:1:1:\nboom";
            let pre = extract_pre_panic_output(output);
            assert!(pre.is_empty());
        }

        #[test]
        fn format_failure_includes_pre_panic_output() {
            let failure = TestFailure {
                name: "test::my_test".to_string(),
                message: "assertion failed".to_string(),
                panic_location: None,
                user_frames: vec![],
                full_output: "setup complete\nrunning step 1\nthread 'test::my_test' panicked at src/lib.rs:10:5:\nassertion failed".to_string(),
            };

            let hover = format_failure_hover(&failure, None, None);
            assert!(hover.contains("Keep scrolling for full test output"));
            assert!(hover.contains("setup complete"));
            assert!(hover.contains("running step 1"));
        }
    }

    mod wrap_line_tests {
        use super::super::wrap_line;

        #[test]
        fn short_line_unchanged() {
            assert_eq!(wrap_line("hello world", 80), vec!["hello world"]);
        }

        #[test]
        fn wraps_at_word_boundary() {
            assert_eq!(
                wrap_line("hello world foo bar", 12),
                vec!["hello world", "foo bar"]
            );
        }

        #[test]
        fn hard_breaks_long_words() {
            assert_eq!(
                wrap_line("abcdefghijklmnop", 8),
                vec!["abcdefgh", "ijklmnop"]
            );
        }

        #[test]
        fn empty_line() {
            assert_eq!(wrap_line("", 80), vec![""]);
        }

        #[test]
        fn exact_width() {
            assert_eq!(wrap_line("12345678", 8), vec!["12345678"]);
        }
    }
}
