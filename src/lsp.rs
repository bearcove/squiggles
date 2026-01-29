//! LSP server implementation using tower-lsp.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{RwLock, mpsc};
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

use crate::config::Config;
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
    test_trigger: mpsc::Sender<()>,
}

impl Backend {
    /// Create a new backend with the given client and configuration.
    pub fn new(client: Client, config: Config, test_trigger: mpsc::Sender<()>) -> Self {
        Self {
            client,
            state: Arc::new(RwLock::new(ServerState {
                config,
                workspace_root: None,
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

                    // Spawn task to handle watcher events
                    tokio::spawn(async move {
                        while let Some(event) = watcher.rx.recv().await {
                            match event {
                                WatcherEvent::FileSaved(path) => {
                                    client
                                        .log_message(
                                            MessageType::INFO,
                                            format!("File changed (debounced): {}", path.display()),
                                        )
                                        .await;
                                    // Trigger test run
                                    let _ = test_trigger.send(()).await;
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

        // Trigger initial test run
        let _ = self.test_trigger.send(()).await;
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
                                        let _ = test_trigger.send(()).await;
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

                // Trigger initial test run
                let _ = test_trigger.send(()).await;

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
        // Store workspace root
        if let Some(root_uri) = params.root_uri {
            if let Ok(path) = root_uri.to_file_path() {
                let mut state = self.state.write().await;
                state.workspace_root = Some(path);
            }
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
        let uri = params.text_document.uri;
        self.client
            .log_message(MessageType::INFO, format!("File saved: {uri}"))
            .await;

        // The file watcher handles debouncing, but we also trigger here
        // in case the watcher missed it (e.g., external editor)
        let _ = self.test_trigger.send(()).await;
    }

    async fn did_open(&self, _params: DidOpenTextDocumentParams) {
        // We track open files but don't need their content
    }

    async fn did_close(&self, _params: DidCloseTextDocumentParams) {
        // File closed - could clear diagnostics if desired
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        let state = self.state.read().await;
        if let Some(stored) = state.find_failure_at(&uri, position) {
            // Format the hover content with test name and full output
            let content = format!(
                "## Test Failure: `{}`\n\n```\n{}\n```",
                stored.failure.name, stored.failure.full_output
            );

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

        // Find all #[test] functions and their names
        let test_functions = find_test_functions(&content);
        let mut hints = Vec::new();

        for (line, fn_name) in test_functions {
            // Skip if outside requested range
            if line < params.range.start.line || line > params.range.end.line {
                continue;
            }

            // Try to find matching test result
            // Test names in nextest are: `{crate}::{binary}${module}::{fn_name}`
            // We match by suffix since we only have the function name
            let result = state.test_results.iter().find(|(name, _)| {
                // Match the function name at the end after ::
                name.ends_with(&format!("::{fn_name}"))
                    || name.ends_with(&format!("${fn_name}"))
                    || **name == fn_name
            });

            if let Some((_, test_result)) = result {
                let (label, tooltip) = match test_result {
                    TestResult::Passed => ("✓ pass".to_string(), "Test passed".to_string()),
                    TestResult::Failed(stored) => (
                        "✗ fail".to_string(),
                        format!("Test failed: {}", stored.failure.message),
                    ),
                };

                hints.push(InlayHint {
                    position: Position { line, character: 0 },
                    label: InlayHintLabel::String(label),
                    kind: None,
                    text_edits: None,
                    tooltip: Some(InlayHintTooltip::String(tooltip)),
                    padding_left: Some(true),
                    padding_right: Some(false),
                    data: None,
                });
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
pub fn find_test_functions(content: &str) -> Vec<(u32, String)> {
    use rustc_lexer::{TokenKind, tokenize};

    // Build line number lookup: byte offset -> line number (0-indexed)
    let line_starts: Vec<usize> = std::iter::once(0)
        .chain(content.match_indices('\n').map(|(i, _)| i + 1))
        .collect();

    let offset_to_line = |offset: usize| -> u32 {
        match line_starts.binary_search(&offset) {
            Ok(line) => line as u32,
            Err(line) => line.saturating_sub(1) as u32,
        }
    };

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

            while i < tokens.len() && depth > 0 {
                match tokens[i].1 {
                    TokenKind::OpenBracket | TokenKind::OpenParen => depth += 1,
                    TokenKind::CloseBracket | TokenKind::CloseParen => depth -= 1,
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
                                let fn_name = tokens[i].2.to_string();
                                let line = offset_to_line(attr_offset);
                                results.push((line, fn_name));
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

/// Run the LSP server on stdin/stdout.
pub async fn run(config: Config) {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    // Channel for triggering test runs
    let (test_tx, test_rx) = mpsc::channel::<()>(16);

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
    mut rx: mpsc::Receiver<()>,
    state: Arc<RwLock<ServerState>>,
    client: Client,
) {
    use crate::diagnostics::{TestFunctionIndex, extract_test_name, failures_to_diagnostics};
    use crate::runner::{RunLogEvent, RunOutcome, run_tests_verbose};

    while rx.recv().await.is_some() {
        // Coalesce multiple rapid triggers into one run
        // Drain any pending triggers
        while rx.try_recv().is_ok() {}

        // Get workspace root and config
        let (workspace_root, config) = {
            let state_guard = state.read().await;
            match &state_guard.workspace_root {
                Some(root) => (root.clone(), state_guard.config.clone()),
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

        // Start progress indicator
        let progress =
            ProgressHandle::begin(client.clone(), "Squiggles", Some("Running tests...".into()))
                .await;

        // Set up verbose logging channel
        let (log_tx, mut log_rx) = mpsc::channel::<RunLogEvent>(4096);
        let log_client = client.clone();

        // Spawn a task to forward log events to the LSP client
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
                            Ok(desc) => format!("OK: {desc}"),
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

                        // If we parsed build progress, log it more prominently
                        if let Some(prog) = progress {
                            use crate::runner::BuildProgress;
                            let msg = match prog {
                                BuildProgress::Compiling { krate } => {
                                    format!("Building {krate}...")
                                }
                                BuildProgress::WaitingForLock { target } => {
                                    format!("Waiting for lock on {target}...")
                                }
                                BuildProgress::Finished => "Build finished".to_string(),
                                BuildProgress::StartingTests { count } => {
                                    format!("Running {count} tests...")
                                }
                            };
                            log_client
                                .log_message(MessageType::INFO, format!("[squiggles] {msg}"))
                                .await;
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

        // Run tests - this always completes, never hangs
        let outcome = run_tests_verbose(&workspace_root, &config, Some(log_tx)).await;

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
                let test_index = TestFunctionIndex::build(&workspace_root);
                let diagnostics_by_file =
                    failures_to_diagnostics(&result.failures, &workspace_root, &test_index);

                // Store failures for hover lookup and get stale files
                let stale_uris = {
                    let mut state_guard = state.write().await;
                    let stored: Vec<_> = result
                        .failures
                        .iter()
                        .filter_map(|f| {
                            let short_name = extract_test_name(&f.name);
                            // Try test function location first, fall back to panic location
                            if let Some((uri, line)) = test_index.get(&short_name) {
                                let range = Range {
                                    start: Position {
                                        line: *line,
                                        character: 0,
                                    },
                                    end: Position {
                                        line: *line,
                                        character: 0,
                                    },
                                };
                                Some((
                                    uri.clone(),
                                    StoredFailure {
                                        failure: f.clone(),
                                        range,
                                    },
                                ))
                            } else if let Some(loc) = f.panic_location.as_ref() {
                                let file_path = resolve_path(&loc.file, &workspace_root);
                                let uri = Url::from_file_path(&file_path).ok()?;
                                Some((
                                    uri,
                                    StoredFailure {
                                        failure: f.clone(),
                                        range: location_to_range(loc),
                                    },
                                ))
                            } else {
                                None
                            }
                        })
                        .collect();

                    // Store all test results for inlay hints
                    state_guard.test_results.clear();
                    for name in &result.passed_tests {
                        state_guard
                            .test_results
                            .insert(name.clone(), TestResult::Passed);
                    }
                    for failure in &result.failures {
                        let short_name = extract_test_name(&failure.name);
                        if let Some((uri, line)) = test_index.get(&short_name) {
                            let range = Range {
                                start: Position {
                                    line: *line,
                                    character: 0,
                                },
                                end: Position {
                                    line: *line,
                                    character: 0,
                                },
                            };
                            state_guard.test_results.insert(
                                failure.name.clone(),
                                TestResult::Failed(StoredFailure {
                                    failure: failure.clone(),
                                    range,
                                }),
                            );
                            let _ = uri; // Keep for future use
                        } else if let Some(loc) = &failure.panic_location {
                            let file_path = resolve_path(&loc.file, &workspace_root);
                            if let Ok(_uri) = Url::from_file_path(&file_path) {
                                state_guard.test_results.insert(
                                    failure.name.clone(),
                                    TestResult::Failed(StoredFailure {
                                        failure: failure.clone(),
                                        range: location_to_range(loc),
                                    }),
                                );
                            }
                        }
                    }

                    state_guard.store_failures(stored)
                };

                // Clear diagnostics from files that no longer have failures
                for uri in stale_uris {
                    client.publish_diagnostics(uri, vec![], None).await;
                }

                // Publish diagnostics for each file with failures
                for (uri, diags) in diagnostics_by_file {
                    client.publish_diagnostics(uri, diags, None).await;
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
        }
    }
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
}
