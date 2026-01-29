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
use crate::watcher::{FileWatcher, WatcherEvent};

/// A stored failure for hover lookup.
#[derive(Debug, Clone)]
pub struct StoredFailure {
    /// The test failure data.
    pub failure: TestFailure,
    /// The range in the file where the diagnostic appears.
    pub range: Range,
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
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "squiggles".to_string(),
                version: option_env!("CARGO_PKG_VERSION").map(|s| s.to_string()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
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
    use crate::diagnostics::failures_to_diagnostics;
    use crate::runner::run_tests;

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

        client
            .log_message(MessageType::INFO, "Running tests...")
            .await;

        // Run tests
        match run_tests(&workspace_root, &config).await {
            Ok(result) => {
                client
                    .log_message(
                        MessageType::INFO,
                        format!(
                            "Tests complete: {} passed, {} failed (of {} total)",
                            result.passed, result.failed, result.total
                        ),
                    )
                    .await;

                // Convert failures to diagnostics
                let diagnostics_by_file =
                    failures_to_diagnostics(&result.failures, &workspace_root);

                // Store failures for hover lookup and get stale files
                let stale_uris = {
                    let mut state_guard = state.write().await;
                    let stored: Vec<_> = result
                        .failures
                        .iter()
                        .filter_map(|f| {
                            let loc = f.panic_location.as_ref()?;
                            let file_path = resolve_path(&loc.file, &workspace_root);
                            let uri = Url::from_file_path(&file_path).ok()?;
                            Some((
                                uri,
                                StoredFailure {
                                    failure: f.clone(),
                                    range: location_to_range(loc),
                                },
                            ))
                        })
                        .collect();
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

                if result.failures.is_empty() {
                    client
                        .log_message(MessageType::INFO, "All tests passing!")
                        .await;
                }
            }
            Err(e) => {
                client
                    .log_message(MessageType::ERROR, format!("Test run failed: {e}"))
                    .await;
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
