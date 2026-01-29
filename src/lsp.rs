//! LSP server implementation using tower-lsp.

use std::sync::Arc;

use tokio::sync::RwLock;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

use crate::config::Config;

/// Shared state for the LSP server.
pub struct ServerState {
    /// Configuration loaded at startup.
    pub config: Config,
    /// Workspace root path (set during initialization).
    pub workspace_root: Option<std::path::PathBuf>,
}

/// The squiggles LSP backend.
pub struct Backend {
    /// LSP client for sending notifications/requests to the editor.
    client: Client,
    /// Shared server state.
    state: Arc<RwLock<ServerState>>,
}

impl Backend {
    /// Create a new backend with the given client and configuration.
    pub fn new(client: Client, config: Config) -> Self {
        Self {
            client,
            state: Arc::new(RwLock::new(ServerState {
                config,
                workspace_root: None,
            })),
        }
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

        // TODO: Start file watcher
        // TODO: Run initial test pass
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

        // TODO: Trigger debounced test run
    }

    async fn did_open(&self, _params: DidOpenTextDocumentParams) {
        // We track open files but don't need their content
    }

    async fn did_close(&self, _params: DidCloseTextDocumentParams) {
        // File closed - could clear diagnostics if desired
    }

    async fn hover(&self, _params: HoverParams) -> Result<Option<Hover>> {
        // TODO: Return full panic output for diagnostics at this location
        Ok(None)
    }
}

/// Run the LSP server on stdin/stdout.
pub async fn run(config: Config) {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(|client| Backend::new(client, config));
    Server::new(stdin, stdout, socket).serve(service).await;
}
