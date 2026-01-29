//! Work done progress reporting for the LSP server.
//!
//! Handles creating progress tokens and sending progress notifications
//! for test runs and idle status.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tower_lsp::Client;
use tower_lsp::lsp_types::notification::Progress;
use tower_lsp::lsp_types::request::WorkDoneProgressCreate;
use tower_lsp::lsp_types::{
    NumberOrString, ProgressParams, ProgressParamsValue, ProgressToken, WorkDoneProgress,
    WorkDoneProgressBegin, WorkDoneProgressCreateParams, WorkDoneProgressEnd,
    WorkDoneProgressReport,
};

/// Counter for generating unique progress tokens.
static TOKEN_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a new unique progress token.
fn new_token() -> ProgressToken {
    let id = TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed);
    NumberOrString::String(format!("squiggles-{id}"))
}

/// A handle to an active progress indicator.
///
/// When dropped, the progress is automatically ended.
pub struct ProgressHandle {
    client: Client,
    token: ProgressToken,
    ended: AtomicBool,
}

impl ProgressHandle {
    /// Create a new progress indicator with the given title.
    ///
    /// This sends the `window/workDoneProgress/create` request followed by
    /// a Begin notification.
    pub async fn begin(client: Client, title: impl Into<String>, message: Option<String>) -> Self {
        let token = new_token();

        // Create the progress token
        let create_result = client
            .send_request::<WorkDoneProgressCreate>(WorkDoneProgressCreateParams {
                token: token.clone(),
            })
            .await;

        if let Err(e) = create_result {
            // Log but don't fail - some clients may not support progress
            tracing::debug!("Failed to create progress token: {e}");
        }

        // Send Begin notification
        client
            .send_notification::<Progress>(ProgressParams {
                token: token.clone(),
                value: ProgressParamsValue::WorkDone(WorkDoneProgress::Begin(
                    WorkDoneProgressBegin {
                        title: title.into(),
                        cancellable: Some(false),
                        message,
                        percentage: None,
                    },
                )),
            })
            .await;

        Self {
            client,
            token,
            ended: AtomicBool::new(false),
        }
    }

    /// Update the progress message.
    pub async fn report(&self, message: impl Into<String>) {
        self.client
            .send_notification::<Progress>(ProgressParams {
                token: self.token.clone(),
                value: ProgressParamsValue::WorkDone(WorkDoneProgress::Report(
                    WorkDoneProgressReport {
                        cancellable: Some(false),
                        message: Some(message.into()),
                        percentage: None,
                    },
                )),
            })
            .await;
    }

    /// Update the progress with a percentage.
    pub async fn report_percent(&self, message: impl Into<String>, percentage: u32) {
        self.client
            .send_notification::<Progress>(ProgressParams {
                token: self.token.clone(),
                value: ProgressParamsValue::WorkDone(WorkDoneProgress::Report(
                    WorkDoneProgressReport {
                        cancellable: Some(false),
                        message: Some(message.into()),
                        percentage: Some(percentage.min(100)),
                    },
                )),
            })
            .await;
    }

    /// End the progress indicator with a final message.
    ///
    /// This can be called on `&self` so it works with `Arc<ProgressHandle>`.
    pub async fn end(&self, message: Option<String>) {
        // Only send end once
        if self.ended.swap(true, Ordering::SeqCst) {
            return;
        }
        self.send_end(message).await;
    }

    async fn send_end(&self, message: Option<String>) {
        self.client
            .send_notification::<Progress>(ProgressParams {
                token: self.token.clone(),
                value: ProgressParamsValue::WorkDone(WorkDoneProgress::End(WorkDoneProgressEnd {
                    message,
                })),
            })
            .await;
    }
}

impl Drop for ProgressHandle {
    fn drop(&mut self) {
        if !self.ended.load(Ordering::SeqCst) {
            // We can't await in drop, so spawn a task
            let client = self.client.clone();
            let token = self.token.clone();
            tokio::spawn(async move {
                client
                    .send_notification::<Progress>(ProgressParams {
                        token,
                        value: ProgressParamsValue::WorkDone(WorkDoneProgress::End(
                            WorkDoneProgressEnd { message: None },
                        )),
                    })
                    .await;
            });
        }
    }
}
