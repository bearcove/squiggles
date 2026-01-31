//! File system watcher with debouncing.
//!
//! Watches for file saves and triggers test runs after a configurable debounce period.

use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

/// Events sent from the file watcher to the LSP backend.
#[derive(Debug)]
pub enum WatcherEvent {
    /// A file was saved (after debounce period).
    FileSaved(PathBuf),
    /// An error occurred in the watcher.
    Error(notify::Error),
}

/// A debounced file watcher.
pub struct FileWatcher {
    _watcher: RecommendedWatcher,
    /// Receiver for watcher events (debounced).
    pub rx: mpsc::Receiver<WatcherEvent>,
}

impl FileWatcher {
    /// Create a new file watcher for the given root directory.
    ///
    /// The watcher will debounce file save events, waiting `debounce_ms` after
    /// the last save before emitting an event.
    pub fn new(root: &Path, debounce_ms: u32) -> Result<Self, notify::Error> {
        let (tx, rx) = mpsc::channel(32);
        let debounce_duration = Duration::from_millis(debounce_ms as u64);

        // Channel for raw notify events
        let (raw_tx, mut raw_rx) = mpsc::channel::<notify::Result<Event>>(64);

        // Create the watcher
        let watcher = notify::recommended_watcher(move |res| {
            let _ = raw_tx.blocking_send(res);
        })?;

        // Spawn debounce task
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            debounce_loop(&mut raw_rx, tx_clone, debounce_duration).await;
        });

        let mut file_watcher = FileWatcher {
            _watcher: watcher,
            rx,
        };

        // Start watching
        file_watcher
            ._watcher
            .watch(root, RecursiveMode::Recursive)?;

        Ok(file_watcher)
    }
}

/// Debounce loop that coalesces file events.
///
/// After receiving a file modification event, waits for `debounce` duration
/// without any new events before emitting. If more events arrive during the
/// wait, the timer resets.
async fn debounce_loop(
    raw_rx: &mut mpsc::Receiver<notify::Result<Event>>,
    tx: mpsc::Sender<WatcherEvent>,
    debounce: Duration,
) {
    use std::collections::HashSet;

    let mut pending_files: HashSet<PathBuf> = HashSet::new();
    let mut debounce_timer: Option<tokio::time::Instant> = None;

    loop {
        tokio::select! {
            // Check for new events from notify
            event = raw_rx.recv() => {
                match event {
                    Some(Ok(ev)) => {
                        if let Some(paths) = extract_saved_paths(&ev) {
                            for path in paths {
                                // Watch Rust files and the squiggles config file
                                if is_rust_file(&path) || is_config_file(&path) {
                                    pending_files.insert(path);
                                }
                            }
                            if !pending_files.is_empty() {
                                // Reset debounce timer
                                debounce_timer = Some(tokio::time::Instant::now() + debounce);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        let _ = tx.send(WatcherEvent::Error(e)).await;
                    }
                    None => {
                        // Channel closed, exit
                        break;
                    }
                }
            }

            // Check if debounce period has elapsed
            _ = async {
                if let Some(deadline) = debounce_timer {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    // No timer set, wait forever (will be interrupted by event)
                    std::future::pending::<()>().await;
                }
            }, if debounce_timer.is_some() => {
                // Debounce period elapsed, emit events for all pending files
                for path in pending_files.drain() {
                    let _ = tx.send(WatcherEvent::FileSaved(path)).await;
                }
                debounce_timer = None;
            }
        }
    }
}

/// Extract paths from a notify event if it represents a file save.
fn extract_saved_paths(event: &Event) -> Option<Vec<PathBuf>> {
    match event.kind {
        // File was modified (save)
        EventKind::Modify(notify::event::ModifyKind::Data(_)) => Some(event.paths.clone()),
        // File was created (new file)
        EventKind::Create(notify::event::CreateKind::File) => Some(event.paths.clone()),
        _ => None,
    }
}

/// Check if a path is a Rust source file.
fn is_rust_file(path: &Path) -> bool {
    path.extension().map(|ext| ext == "rs").unwrap_or(false)
}

/// Check if a path is the squiggles config file.
fn is_config_file(path: &Path) -> bool {
    path.ends_with(".config/squiggles/config.styx")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_rust_file() {
        assert!(is_rust_file(Path::new("src/main.rs")));
        assert!(is_rust_file(Path::new("lib.rs")));
        assert!(!is_rust_file(Path::new("Cargo.toml")));
        assert!(!is_rust_file(Path::new("README.md")));
        assert!(!is_rust_file(Path::new("no_extension")));
    }

    #[test]
    fn test_is_config_file() {
        assert!(is_config_file(Path::new(
            "/home/user/project/.config/squiggles/config.styx"
        )));
        assert!(is_config_file(Path::new(".config/squiggles/config.styx")));
        assert!(!is_config_file(Path::new("config.styx")));
        assert!(!is_config_file(Path::new(".config/other/config.styx")));
        assert!(!is_config_file(Path::new("src/main.rs")));
    }
}
