use zed_extension_api::{self as zed, Command, LanguageServerId, Result, Worktree};

struct SquigglesExtension;

impl zed::Extension for SquigglesExtension {
    fn new() -> Self {
        SquigglesExtension
    }

    fn language_server_command(
        &mut self,
        _language_server_id: &LanguageServerId,
        worktree: &Worktree,
    ) -> Result<Command> {
        // Look for 'squiggles' in PATH or in the workspace
        let path = worktree.which("squiggles").ok_or_else(|| {
            "squiggles not found in PATH. Install with `cargo install squiggles` or add it to PATH.".to_string()
        })?;

        Ok(Command {
            command: path,
            args: vec![],
            env: vec![],
        })
    }
}

zed::register_extension!(SquigglesExtension);
