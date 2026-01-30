use facet::Facet;

/// Squiggles configuration.
///
/// Projects must opt-in by creating `.config/squiggles/config.styx`.
/// Without a config file, squiggles does nothing.
#[derive(Facet, Debug, Clone)]
pub struct Config {
    /// Whether squiggles is enabled. Defaults to false.
    #[facet(default)]
    pub enabled: bool,

    /// Nextest filter expression (passed directly to -E).
    /// See https://nexte.st/docs/filtersets/ for syntax.
    /// Example: `"not test(slow_) and not test(integration)"`
    #[facet(default)]
    pub filter: Option<String>,

    /// Debounce delay in milliseconds after file save before running tests.
    /// Prevents rapid re-runs during burst saves.
    #[facet(default = 500)]
    pub debounce_ms: u32,

    /// Maximum number of test failures to report as diagnostics.
    /// Prevents flooding the editor with too many squiggles.
    #[facet(default = 50)]
    pub max_diagnostics: u32,

    /// Use captain's shared target directory (~/.captain/target).
    /// This avoids lock contention with rust-analyzer and shares
    /// build artifacts across projects.
    #[facet(default)]
    pub captain: bool,

    /// Directory patterns to exclude from scanning for test functions.
    /// Use this to skip vendored code, submodules, or other directories
    /// that contain duplicate test function names.
    /// Patterns are matched against directory names (not full paths).
    /// Examples: `("vendor" "third_party" "editors")`
    #[facet(default)]
    pub scan_exclude: Option<Vec<String>>,
}

impl Config {
    /// Get the target directory to use, if captain mode is enabled.
    pub fn target_dir(&self) -> Option<std::path::PathBuf> {
        if self.captain {
            dirs::home_dir().map(|home| home.join(".captain/target"))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_config_defaults_to_disabled() {
        // Styx config files are just key-value pairs at the top level
        let config: Config = facet_styx::from_str("").unwrap();
        assert!(!config.enabled, "enabled should default to false");
    }

    #[test]
    fn test_enabled_true() {
        let config: Config = facet_styx::from_str("enabled true").unwrap();
        assert!(config.enabled);
    }

    #[test]
    fn test_enabled_false() {
        let config: Config = facet_styx::from_str("enabled false").unwrap();
        assert!(!config.enabled);
    }
}
