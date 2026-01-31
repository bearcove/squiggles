use std::collections::HashMap;

use facet::Facet;

/// Test configuration for a workspace or individual package.
///
/// This is the shared configuration type used both for workspace-wide
/// settings and per-package overrides.
#[derive(Facet, Debug, Clone, Default)]
pub struct TestConfig {
    /// Nextest filter expression (passed directly to -E).
    /// See https://nexte.st/docs/filtersets/ for syntax.
    /// Example: `not test(slow_) and not test(integration_)`
    #[facet(default)]
    pub filter: Option<String>,

    /// Cargo features to enable when building/testing.
    /// Example: `(feature1 feature2)`
    #[facet(default)]
    pub features: Option<Vec<String>>,

    /// Enable all features (--all-features).
    #[facet(default)]
    pub all_features: bool,

    /// Environment variables to set when running tests.
    /// Example: `{ RUST_LOG debug DATABASE_URL postgres://localhost/test }`
    #[facet(default)]
    pub env: Option<HashMap<String, String>>,
}

/// Squiggles configuration.
///
/// Projects must opt-in by creating `.config/squiggles/config.styx`.
/// Without a config file, squiggles does nothing.
///
/// There are two modes of operation:
/// - **Workspace mode**: Set `workspace { ... }` to run tests across the entire workspace.
/// - **Package mode**: Set `packages { ... }` to run tests only for specific packages.
///
/// These modes are mutually exclusive. If `packages` is defined, only those
/// packages will be tested (workspace-wide testing is disabled).
#[derive(Facet, Debug, Clone)]
pub struct Config {
    /// Whether squiggles is enabled. Defaults to false.
    #[facet(default)]
    pub enabled: bool,

    /// Workspace-wide test configuration.
    /// Use this to run tests across the entire workspace with shared settings.
    /// Mutually exclusive with `packages`.
    #[facet(default)]
    pub workspace: Option<TestConfig>,

    /// Per-package test configurations.
    /// Use this to run tests only for specific packages with individual settings.
    /// When set, only these packages will be tested (no workspace-wide testing).
    /// Mutually exclusive with `workspace`.
    #[facet(default)]
    pub packages: Option<HashMap<String, TestConfig>>,

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
    /// Example: `(vendor third_party editors)`
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

    /// Returns true if package mode is enabled (specific packages configured).
    pub fn is_package_mode(&self) -> bool {
        self.packages.is_some()
    }

    /// Get the workspace config if configured.
    pub fn effective_workspace_config(&self) -> Option<TestConfig> {
        self.workspace.clone()
    }

    /// Get the test config for a specific package.
    pub fn package_config(&self, package: &str) -> Option<&TestConfig> {
        self.packages.as_ref()?.get(package)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_config_defaults_to_disabled() {
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

    #[test]
    fn test_workspace_config() {
        let config: Config = facet_styx::from_str(
            r#"
            enabled true
            workspace {
                filter "not test(slow_)"
                features (feature1 feature2)
                all_features false
                env { RUST_LOG debug }
            }
            "#,
        )
        .unwrap();

        assert!(config.enabled);
        assert!(!config.is_package_mode());

        let ws = config.workspace.unwrap();
        assert_eq!(ws.filter, Some("not test(slow_)".to_string()));
        assert_eq!(
            ws.features,
            Some(vec!["feature1".to_string(), "feature2".to_string()])
        );
        assert!(!ws.all_features);
        assert_eq!(ws.env.unwrap().get("RUST_LOG"), Some(&"debug".to_string()));
    }

    #[test]
    fn test_packages_config() {
        let config: Config = facet_styx::from_str(
            r#"
            enabled true
            packages {
                my-crate {
                    filter "test(unit_)"
                    features (foo bar)
                }
                other-crate {
                    all_features true
                    env { DATABASE_URL postgres://localhost/test }
                }
            }
            "#,
        )
        .unwrap();

        assert!(config.enabled);
        assert!(config.is_package_mode());

        let my_crate = config.package_config("my-crate").unwrap();
        assert_eq!(my_crate.filter, Some("test(unit_)".to_string()));
        assert_eq!(
            my_crate.features,
            Some(vec!["foo".to_string(), "bar".to_string()])
        );

        let other_crate = config.package_config("other-crate").unwrap();
        assert!(other_crate.all_features);
        assert_eq!(
            other_crate.env.as_ref().unwrap().get("DATABASE_URL"),
            Some(&"postgres://localhost/test".to_string())
        );
    }
}
