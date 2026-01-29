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

    /// Test filter patterns to include (glob syntax).
    /// If empty/absent, all tests are included.
    /// Examples: `("tests::unit::*" "my_crate::*")`
    #[facet(default)]
    pub include: Option<Vec<String>>,

    /// Test filter patterns to exclude (glob syntax).
    /// Examples: `("tests::integration::*" "*::slow_*")`
    #[facet(default)]
    pub exclude: Option<Vec<String>>,

    /// Debounce delay in milliseconds after file save before running tests.
    /// Prevents rapid re-runs during burst saves.
    #[facet(default = 500)]
    pub debounce_ms: u32,

    /// Maximum number of test failures to report as diagnostics.
    /// Prevents flooding the editor with too many squiggles.
    #[facet(default = 50)]
    pub max_diagnostics: u32,
}
