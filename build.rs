use facet::Facet;
use facet_styx::GenerateSchema;

// Mirror the Config struct from src/config.rs for schema generation.
// Keep this in sync with the actual Config struct!
#[derive(Facet)]
struct Config {
    /// Whether squiggles is enabled. Defaults to false.
    #[facet(default)]
    enabled: bool,

    /// Test filter patterns to include (glob syntax).
    /// If empty/absent, all tests are included.
    /// Examples: `("tests::unit::*" "my_crate::*")`
    #[facet(default)]
    include: Option<Vec<String>>,

    /// Test filter patterns to exclude (glob syntax).
    /// Examples: `("tests::integration::*" "*::slow_*")`
    #[facet(default)]
    exclude: Option<Vec<String>>,

    /// Debounce delay in milliseconds after file save before running tests.
    /// Prevents rapid re-runs during burst saves.
    #[facet(default = 500)]
    debounce_ms: u32,

    /// Maximum number of test failures to report as diagnostics.
    /// Prevents flooding the editor with too many squiggles.
    #[facet(default = 50)]
    max_diagnostics: u32,
}

fn main() {
    GenerateSchema::<Config>::new()
        .crate_name("squiggles-config")
        .version("1")
        .write("config.schema.styx");
}
