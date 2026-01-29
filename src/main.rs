use facet::Facet;
use facet_styx::StyxFormat;
use figue as args;

mod config;

use config::Config;

/// Squiggles - Continuous Cargo Test LSP
///
/// Surfaces test failures as editor diagnostics.
#[derive(Facet, Debug)]
struct Args {
    /// Standard CLI options (--help, --version)
    #[facet(flatten)]
    builtins: args::FigueBuiltins,

    /// Configuration (from .config/squiggles/config.styx)
    #[facet(args::config, args::env_prefix = "SQUIGGLES")]
    config: Config,
}

fn main() {
    let figue_config = args::builder::<Args>()
        .expect("failed to create figue builder")
        .cli(|c| c.strict())
        .env(|e| e.strict())
        .file(|f| {
            f.strict()
                .format(StyxFormat)
                .default_paths([".config/squiggles/config.styx"])
        })
        .help(|h| {
            h.program_name("squiggles")
                .description("Continuous Cargo Test LSP - surfaces test failures as diagnostics")
                .version(option_env!("CARGO_PKG_VERSION").unwrap_or("dev"))
        })
        .build();

    let args = args::Driver::new(figue_config).run().unwrap();

    if !args.config.enabled {
        eprintln!("squiggles: not enabled (no config file or enabled = false)");
        eprintln!("hint: create .config/squiggles/config.styx with:");
        eprintln!("  {{enabled true}}");
        return;
    }

    println!("Config loaded: {:#?}", args.config);

    // TODO: Start LSP server
}
