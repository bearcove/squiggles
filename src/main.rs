use facet::Facet;
use facet_styx::StyxFormat;
use figue as args;

mod config;
mod diagnostics;
mod lsp;
mod nextest;
mod runner;
mod watcher;

use config::Config;

/// Surfaces test failures as editor diagnostics.
#[derive(Facet, Debug)]
struct Args {
    #[facet(flatten)]
    builtins: args::FigueBuiltins,

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

    // Start the LSP server
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
        .block_on(lsp::run(args.config));
}
