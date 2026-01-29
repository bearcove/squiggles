// Re-export config from squiggles-config crate
pub use squiggles_config::Config;

// Embed the schema for the config file (generated from Config in build.rs).
// This allows tooling to discover the schema from the binary.
styx_embed::embed_outdir_file!("config.schema.styx");
