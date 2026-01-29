use facet_styx::GenerateSchema;
use squiggles_config::Config;

fn main() {
    GenerateSchema::<Config>::new()
        .crate_name("squiggles-config")
        .version("1")
        .write("config.schema.styx");
}
