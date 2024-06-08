use lib_flutter_rust_bridge_codegen::codegen;
use lib_flutter_rust_bridge_codegen::codegen::Config;

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=src/api");

    codegen::generate(
        Config::from_config_file("./flutter/flutter_rust_bridge.yaml")?.unwrap(),
        Default::default(),
    )
}
