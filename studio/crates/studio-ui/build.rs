fn main() {
    let style = match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => "cupertino",
        _ => "fluent",
    };
    // Geometry tests inspect controls even when Rust debug symbols are disabled.
    // Release packages omit this UI introspection metadata.
    let debug_ui = std::env::var("PROFILE").as_deref() == Ok("debug");
    slint_build::compile_with_config(
        "ui/main.slint",
        slint_build::CompilerConfiguration::new()
            .with_style(style.into())
            .with_debug_info(debug_ui),
    )
    .unwrap();
}
