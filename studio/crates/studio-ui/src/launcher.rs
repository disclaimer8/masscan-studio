//! The bundle signs this entry point; the GUI keeps its standalone signature so
//! the retained work host can verify and admit its exact executable hash.
#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::process::CommandExt;
    let gui = std::env::current_exe()?.with_file_name("studio-ui");
    Err(std::process::Command::new(gui)
        .args(std::env::args_os().skip(1))
        .exec()
        .into())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("studio-launcher is the macOS bundle entry point; run studio-ui directly here");
    std::process::exit(1);
}
