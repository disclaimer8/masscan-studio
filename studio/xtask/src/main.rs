use sha2::{Digest, Sha256};
#[cfg(target_os = "macos")]
mod feth_acceptance;
#[cfg(target_os = "linux")]
mod linux_acceptance;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod runner_setup;
#[cfg(windows)]
#[path = "runner_setup_windows.rs"]
mod runner_setup;
#[cfg(windows)]
mod windows_acceptance;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd.status()?;
    if !status.success() {
        return Err(format!("{cmd:?} failed: {status}").into());
    }
    Ok(())
}
fn text(cmd: &mut Command) -> Result<String> {
    let o = cmd.output()?;
    if !o.status.success() {
        return Err(String::from_utf8_lossy(&o.stderr).into_owned().into());
    }
    Ok(String::from_utf8(o.stdout)?.trim().into())
}
fn digest(path: &Path) -> Result<String> {
    Ok(Sha256::digest(fs::read(path)?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
fn main() -> Result<()> {
    let task = std::env::args().nth(1).unwrap_or("build".into());
    #[cfg(windows)]
    let packaged = std::env::current_exe()?
        .file_name()
        .is_some_and(|n| n == "studio-tools.exe");
    #[cfg(not(windows))]
    let packaged = false;
    if packaged
        && (!matches!(
            task.as_str(),
            "prepare-runner" | "verify-installed-runner" | "probe-windows-authorization"
        ) || std::env::args().nth(2).is_none())
    {
        return Err("Usage: studio-tools.exe prepare-runner PATH | verify-installed-runner HASH | probe-windows-authorization HASH".into());
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned();
    let root = if packaged {
        std::env::current_dir()?
    } else {
        root
    };
    std::env::set_current_dir(&root)?;
    match task.as_str() {
        #[cfg(any(target_os="macos", target_os="linux", windows))]
        "prepare-runner" => runner_setup::prepare(&root)?,
        #[cfg(windows)]
        "verify-installed-runner" => runner_setup::verify_installed()?,
        #[cfg(windows)]
        "verify-windows-installation" => runner_setup::verify_ci(&root)?,
        #[cfg(windows)]
        "probe-windows-token" => windows_acceptance::token_probe()?,
        #[cfg(windows)]
        "verify-windows-elevated-entry" => windows_acceptance::guard_probe(&root)?,
        #[cfg(windows)]
        "verify-windows-uac" => windows_acceptance::verify_uac(&root)?,
        #[cfg(windows)]
        "prepare-windows-uac-tests" => windows_acceptance::package_tests(&root)?,
        #[cfg(windows)]
        "windows-uac-cancel-fixture" => windows_acceptance::cancel_fixture()?,
        #[cfg(windows)]
        "windows-uac-fixture" | "probe-windows-authorization" => windows_acceptance::uac_fixture()?,
        #[cfg(windows)]
        "windows-limited-token-fixture" => windows_acceptance::token_fixture()?,
        #[cfg(target_os = "macos")]
        "feth-acceptance" => {
            let code = feth_acceptance::main_entry()?;
            if code != 0 {
                std::process::exit(code);
            }
        }
        #[cfg(any(target_os="macos", target_os="linux"))]
        "install-runner" => runner_setup::install()?,
        #[cfg(any(target_os="macos", target_os="linux"))]
        "probe-authorization" => runner_setup::probe()?,
        #[cfg(target_os="linux")]
        "verify-linux-authorization" => linux_acceptance::verify(&root)?,
        #[cfg(target_os="linux")]
        "linux-authorization-owner-fixture" => linux_acceptance::owner_fixture()?,
        "test" => {
            #[cfg(windows)]
            if studio_platform::windows::Process::open(std::process::id())?.elevation()?.elevated {
                if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
                    return Err("Run application tests from an ordinary terminal, not as Administrator".into());
                }
                return windows_acceptance::limited(&["test"]);
            }
            run(Command::new("cargo").args(["test", "--locked", "--workspace", "--all-targets", "--no-fail-fast"]))?;
            run(Command::new("cargo").args([
                "clippy",
                "--locked",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ]))?;
            run(Command::new("cargo").args(["fmt", "--all", "--check"]))?;
        }
        "build" | "package" => {
            let release = std::env::args().any(|a| a == "--release");
            let mut cmd = Command::new("cargo");
            cmd.args([
                "build",
                "--locked",
                "-p",
                "studio-ui",
                "-p",
                "studio-runner",
                "-p",
                "studio-inspection",
            ]);
            if release {
                cmd.arg("--release");
            }
            run(&mut cmd)?;
            let target = std::env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join("target"))
                .join(if release { "release" } else { "debug" });
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis();
            let dist = root.join("dist").join(format!("build-{stamp}"));
            fs::create_dir_all(&dist)?;
            let mut files = Vec::new();
            if cfg!(target_os = "macos") {
                let bundle = dist.join("Masscan Studio.app");
                let macos = bundle.join("Contents/MacOS");
                fs::create_dir_all(&macos)?;
                for name in ["studio-ui", "studio-runner", "studio-inspect"] {
                    let dst = macos.join(name);
                    fs::copy(target.join(name), &dst)?;
                    files.push(dst);
                }
                fs::write(
                    bundle.join("Contents/Info.plist"),
                    r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleExecutable</key><string>studio-ui</string><key>CFBundleIdentifier</key><string>dev.masscanstudio.rust</string><key>CFBundleName</key><string>Masscan Studio</string><key>CFBundleVersion</key><string>1</string><key>CFBundleShortVersionString</key><string>0.1.0</string><key>CFBundlePackageType</key><string>APPL</string><key>LSMinimumSystemVersion</key><string>14.0</string><key>NSHighResolutionCapable</key><true/></dict></plist>"#,
                )?;
                let deps = text(Command::new("otool").arg("-L").arg(macos.join("studio-ui")))?;
                if let Some(sqlite) = deps
                    .lines()
                    .filter_map(|l| l.split_whitespace().next())
                    .find(|p| p.contains("libsqlite3") && !p.starts_with("/usr/lib/"))
                {
                    let framework = bundle.join("Contents/Frameworks");
                    fs::create_dir_all(&framework)?;
                    let dest = framework.join("libsqlite3.0.dylib");
                    fs::copy(sqlite, &dest)?;
                    run(Command::new("install_name_tool")
                        .args(["-id", "@rpath/libsqlite3.0.dylib"])
                        .arg(&dest))?;
                    run(Command::new("install_name_tool")
                        .args([
                            "-change",
                            sqlite,
                            "@executable_path/../Frameworks/libsqlite3.0.dylib",
                        ])
                        .arg(macos.join("studio-ui")))?;
                    run(Command::new("codesign")
                        .args(["--force", "--sign", "-", "--timestamp=none"])
                        .arg(&dest))?;
                    files.push(dest);
                }
                // Fresh copies/inodes and signing only after every Mach-O change avoid taskgated's stale signatures.
                for name in ["studio-runner", "studio-inspect", "studio-ui"] {
                    run(Command::new("codesign")
                        .args(["--force", "--sign", "-", "--timestamp=none"])
                        .arg(macos.join(name)))?;
                }
                run(Command::new("codesign")
                    .args(["--force", "--sign", "-", "--timestamp=none"])
                    .arg(&bundle))?;
                run(Command::new("codesign")
                    .args(["--verify", "--deep", "--strict", "--verbose=2"])
                    .arg(&bundle))?;
                println!("App: {}", bundle.display());
            } else {
                for name in ["studio-ui", "studio-runner", "studio-inspect"] {
                    let name = format!("{name}{}", std::env::consts::EXE_SUFFIX);
                    let dst = dist.join(&name);
                    fs::copy(target.join(&name), &dst)?;
                    files.push(dst);
                }
                if cfg!(windows) {
                    let dir = std::env::var_os("SQLITE3_LIB_DIR").ok_or(
                        "Set SQLITE3_LIB_DIR to the verified external SQLite DLL/import library",
                    )?;
                    let dest = dist.join("sqlite3.dll");
                    fs::copy(PathBuf::from(dir).join("sqlite3.dll"), &dest)?;
                    files.push(dest);
                    // Standalone installation/probe utility: does not need Cargo
                    // or the source checkout on the acceptance machine.
                    let tool = dist.join("studio-tools.exe");
                    fs::copy(std::env::current_exe()?, &tool)?;
                    files.push(tool);
                }
            }
            let file_hashes=files.iter().map(|p|Ok(serde_json::json!({"path":p.strip_prefix(&dist)?.to_string_lossy(),"sha256":digest(p)?}))).collect::<Result<Vec<_>>>()?;
            let provenance = serde_json::json!({"source_commit":text(Command::new("git").args(["rev-parse","HEAD"]))?,"dirty":!text(Command::new("git").args(["status","--porcelain"]))?.is_empty(),"cargo_lock_sha256":digest(&root.join("Cargo.lock"))?,"platform":std::env::consts::OS,"arch":std::env::consts::ARCH,"profile":if release{"release"}else{"debug"},"files":file_hashes});
            fs::write(
                dist.join("manifest.json"),
                serde_json::to_vec_pretty(&provenance)?,
            )?;
            println!("Artifacts: {}", dist.display());
        }
        _ => return Err("Usage: cargo xtask build [--release] | test | prepare-runner [PATH] | install-runner DIR | probe-authorization PATH (macOS/Linux) | feth-acceptance --out DIR --app APP --lab LAB [--manual] [--dry-run] (macOS) | verify-installed-runner HASH (Windows; install via reviewed install.ps1)".into()),
    }
    Ok(())
}
