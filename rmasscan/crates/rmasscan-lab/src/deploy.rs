//! Provenance of the pieces a live Windows rerun depends on (review W I8): the Linux
//! `rmasscan-lab` on home-pc, the guest scripts, and the clocks. Everything here is pure or
//! reads local files; the suite wires it to the remote stand through its `Exec` seam.
//!
//! Trust anchor: the deploy manifest is kept on the orchestrating machine and passed to the
//! suite with `--deploy-manifest`. The binary that the suite is about to run as root on home-pc
//! must hash to a value listed in it, so a rebuilt, replaced or tampered remote binary is
//! refused before it is executed. A manifest stored next to the binary on home-pc would prove
//! nothing, which is why the suite never reads one from there.
use crate::windows_suite::{epoch, safe_id, write_json};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

pub const MANIFEST_KIND: &str = "rmasscan-lab-deploy";
/// Directory of the guest scripts in the repository, relative to the repository root.
pub(crate) const SCRIPTS_IN_REPO: &str = "rmasscan/scripts";
/// Guest scripts the suite copies, each as (file name in the repository, path under the lab
/// user's home on the guest, forward slashes). All of them are taken from the tree of the
/// commit under test; none is a compile-time path.
pub(crate) const GUEST_SCRIPTS: &[(&str, &str)] = &[
    ("windows_wire_hash.ps1", "t4/windows_wire_hash.ps1"),
    ("windows_wire_prepare.ps1", "t4/windows_wire_prepare.ps1"),
    ("windows_wire_clock.ps1", "t4/windows_wire_clock.ps1"),
    ("windows_wire_run.ps1", "t4/windows_wire_run.ps1"),
    ("windows_wire_runas.cmd", "t4/windows_wire_runas.cmd"),
    (
        "windows_wire_restricted.cmd",
        "t4/windows_wire_restricted.cmd",
    ),
    ("windows-vm-lab.ps1", "windows-vm-lab.ps1"),
];

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub(crate) fn full_commit(c: &str) -> bool {
    c.len() == 40 && c.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The manifest a build on home-pc records: which commit was built and the hash of the
/// installed binary.
pub fn build_manifest(
    commit: &str,
    binary_path: &str,
    binary: &[u8],
    toolchain: &str,
    built_utc: f64,
) -> Value {
    json!({
        "schema": 1,
        "kind": MANIFEST_KIND,
        "commit": commit,
        "built_utc": built_utc,
        "toolchain": toolchain,
        "binaries": [{
            "path": binary_path,
            "sha256": sha256_hex(binary),
            "size": binary.len(),
        }],
    })
}

/// The sha256 values the manifest allows for the binary at `remote`, or the reason it cannot
/// be used for `commit`.
pub(crate) fn allowed_binary_hashes(
    manifest: &Value,
    commit: &str,
    remote: &str,
) -> Result<Vec<String>, String> {
    if manifest["kind"] != MANIFEST_KIND || manifest["schema"] != 1 {
        return Err("deploy manifest: unknown kind or schema".into());
    }
    let built = manifest["commit"].as_str().unwrap_or("");
    if !full_commit(built) || built != commit {
        return Err(format!(
            "deploy manifest was recorded for commit {built:?}, not for --commit {commit}"
        ));
    }
    let hashes: Vec<String> = manifest["binaries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|b| b["path"] == remote)
        .filter_map(|b| b["sha256"].as_str())
        .filter(|h| h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
        .collect();
    if hashes.is_empty() {
        return Err(format!(
            "deploy manifest lists no binary at --remote-lab {remote}"
        ));
    }
    Ok(hashes)
}

/// First whitespace-separated token of `sha256sum` output, validated.
pub(crate) fn parse_sha256sum(stdout: &str) -> Result<String, String> {
    let h = stdout.split_whitespace().next().unwrap_or("");
    if h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit()) {
        Ok(h.to_ascii_lowercase())
    } else {
        Err("could not read the sha256 of the remote binary".into())
    }
}

pub(crate) fn check_remote_binary(allowed: &[String], actual: &str) -> Result<(), String> {
    if allowed.iter().any(|a| a == actual) {
        Ok(())
    } else {
        Err(format!(
            "remote rmasscan-lab sha256 {actual} is not in the deploy manifest; rebuild it from the commit and record a new manifest"
        ))
    }
}

/// Result of comparing the two clocks.
#[derive(Debug, PartialEq)]
pub(crate) struct ClockReading {
    /// Guest minus home-pc, seconds, midpoint estimate (positive: guest ahead).
    pub offset: f64,
    /// Half the round trip of the home-pc readings that bracket the guest reading.
    pub uncertainty: f64,
}

/// `record-guest` accepts a guest Verify report at most `VERIFY_FUTURE_SKEW_S` ahead of and
/// `VERIFY_MAX_AGE_S` behind the home-pc clock. The preflight refuses a pair of clocks that
/// could break either bound, taking the measurement uncertainty against the clocks.
pub(crate) fn clock_verdict(
    home_before: f64,
    guest: f64,
    home_after: f64,
) -> Result<ClockReading, String> {
    if !(home_before.is_finite() && guest.is_finite() && home_after.is_finite())
        || home_after < home_before
    {
        return Err("clock readings are not usable".into());
    }
    let reading = ClockReading {
        offset: guest - (home_before + home_after) / 2.0,
        uncertainty: (home_after - home_before) / 2.0,
    };
    let ahead = reading.offset + reading.uncertainty;
    let behind = -(reading.offset - reading.uncertainty);
    if ahead > crate::vm_lab::VERIFY_FUTURE_SKEW_S {
        return Err(format!(
            "guest clock is {ahead:.1} s ahead of home-pc (limit +{} s); fix time sync before a raw run",
            crate::vm_lab::VERIFY_FUTURE_SKEW_S
        ));
    }
    if behind > crate::vm_lab::VERIFY_MAX_AGE_S {
        return Err(format!(
            "guest clock is {behind:.1} s behind home-pc (limit -{} s); fix time sync before a raw run",
            crate::vm_lab::VERIFY_MAX_AGE_S
        ));
    }
    Ok(reading)
}

pub(crate) fn parse_epoch(stdout: &str) -> Result<f64, String> {
    stdout
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && *v > 1.0e9)
        .ok_or_else(|| format!("unreadable clock output {:?}", stdout.trim()))
}

const HELP: &str = "deploy-manifest --commit SHA --binary /absolute/installed/rmasscan-lab --out FILE [--toolchain TEXT]\n  Run on home-pc after building the commit. Records the commit and the sha256 of the installed binary.\n  Copy FILE to the orchestrating machine and pass it to windows-suite with --deploy-manifest.";

/// `rmasscan-lab deploy-manifest`: write the manifest of an installed binary.
pub fn run(args: &[String]) -> Result<i32, String> {
    let o = crate::windows_suite::options_for(
        "deploy-manifest",
        args,
        &["commit", "binary", "out", "toolchain"],
    )?;
    if o.contains_key("help") {
        println!("{HELP}");
        return Ok(0);
    }
    let commit = crate::windows_suite::required(&o, "commit")?;
    if !full_commit(&commit) {
        return Err("--commit requires the full 40-hex SHA".into());
    }
    let binary = crate::windows_suite::required(&o, "binary")?;
    if !binary.starts_with('/') || binary.contains('\n') || !binary.bytes().all(|b| b != 0) {
        return Err("--binary must be an absolute path".into());
    }
    let out = crate::windows_suite::required(&o, "out")?;
    let toolchain = crate::windows_suite::opt(&o, "toolchain", "");
    if !toolchain.is_empty() && toolchain.len() > 200 {
        return Err("--toolchain is too long".into());
    }
    let bytes = fs::read(&binary).map_err(|e| format!("{binary}: {e}"))?;
    if bytes.is_empty() {
        return Err("the binary is empty".into());
    }
    let manifest = build_manifest(&commit, &binary, &bytes, &toolchain, epoch());
    write_json(&out, &manifest)?;
    println!("{}  {binary}", sha256_hex(&bytes));
    Ok(0)
}

/// Staged copy of the guest scripts, read from the tree of `commit`.
pub(crate) struct StagedScripts {
    /// (repository file name, guest path under the lab home, content, sha256)
    pub files: Vec<(String, String, Vec<u8>, String)>,
}

impl StagedScripts {
    /// `read(path)` returns the bytes of `path` (relative to the repository root) in the tree
    /// of the commit under test.
    pub(crate) fn load(read: impl Fn(&str) -> Result<Vec<u8>, String>) -> Result<Self, String> {
        let mut files = Vec::new();
        for (name, guest) in GUEST_SCRIPTS {
            let bytes = read(&format!("{SCRIPTS_IN_REPO}/{name}"))
                .map_err(|e| format!("guest script {name} is not readable at --commit: {e}"))?;
            if bytes.is_empty() {
                return Err(format!("guest script {name} is empty at --commit"));
            }
            let sha = sha256_hex(&bytes);
            files.push(((*name).to_string(), (*guest).to_string(), bytes, sha));
        }
        Ok(Self { files })
    }

    /// Write the scripts under `dir` (kept as evidence) and return the local path of each.
    pub(crate) fn write_to(&self, dir: &Path) -> Result<(), String> {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        for (name, _, bytes, _) in &self.files {
            debug_assert!(safe_id(name));
            fs::write(dir.join(name), bytes).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub(crate) fn record(&self) -> Value {
        let mut m = serde_json::Map::new();
        for (name, guest, bytes, sha) in &self.files {
            m.insert(
                name.clone(),
                json!({"guest_path": format!("C:\\Users\\lab\\{}", guest.replace('/', "\\")), "sha256": sha, "size": bytes.len()}),
            );
        }
        Value::Object(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn the_manifest_records_commit_path_and_the_exact_hash() {
        let m = build_manifest(
            C,
            "/home/a1/winvm/lab/rmasscan-lab",
            b"binary",
            "rustc 1.99.1",
            1.0,
        );
        assert_eq!(m["commit"], C);
        assert_eq!(
            m["binaries"][0]["sha256"],
            sha256_hex(b"binary"),
            "sha256 of the bytes"
        );
        assert_eq!(m["binaries"][0]["size"], 6);
        let allowed = allowed_binary_hashes(&m, C, "/home/a1/winvm/lab/rmasscan-lab").unwrap();
        assert_eq!(allowed, vec![sha256_hex(b"binary")]);
    }

    #[test]
    fn a_manifest_for_another_commit_path_or_kind_is_unusable() {
        let m = build_manifest(C, "/p/lab", b"b", "", 1.0);
        let other = "f".repeat(40);
        assert!(allowed_binary_hashes(&m, &other, "/p/lab").is_err());
        assert!(allowed_binary_hashes(&m, C, "/other/lab").is_err());
        let mut bad = m.clone();
        bad["kind"] = json!("something-else");
        assert!(allowed_binary_hashes(&bad, C, "/p/lab").is_err());
        let mut bad = m.clone();
        bad["schema"] = json!(2);
        assert!(allowed_binary_hashes(&bad, C, "/p/lab").is_err());
        let mut short = m.clone();
        short["binaries"][0]["sha256"] = json!("abc");
        assert!(allowed_binary_hashes(&short, C, "/p/lab").is_err());
        let mut abbreviated = m;
        abbreviated["commit"] = json!("0123456");
        assert!(allowed_binary_hashes(&abbreviated, "0123456", "/p/lab").is_err());
    }

    #[test]
    fn only_a_listed_hash_passes_the_remote_binary_check() {
        let allowed = vec![sha256_hex(b"good")];
        assert!(check_remote_binary(&allowed, &sha256_hex(b"good")).is_ok());
        assert!(check_remote_binary(&allowed, &sha256_hex(b"evil")).is_err());
        assert!(check_remote_binary(&[], &sha256_hex(b"good")).is_err());
        let line = format!("{}  /home/a1/rmasscan-lab\n", sha256_hex(b"good"));
        assert_eq!(parse_sha256sum(&line).unwrap(), sha256_hex(b"good"));
        assert!(parse_sha256sum("").is_err());
        assert!(parse_sha256sum("sha256sum: x: No such file").is_err());
    }

    #[test]
    fn clock_limits_are_plus_five_and_minus_sixty_seconds() {
        let base = 1_800_000_000.0;
        let at = |offset: f64| clock_verdict(base, base + offset, base);
        assert!(at(0.0).is_ok());
        assert!(at(4.9).is_ok());
        assert!(at(5.1).is_err(), "guest ahead beyond +5 s");
        assert!(at(-59.0).is_ok());
        assert!(at(-61.0).is_err(), "guest behind beyond -60 s");
        let err = at(5.1).unwrap_err();
        assert!(err.contains("ahead"), "{err}");
        assert!(at(-61.0).unwrap_err().contains("behind"));
        // The reading is a midpoint; a slow round trip widens the margin against the limit.
        assert!(clock_verdict(base, base + 4.0, base + 4.0).is_ok());
        assert!(clock_verdict(base, base + 6.0, base + 4.0).is_err());
        assert!(
            clock_verdict(base + 1.0, base, base).is_err(),
            "time ran backwards"
        );
        assert!(clock_verdict(f64::NAN, base, base).is_err());
        assert!(parse_epoch("1800000000.123\n").is_ok());
        assert!(parse_epoch("garbage").is_err());
        assert!(parse_epoch("12").is_err());
    }

    #[test]
    fn scripts_are_read_from_the_commit_not_from_a_compile_time_path() {
        let reads = std::cell::RefCell::new(Vec::new());
        let staged = StagedScripts::load(|p| {
            reads.borrow_mut().push(p.to_string());
            Ok(format!("content of {p}").into_bytes())
        })
        .unwrap();
        assert_eq!(staged.files.len(), GUEST_SCRIPTS.len());
        assert!(
            reads
                .borrow()
                .iter()
                .all(|p| p.starts_with("rmasscan/scripts/"))
        );
        let record = staged.record();
        assert_eq!(
            record["windows-vm-lab.ps1"]["guest_path"],
            "C:\\Users\\lab\\windows-vm-lab.ps1"
        );
        assert_eq!(
            record["windows_wire_clock.ps1"]["guest_path"],
            "C:\\Users\\lab\\t4\\windows_wire_clock.ps1"
        );
        assert_eq!(
            record["windows_wire_hash.ps1"]["sha256"],
            sha256_hex(b"content of rmasscan/scripts/windows_wire_hash.ps1")
        );
        // A script that cannot be read, or is empty, stops the staging.
        assert!(StagedScripts::load(|_| Err("no such path".into())).is_err());
        assert!(StagedScripts::load(|_| Ok(Vec::new())).is_err());
    }

    // The orchestrator runs on Mac and Linux; this test relies on unix paths or tools.
    #[cfg(unix)]
    #[test]
    fn the_deploy_manifest_command_hashes_the_installed_file() {
        let dir = std::env::temp_dir().join(format!("rmasscan-deploy-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("lab");
        fs::write(&bin, b"installed bytes").unwrap();
        let out = dir.join("m.json");
        let args: Vec<String> = [
            "--commit",
            C,
            "--binary",
            bin.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--toolchain",
            "rustc 1.99.1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(run(&args).unwrap(), 0);
        let m: Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
        assert_eq!(m["commit"], C);
        assert_eq!(m["binaries"][0]["sha256"], sha256_hex(b"installed bytes"));
        assert_eq!(m["binaries"][0]["path"], bin.to_str().unwrap());
        // refusals
        let mut bad = args.clone();
        bad[1] = "abc".into();
        assert!(run(&bad).is_err());
        let mut relative = args.clone();
        relative[3] = "lab".into();
        assert!(run(&relative).is_err());
        let mut missing = args;
        missing[3] = dir.join("absent").to_str().unwrap().into();
        assert!(run(&missing).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
