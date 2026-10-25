//! Build provenance of the Mac-side orchestrator/verifier (`rmasscan-lab` itself): which commit it
//! was built from, whether that tree had uncommitted changes, and the hash of the binary that is
//! running. Recorded in the evidence manifest and in every preflight record by `windows-suite`, and
//! reported by `windows-verify`, so a verdict can be tied to the exact tool that produced it.
//!
//! `git_commit` and `git_dirty` are read at run time from the work tree given as `--repo`
//! (`git rev-parse HEAD`, `git status --porcelain --untracked-files=no`) and `binary_sha256` from
//! `current_exe()`. They describe the checkout, not the compiler input: an old binary run from an updated
//! checkout records the new HEAD. `build_commit` is the commit the binary was BUILT from, embedded at build time
//! from `RMASSCAN_LAB_BUILD_COMMIT` (set by the documented build command; `unknown` otherwise). The binary
//! sha256 is the authoritative identity. A value that cannot be read is recorded as null with a reason, never
//! guessed.
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
};

fn git(repo: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The commit this binary was built from (build-time environment), or `unknown`.
pub const BUILD_COMMIT: &str = match option_env!("RMASSCAN_LAB_BUILD_COMMIT") {
    Some(c) => c,
    None => "unknown",
};

/// Provenance of the running binary and of the work tree at `repo`.
pub fn collect(repo: &Path) -> Value {
    let mut errors = Vec::new();
    let commit = match git(repo, &["rev-parse", "HEAD"]) {
        Ok(c) if crate::deploy::full_commit(c.trim()) => Some(c.trim().to_owned()),
        Ok(c) => {
            errors.push(format!("HEAD is not a full commit id: {:?}", c.trim()));
            None
        }
        Err(e) => {
            errors.push(e);
            None
        }
    };
    // Tracked files only: an untracked scratch file cannot change what was compiled.
    let dirty = match git(repo, &["status", "--porcelain", "--untracked-files=no"]) {
        Ok(s) => Some(!s.trim().is_empty()),
        Err(e) => {
            errors.push(e);
            None
        }
    };
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"));
    let sha = exe
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|p| fs::read(p).map_err(|e| format!("{}: {e}", p.display())))
        .map(|b| crate::deploy::sha256_hex(&b));
    if let Err(e) = &sha {
        errors.push(e.clone());
    }
    json!({
        "git_commit": commit,
        "git_dirty": dirty,
        "build_commit": BUILD_COMMIT,
        "binary_sha256": sha.ok(),
        "binary_name": exe.ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
        "errors": errors,
    })
}

/// Why a recorded provenance object is not acceptable evidence (None = acceptable). A dirty tree is
/// acceptable here: it is reported, not refused.
pub fn problem(p: &Value) -> Option<String> {
    if !p["git_commit"]
        .as_str()
        .is_some_and(crate::deploy::full_commit)
    {
        return Some("git_commit is not a full commit id".into());
    }
    if !p["git_dirty"].is_boolean() {
        return Some("git_dirty is not recorded".into());
    }
    // Absent in records from before the build commit was embedded; when present it must be well formed.
    if let Some(b) = p.get("build_commit")
        && !b
            .as_str()
            .is_some_and(|b| b == "unknown" || crate::deploy::full_commit(b))
    {
        return Some("build_commit is neither a full commit id nor unknown".into());
    }
    let sha = p["binary_sha256"].as_str().unwrap_or("");
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some("binary_sha256 is not a sha256".into());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rmasscan-prov-{tag}-{}-{}",
            std::process::id(),
            crate::windows_suite::nonce()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }
    fn g(d: &Path, args: &[&str]) -> String {
        let o = Command::new("git")
            .arg("-C")
            .arg(d)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(o.status.success(), "git {args:?}: {o:?}");
        String::from_utf8_lossy(&o.stdout).trim().to_owned()
    }

    #[test]
    fn commit_dirty_flag_and_binary_hash_are_read_from_the_tree_and_the_running_binary() {
        let d = temp("tree");
        g(&d, &["init", "-q"]);
        fs::write(d.join("a.txt"), "one").unwrap();
        g(&d, &["add", "-A"]);
        g(&d, &["commit", "-q", "-m", "x"]);
        let head = g(&d, &["rev-parse", "HEAD"]);

        let clean = collect(&d);
        assert_eq!(clean["git_commit"], head);
        assert_eq!(clean["git_dirty"], false, "{clean}");
        assert_eq!(problem(&clean), None);
        let exe = fs::read(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(clean["binary_sha256"], crate::deploy::sha256_hex(&exe));
        assert!(clean["errors"].as_array().unwrap().is_empty());

        // An untracked file does not change what was built; a modified tracked file does.
        fs::write(d.join("scratch.txt"), "x").unwrap();
        assert_eq!(collect(&d)["git_dirty"], false);
        fs::write(d.join("a.txt"), "two").unwrap();
        let dirty = collect(&d);
        assert_eq!(dirty["git_dirty"], true);
        assert_eq!(dirty["git_commit"], head);
        assert_eq!(problem(&dirty), None, "dirty is reported, not refused");
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn an_unreadable_tree_is_recorded_as_null_with_a_reason_and_is_not_acceptable() {
        let d = temp("nogit");
        // Not a repository (and not inside one: the temp dir is outside the work tree).
        let p = collect(&d);
        assert!(p["git_commit"].is_null() && p["git_dirty"].is_null(), "{p}");
        assert!(!p["errors"].as_array().unwrap().is_empty());
        assert!(problem(&p).is_some());
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn the_build_commit_is_embedded_apart_from_the_checkout_head() {
        let d = temp("build");
        g(&d, &["init", "-q"]);
        fs::write(d.join("a.txt"), "one").unwrap();
        g(&d, &["add", "-A"]);
        g(&d, &["commit", "-q", "-m", "x"]);
        let p = collect(&d);
        // This test binary was not built by the documented command: the build commit is `unknown`, and it
        // is never taken from the checkout it is pointed at.
        assert_eq!(p["build_commit"], BUILD_COMMIT);
        assert_eq!(
            BUILD_COMMIT,
            option_env!("RMASSCAN_LAB_BUILD_COMMIT").unwrap_or("unknown")
        );
        if option_env!("RMASSCAN_LAB_BUILD_COMMIT").is_none() {
            assert_eq!(p["build_commit"], "unknown");
            assert_ne!(p["build_commit"], p["git_commit"]);
        }
        assert_eq!(problem(&p), None);
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn problem_checks_the_build_commit_when_present() {
        let mut ok =
            json!({"git_commit":"a".repeat(40),"git_dirty":false,"binary_sha256":"b".repeat(64)});
        assert_eq!(problem(&ok), None, "older records have no build_commit");
        for good in [json!("unknown"), json!("c".repeat(40))] {
            ok["build_commit"] = good;
            assert_eq!(problem(&ok), None, "{ok}");
        }
        for bad in [json!("abc"), Value::Null, json!(7)] {
            ok["build_commit"] = bad;
            assert!(problem(&ok).is_some(), "{ok}");
        }
    }

    #[test]
    fn problem_rejects_each_malformed_field() {
        let ok =
            json!({"git_commit":"a".repeat(40),"git_dirty":false,"binary_sha256":"b".repeat(64)});
        assert_eq!(problem(&ok), None);
        for (k, v) in [
            ("git_commit", json!("abc")),
            ("git_commit", Value::Null),
            ("git_dirty", json!("no")),
            ("git_dirty", Value::Null),
            ("binary_sha256", json!("b".repeat(63))),
            ("binary_sha256", json!("z".repeat(64))),
            ("binary_sha256", Value::Null),
        ] {
            let mut p = ok.clone();
            p[k] = v;
            assert!(problem(&p).is_some(), "{p}");
        }
    }
}
