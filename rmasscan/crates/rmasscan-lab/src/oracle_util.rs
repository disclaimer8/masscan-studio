//! Metadata helpers for building the independent pinned C oracle.
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};
pub fn patch_offline(source: &str) -> Result<String, String> {
    let old = "    if (is_offline)\n        return adapter;\n";
    let new = "    if (is_offline) {\n        adapter->link_type = 1; /* rmasscan oracle patch: DLT_EN10MB */\n        return adapter;\n    }\n";
    if source.matches(old).count() != 1 {
        return Err("offline patch requires exactly one original return".into());
    }
    Ok(source.replacen(old, new, 1))
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn cmd(args: &[&str]) -> Result<String, String> {
    let o = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(err)?;
    if !o.status.success() {
        return Err(format!(
            "{}: {}",
            args[0],
            String::from_utf8_lossy(&o.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_owned())
}
fn manifest(a: &[String]) -> Result<i32, String> {
    if a.len() != 9 {
        return Err("manifest needs OUT PIN VERSION BIN_SHA NS WALL TOTAL CPU COMMAND".into());
    }
    let d = Path::new(&a[0]);
    let mut secs = 0f64;
    for p in a[5].split(':') {
        secs = secs * 60. + p.parse::<f64>().map_err(err)?;
    }
    if !secs.is_finite() || secs <= 0. {
        return Err("invalid benchmark wall time".into());
    }
    let total = a[6].parse::<u64>().map_err(err)?;
    let mut cases = Vec::new();
    for line in fs::read_to_string(d.join(".cases.jsonl"))
        .map_err(err)?
        .lines()
    {
        let c: Value = serde_json::from_str(line).map_err(err)?;
        let file = c["file"].as_str().ok_or("case file missing")?;
        let path = Path::new(file);
        if path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err("case file outside golden directory".into());
        }
        if !d.join(file).is_file() {
            return Err(format!("case file missing: {file}"));
        }
        for k in ["line_count", "sha256", "truncated"] {
            if c[k].is_null() {
                return Err(format!("missing {file}.{k}"));
            }
        }
        let mut record = json!({});
        for k in [
            "file",
            "mode",
            "args",
            "binary",
            "line_count",
            "sha256",
            "truncated",
            "size_bytes",
            "deterministic",
            "note",
            "signal",
        ] {
            record[k] = c[k].clone();
        }
        cases.push(record);
    }
    let os = fs::read_to_string("/etc/os-release").map_err(err)?;
    let os = os
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .unwrap_or("?")
        .trim_matches('"');
    let m = json!({"masscan_git_head":a[1],"masscan_version":a[2],"binary_sha256":a[3],"offline_binary_sha256":std::env::var("BIN_OFF_SHA").map_err(err)?,"offline_binary_note":"pinned commit + one-line patch in src/rawsock.c: offline adapter link_type = DLT_EN10MB. Only paused captures and offline benchmark use patched binary.","built_on":os,"kernel":cmd(&["uname","-r"])?,"compiler":cmd(&["gcc","--version"])?.lines().next(),"arch":cmd(&["uname","-m"])?,"isolation":format!("{} (new network namespace; only a DOWN lo exists; no packets can leave)",a[4]),"built_at":cmd(&["date","-u","+%Y-%m-%dT%H:%M:%SZ"])?,"offline_gen_pps":(total as f64/secs).round() as u64,"offline_gen_bench":{"command":a[8].trim(),"targets_total":total,"wall_seconds":secs,"method":"total targets divided by wall clock from /usr/bin/time -v, including process start and exit","cpu_model":a[7],"cores":cmd(&["nproc"])?.parse::<u64>().map_err(err)?,"note":"single run; one transmit thread"},"cases":cases});
    fs::write(
        d.join("manifest.json"),
        format!("{}\n", serde_json::to_string_pretty(&m).map_err(err)?),
    )
    .map_err(err)?;
    Ok(0)
}
pub fn run(args: &[String]) -> Result<i32, String> {
    let (c, a) = args
        .split_first()
        .ok_or("oracle-util subcommand required")?;
    match c.as_str() {
        "patch-offline" if a.len() == 1 => {
            let src = fs::read_to_string(&a[0]).map_err(err)?;
            fs::write(&a[0], patch_offline(&src)?).map_err(err)?;
            Ok(0)
        }
        "record" if a.len() >= 3 => {
            let extra: Value = serde_json::from_str(&a[2]).map_err(err)?;
            let mut v = json!({"file":a[0],"mode":a[1],"args":a[3..]});
            for (k, x) in extra.as_object().ok_or("record extra must be object")? {
                v[k] = x.clone();
            }
            println!("{v}");
            Ok(0)
        }
        "manifest" => manifest(a),
        "validate-json" if a.len() == 1 => {
            let _: Value = serde_json::from_slice(&fs::read(&a[0]).map_err(err)?).map_err(err)?;
            Ok(0)
        }
        _ => Err("invalid oracle-util arguments".into()),
    }
}
