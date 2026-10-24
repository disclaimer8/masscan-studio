use crate::windows_suite::{
    command, epoch, hash, nonce, opt, options, quote, read_json, required, strings, valid_mac,
    write_json,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};
const PIN: &str = "8e6b3b0c07a81e8ea61d557c06134a21a6881614";
const STAGED_SCRIPTS: &[&str] = &["wire-lab.sh", "lab-process-group.sh"];
fn staging_command(scripts: &Path, host: &str, work: &str) -> Vec<String> {
    let mut argv = strings(&["scp", "-q"]);
    argv.extend(
        STAGED_SCRIPTS
            .iter()
            .map(|f| scripts.join(f).to_string_lossy().into_owned()),
    );
    argv.push(format!("{host}:{work}/scripts/"));
    argv
}
fn oracle_command(work: &str, peer_mac: &str, lab: &str) -> Result<String, String> {
    if !valid_mac(peer_mac) || !work.starts_with('/') || !lab.starts_with('/') {
        return Err("invalid oracle binding or remote path".into());
    }
    Ok(format!(
        "cd {} && WIRELAB_MAC_A='52:54:00:04:80:a9' WIRELAB_MAC_B={} WIRELAB_IP_ADAPTER='198.18.0.1' WIRELAB_IP_A_LINK='' WIRELAB_PEER_IPS='198.18.0.2' WIRELAB_PEER_PREFIX='30' WIRELAB_OPEN_PORTS='80,443,8000,8001,8002,8003,8004,8005,8006,8007' WIRELAB_CASES_FILE={} RMASSCAN_LAB_BIN={} bash scripts/wire-lab.sh --oracle \"$HOME/rmasscan-oracle/masscan/bin/masscan\" --out out",
        quote(work),
        quote(peer_mac),
        quote(&format!("{work}/cases.psv")),
        quote(lab)
    ))
}
pub(crate) fn convert(raw: &Value, out: &Path, host: &str) -> Result<Value, String> {
    let mut fixtures = serde_json::Map::new();
    let mut valid = raw["all_valid"] == true;
    for c in raw["cases"]
        .as_array()
        .ok_or("oracle manifest missing cases")?
    {
        for (i, r) in c["runs"]
            .as_array()
            .ok_or("oracle case missing runs")?
            .iter()
            .enumerate()
        {
            let file = r["pcap"].as_str().ok_or("oracle run missing pcap")?;
            if Path::new(file)
                .components()
                .any(|x| !matches!(x, std::path::Component::Normal(_)))
            {
                return Err("oracle capture escaped evidence directory".into());
            }
            fixtures.insert(format!("{}.run{}",c["name"].as_str().ok_or("case name missing")?,i+1),json!({"file":format!("fixtures/{file}"),"sha256":hash(out.join(file))?,"capture_valid":r["valid"]==true,"observed":r["observed"],"expected":c["expected"]}));
            valid &= r["valid"] == true;
        }
        valid &= c["repeat_compare"]["result"] == "PASS";
    }
    let b = &raw["binding"];
    let o = &raw["oracle"];
    Ok(
        json!({"schema":1,"all_valid":valid,"oracle":{"sha256":o["sha256"],"git_commit":o["git_commit"],"git_tree_clean":o["git_tree_clean"],"variant":o["variant"],"version_line":o["version_line"],"pinned_revision":PIN,"host":host},"binding":{"src_ip":b["adapter_ip"],"src_mac":b["adapter_mac"],"router_mac":b["router_mac"],"seed":b["seed"],"rate":b["rate"],"blackrock_rounds":b["blackrock_rounds"],"retries":b["retries"],"wait":b["wait"],"responder_open_ports":b["responder_open_ports"]},"fixtures":fixtures,"created_utc":epoch()}),
    )
}
pub fn run(args: &[String]) -> Result<i32, String> {
    let o = options(args)?;
    if o.contains_key("help") {
        println!(
            "oracle-fixtures --out DIR --peer-mac MAC --remote-lab /absolute/linux/rmasscan-lab [--host minipc]"
        );
        return Ok(0);
    }
    let out = PathBuf::from(required(&o, "out")?);
    let pm = required(&o, "peer-mac")?;
    if !valid_mac(&pm) {
        return Err("invalid peer MAC".into());
    }
    let host = opt(&o, "host", "minipc");
    if host.starts_with('-') || host.chars().any(char::is_whitespace) {
        return Err("invalid SSH host".into());
    }
    let lab = required(&o, "remote-lab")?;
    if !lab.starts_with('/') {
        return Err("remote lab binary must be absolute Linux path".into());
    }
    if out.exists()
        && fs::read_dir(&out)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
    {
        return Err("refusing to reuse non-empty evidence directory".into());
    }
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let ssh = |cmd: &str, check: bool| {
        command(
            &strings(&["ssh", "-o", "BatchMode=yes", &host, cmd]),
            1800,
            check,
        )
    };
    let rh = ssh("printf '%s' \"$HOME\"", true)?.stdout;
    if !rh.starts_with('/') || rh.contains('\n') {
        return Err("invalid remote home".into());
    }
    let work = format!("{rh}/t4-fixtures-{}", nonce());
    let scripts = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts");
    let localcases = out.join("cases.psv");
    fs::write(&localcases, crate::verify::cases_psv()).map_err(|e| e.to_string())?;
    let result = (|| {
        ssh(
            &format!(
                "test -x {} && mkdir -- {} && mkdir -- {}",
                quote(&lab),
                quote(&work),
                quote(&format!("{work}/scripts"))
            ),
            true,
        )?;
        command(&staging_command(&scripts, &host, &work), 180, true)?;
        command(
            &[
                "scp".into(),
                "-q".into(),
                localcases.to_string_lossy().into_owned(),
                format!("{host}:{work}/cases.psv"),
            ],
            180,
            true,
        )?;
        let cmd = oracle_command(&work, &pm, &lab)?;
        let r = ssh(&cmd, false)?;
        fs::write(
            out.join("wire-lab.log"),
            format!("{}\n--- stderr ---\n{}", r.stdout, r.stderr),
        )
        .map_err(|e| e.to_string())?;
        command(
            &strings(&[
                "scp",
                "-q",
                "-r",
                &format!("{host}:{work}/out/."),
                &out.to_string_lossy(),
            ]),
            180,
            true,
        )?;
        let left = ssh("ip netns list | grep -c wl- || true", false)?.stdout;
        fs::write(
            out.join("cleanup.txt"),
            format!(
                "lab namespaces left on oracle host after run: {}\n",
                left.trim()
            ),
        )
        .map_err(|e| e.to_string())?;
        if r.rc != 0 {
            return Err(format!(
                "wire-lab failed rc={}, remote evidence retained: {work}",
                r.rc
            ));
        }
        let raw = read_json(out.join("manifest.json"))?;
        fs::rename(
            out.join("manifest.json"),
            out.join("wire-lab-manifest.json"),
        )
        .map_err(|e| e.to_string())?;
        let fx = convert(&raw, &out, &host)?;
        write_json(out.join("manifest.json"), &fx)?;
        Ok(if fx["all_valid"] == true { 0 } else { 3 })
    })();
    if result.is_ok() {
        ssh(
            &format!(
                "test \"$(readlink -f -- {p})\" = {p} && rm -rf -- {p}",
                p = quote(&work)
            ),
            true,
        )?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_staging_includes_every_local_sourced_script() {
        let scripts = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts");
        let argv = staging_command(&scripts, "oracle-host", "/home/lab/run-nonce");
        assert_eq!(
            argv.last().unwrap(),
            "oracle-host:/home/lab/run-nonce/scripts/"
        );
        for entry in STAGED_SCRIPTS {
            let source = fs::read_to_string(scripts.join(entry)).unwrap();
            for line in source
                .lines()
                .map(str::trim)
                .filter(|l| l.starts_with("source \"$HERE/"))
            {
                let dependency = line
                    .strip_prefix("source \"$HERE/")
                    .unwrap()
                    .split('"')
                    .next()
                    .unwrap();
                assert!(
                    STAGED_SCRIPTS.contains(&dependency),
                    "{entry} sources unstaged {dependency}"
                );
                assert!(argv.contains(&scripts.join(dependency).to_string_lossy().into_owned()));
            }
        }
    }
    #[test]
    fn oracle_conversion_preserves_hashes_binding_and_repeat_failures() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/wire");
        let mut raw = read_json(dir.join("manifest.json")).unwrap();
        let converted = convert(&raw, &dir, "custom-oracle").unwrap();
        assert_eq!(converted["all_valid"], true);
        assert_eq!(converted["oracle"]["host"], "custom-oracle");
        assert_eq!(
            converted["binding"]["src_mac"],
            raw["binding"]["adapter_mac"]
        );
        assert_eq!(converted["fixtures"].as_object().unwrap().len(), 12);
        assert_eq!(
            converted["fixtures"]["c01_one_addr_port_synack.run1"]["sha256"],
            hash(dir.join("c01_one_addr_port_synack.run1.pcap")).unwrap()
        );
        raw["cases"][0]["repeat_compare"]["result"] = json!("FAIL");
        assert_eq!(convert(&raw, &dir, "x").unwrap()["all_valid"], false);
        raw["cases"][0]["runs"][0]["pcap"] = json!("../escape.pcap");
        assert!(convert(&raw, &dir, "x").is_err());
    }
    #[test]
    fn oracle_plan_has_no_interpreter_and_quotes_binding() {
        assert!(
            oracle_command("/home/lab/x", "bad;touch /tmp/x", "/home/lab/rmasscan-lab").is_err()
        );
        let cmd =
            oracle_command("/home/lab/x", "02:57:4c:3d:2e:9b", "/home/lab/rmasscan-lab").unwrap();
        assert!(!cmd.contains("python"));
        assert!(cmd.contains("WIRELAB_MAC_A"));
    }
}
