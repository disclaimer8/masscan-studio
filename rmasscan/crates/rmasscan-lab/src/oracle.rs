use crate::windows_suite::{
    command, epoch, hash, nonce, opt, quote, read_json, required, strings, valid_mac, write_json,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};
const PIN: &str = "8e6b3b0c07a81e8ea61d557c06134a21a6881614";
/// The Windows VM adapter MAC of the original fixtures; `--src-mac` replaces it for another binding (the Mac stand).
pub(crate) const DEFAULT_SRC_MAC: &str = "52:54:00:04:80:a9";
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
/// The listener ports of the Windows VM and Linux oracle runs, and of the Mac stand (a non-root peer cannot bind 80 or
/// 443 there, so 80 and 443 are closed and answer RST).
pub(crate) const DEFAULT_OPEN_PORTS: &str = "80,443,8000,8001,8002,8003,8004,8005,8006,8007";
pub(crate) const MAC_OPEN_PORTS: &str = "8000,8001,8002,8003,8004,8005,8006,8007";
#[cfg(test)]
fn oracle_command(work: &str, src_mac: &str, peer_mac: &str, lab: &str) -> Result<String, String> {
    oracle_command_with(work, src_mac, peer_mac, lab, DEFAULT_OPEN_PORTS)
}
fn oracle_command_with(
    work: &str,
    src_mac: &str,
    peer_mac: &str,
    lab: &str,
    open_ports: &str,
) -> Result<String, String> {
    if !open_ports
        .split(',')
        .all(|p| p.parse::<u16>().is_ok_and(|v| v > 0))
    {
        return Err(format!("invalid --open-ports {open_ports:?}"));
    }
    if !valid_mac(src_mac)
        || !valid_mac(peer_mac)
        || !work.starts_with('/')
        || !lab.starts_with('/')
    {
        return Err("invalid oracle binding or remote path".into());
    }
    Ok(format!(
        "cd {} && WIRELAB_MAC_A={} WIRELAB_MAC_B={} WIRELAB_IP_ADAPTER='198.18.0.1' WIRELAB_IP_A_LINK='' WIRELAB_PEER_IPS='198.18.0.2' WIRELAB_PEER_PREFIX='30' WIRELAB_OPEN_PORTS={} WIRELAB_CASES_FILE={} RMASSCAN_LAB_BIN={} bash scripts/wire-lab.sh --oracle \"$HOME/rmasscan-oracle/masscan/bin/masscan\" --out out",
        quote(work),
        quote(src_mac),
        quote(peer_mac),
        quote(open_ports),
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
/// `--src-mac`: the adapter MAC the C oracle runs with (default: the Windows VM adapter MAC). It is
/// validated here and quoted again where it enters the remote command.
pub(crate) fn src_mac_option(
    o: &std::collections::BTreeMap<String, Vec<String>>,
) -> Result<String, String> {
    let m = opt(o, "src-mac", DEFAULT_SRC_MAC);
    // Lower case only (a binding is compared without normalization) and a unicast address (group bit clear).
    let unicast = m
        .get(0..2)
        .and_then(|h| u8::from_str_radix(h, 16).ok())
        .is_some_and(|b| b & 1 == 0);
    if valid_mac(&m) && m == m.to_lowercase() && unicast {
        Ok(m)
    } else {
        Err(format!(
            "invalid --src-mac {m:?} (six lower-case hex pairs, unicast)"
        ))
    }
}
pub fn run(args: &[String]) -> Result<i32, String> {
    let o = crate::windows_suite::options_for(
        "oracle-fixtures",
        args,
        &[
            "out",
            "peer-mac",
            "remote-lab",
            "host",
            "src-mac",
            "open-ports",
        ],
    )?;
    if o.contains_key("help") {
        println!(
            "oracle-fixtures --out DIR --peer-mac MAC [--src-mac MAC] [--open-ports CSV] --remote-lab /absolute/linux/rmasscan-lab [--host minipc]"
        );
        return Ok(0);
    }
    let out = PathBuf::from(required(&o, "out")?);
    let pm = required(&o, "peer-mac")?;
    if !valid_mac(&pm) {
        return Err("invalid peer MAC".into());
    }
    let src_mac = src_mac_option(&o)?;
    let open_ports = opt(&o, "open-ports", DEFAULT_OPEN_PORTS);
    if !open_ports
        .split(',')
        .all(|p| p.parse::<u16>().is_ok_and(|v| v > 0))
    {
        return Err(format!("invalid --open-ports {open_ports:?}"));
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
    // The expected open and closed counts follow the listeners the oracle is run against.
    let cases = {
        let _mac = (open_ports == MAC_OPEN_PORTS).then(crate::verify::MacStandGuard::enter);
        crate::verify::cases_psv()
    };
    fs::write(&localcases, cases).map_err(|e| e.to_string())?;
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
        let cmd = oracle_command_with(&work, &src_mac, &pm, &lab, &open_ports)?;
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
        let scripts =
            PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../scripts");
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
        let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("../../tests/golden/wire");
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
            oracle_command(
                "/home/lab/x",
                DEFAULT_SRC_MAC,
                "bad;touch /tmp/x",
                "/home/lab/rmasscan-lab"
            )
            .is_err()
        );
        let cmd = oracle_command(
            "/home/lab/x",
            DEFAULT_SRC_MAC,
            "02:57:4c:3d:2e:9b",
            "/home/lab/rmasscan-lab",
        )
        .unwrap();
        assert!(!cmd.contains(concat!("py", "thon")));
        assert!(cmd.contains("WIRELAB_MAC_A='52:54:00:04:80:a9'"));
    }
    #[test]
    fn oracle_plan_uses_the_given_source_mac_and_quotes_it() {
        let cmd = oracle_command(
            "/home/lab/x",
            "02:ac:00:00:00:01",
            "02:ac:00:00:00:02",
            "/home/lab/rmasscan-lab",
        )
        .unwrap();
        assert!(cmd.contains("WIRELAB_MAC_A='02:ac:00:00:00:01'"), "{cmd}");
        assert!(cmd.contains("WIRELAB_MAC_B='02:ac:00:00:00:02'"), "{cmd}");
        assert!(
            !cmd.contains("52:54:00:04:80:a9"),
            "the Windows source MAC must not leak into a Mac binding"
        );
        // A source MAC that is not exactly six hex pairs is refused before anything is quoted.
        for bad in [
            "02:ac:00:00:00:01; id",
            "02:ac:00:00:00",
            "2:ac:0:0:0:1",
            "$(id)",
            "",
        ] {
            assert!(
                oracle_command("/home/lab/x", bad, "02:ac:00:00:00:02", "/home/lab/l").is_err(),
                "{bad:?}"
            );
        }
    }
    #[test]
    fn src_mac_is_validated_and_defaults_to_the_windows_value() {
        let args = |extra: &[&str]| -> Vec<String> {
            let mut v: Vec<String> = [
                "--out",
                "/nonexistent-out",
                "--peer-mac",
                "02:ac:00:00:00:02",
            ]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
            v.extend(extra.iter().map(|s| (*s).to_owned()));
            v
        };
        assert_eq!(
            src_mac_option(&options_of(&args(&[]))).unwrap(),
            DEFAULT_SRC_MAC
        );
        assert_eq!(
            src_mac_option(&options_of(&args(&["--src-mac", "02:ac:00:00:00:01"]))).unwrap(),
            "02:ac:00:00:00:01"
        );
        assert!(src_mac_option(&options_of(&args(&["--src-mac", "bogus"]))).is_err());
        for bad in [
            "02:AC:00:00:00:01",
            "ff:ff:ff:ff:ff:ff",
            "03:ac:00:00:00:01",
        ] {
            assert!(
                src_mac_option(&options_of(&args(&["--src-mac", bad]))).is_err(),
                "{bad}"
            );
        }
    }
    fn options_of(a: &[String]) -> std::collections::BTreeMap<String, Vec<String>> {
        crate::windows_suite::options_for(
            "oracle-fixtures",
            a,
            &["out", "peer-mac", "remote-lab", "host", "src-mac"],
        )
        .unwrap()
    }
}

#[cfg(test)]
mod open_port_tests {
    use super::*;
    #[test]
    fn oracle_plan_uses_the_given_open_ports_and_cases_follow_them() {
        let cmd = oracle_command_with(
            "/h/x",
            "02:ac:00:00:00:01",
            "02:ac:00:00:00:02",
            "/h/l",
            MAC_OPEN_PORTS,
        )
        .unwrap();
        assert!(
            cmd.contains(&format!("WIRELAB_OPEN_PORTS='{MAC_OPEN_PORTS}'")),
            "{cmd}"
        );
        assert!(!cmd.contains("80,443"));
        let win = oracle_command("/h/x", DEFAULT_SRC_MAC, "02:ac:00:00:00:02", "/h/l").unwrap();
        assert!(win.contains(&format!("WIRELAB_OPEN_PORTS='{DEFAULT_OPEN_PORTS}'")));
        for bad in ["80;id", "", "0", "80,,81", "99999"] {
            assert!(
                oracle_command_with(
                    "/h/x",
                    "02:ac:00:00:00:01",
                    "02:ac:00:00:00:02",
                    "/h/l",
                    bad
                )
                .is_err(),
                "{bad:?}"
            );
        }
        // c01 scans port 80: open for the Windows listeners, closed (one RST) for the Mac stand.
        let line = |t: &str| {
            t.lines()
                .find(|l| l.starts_with("c01_"))
                .unwrap()
                .to_owned()
        };
        assert!(line(&crate::verify::cases_psv()).starts_with("c01_one_addr_port_synack|1|1|0|"));
        let mac = {
            let _g = crate::verify::MacStandGuard::enter();
            crate::verify::cases_psv()
        };
        assert!(
            line(&mac).starts_with("c01_one_addr_port_synack|1|0|1|"),
            "{}",
            line(&mac)
        );
    }
}
