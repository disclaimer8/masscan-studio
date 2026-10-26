use studio_inspection::*;

fn xml(ip: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><address addr="{ip}" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Example" version="1.2" method="probed" conf="10" devicetype="printer"><cpe>cpe:/a:example:server:1.2</cpe></service></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>"#
    )
}
#[test]
fn exact_nmap_contract_and_print_port_exclusion() {
    let request = Request::new("127.0.0.1", vec![9100, 443, 80, 80]).unwrap();
    assert_eq!(request.ports, vec![80, 443]);
    assert_eq!(
        request.args(),
        [
            "--unprivileged",
            "-sT",
            "-sV",
            "--version-light",
            "-Pn",
            "-n",
            "--host-timeout",
            "45s",
            "--max-retries",
            "1",
            "-T3",
            "-p",
            "80,443",
            "-oX",
            "-",
            "127.0.0.1"
        ]
    );
    for ip in ["--script=all", "localhost", "::1", "127.0.0.1;id"] {
        assert!(Request::new(ip, vec![80]).is_err());
    }
    assert!(Request::new("127.0.0.1", vec![9100]).is_err());
    assert!(Request::new("127.0.0.1", (1..=65).collect()).is_err());
    assert!(Request::new("127.0.0.1", vec![0]).is_err());
}
#[test]
fn xml_requires_complete_matching_host_and_rejects_entities() {
    let r = Request::new("127.0.0.1", vec![80]).unwrap();
    let good = xml("127.0.0.1");
    let parsed = parse_xml(good.as_bytes(), &r).unwrap();
    assert_eq!(parsed.services[0].cpes, ["cpe:/a:example:server:1.2"]);
    assert_eq!(parsed.services[0].method, "probed");
    for bad in [
        xml("127.0.0.2"),
        good.replace("success", "error"),
        good.replace("<host>", "<host timedout=\"true\">"),
        good.replace(
            "<!DOCTYPE nmaprun>",
            "<!DOCTYPE nmaprun [<!ENTITY xx SYSTEM 'file:///etc/passwd'>]>",
        ),
        good.replace("</nmaprun>", ""),
        good.replace(
            "<runstats>",
            "<host><address addr='127.0.0.1' addrtype='ipv4'/></host><runstats>",
        ),
    ] {
        assert!(parse_xml(bad.as_bytes(), &r).is_err(), "{bad}");
    }
    assert!(parse_xml(&vec![b' '; 2_097_153], &r).is_err());
}
#[test]
fn export_quotes_formulas_and_keeps_snapshot_order() {
    let rows = vec![
        ExportRow {
            ip: "127.0.0.2".into(),
            port: 80,
            hostname: Some(" =1+1".into()),
            service: "x,\"y\"\r\nz".into(),
            ..Default::default()
        },
        ExportRow {
            ip: "127.0.0.1".into(),
            port: 443,
            ..Default::default()
        },
    ];
    let csv = csv(&rows).unwrap();
    assert!(csv.contains("' =1+1"));
    assert!(csv.contains("\"x,\"\"y\"\"\r\nz\""));
    assert!(csv.find("127.0.0.2").unwrap() < csv.find("127.0.0.1").unwrap());
    for v in ["=1+1", " +cmd", "\t-cmd", "@sum"] {
        assert!(csv_cell(v).starts_with('\''));
    }
    assert_eq!(valid_hostname("host.local."), Some("host.local".into()));
    for v in ["evil/a", "x@evil", "-x.local", "x\n.local"] {
        assert!(valid_hostname(v).is_none());
    }
}

#[test]
fn export_replaces_complete_files_and_preserves_destination_on_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("result.json");
    std::fs::write(&path, "old").unwrap();
    write_export(
        &path,
        &[ExportRow {
            ip: "127.0.0.1".into(),
            port: 80,
            ..Default::default()
        }],
        true,
    )
    .unwrap();
    let data: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(data["rows"][0]["ip"], "127.0.0.1");
    assert!(write_export(&dir.path().join("missing/file.csv"), &[], false).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = dir.path().join("alias");
        symlink(&path, &link).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(write_export(&link, &[], true).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
