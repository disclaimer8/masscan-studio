//! `paused.conf` и разбор файлов конфигурации (AGPL-3.0). Порт
//! `masscan_save_state` (`main-conf.c:395-416`), `masscan_echo` (`:3636-3780`),
//! `masscan_echo_nic` (`:294-389`), `masscan_read_config_file` (`:3883-3924`)
//! и ключей `resume`/`conf`/`includefile` (`:2926-2928`, `:2825-2836`) из
//! masscan © Robert David Graham (github.com/robertdavidgraham/masscan,
//! HEAD 8e6b3b0).

use std::fmt::Write as _;
use std::path::Path;

use rmasscan_core::config::{
    EchoExtras, ScanConfig, apply_core_kv, conf_line_kv, echo_with, normalize_key, parse_bool,
};
use rmasscan_core::targets::add_target_string;

use crate::output::Format;

/// Ключи вывода, которые `paused.conf` хранит между двумя `SPACE`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutputConfPatch {
    pub format: Option<Format>,
    pub filename: Option<String>,
    pub append: Option<bool>,
    pub flush: Option<bool>,
    pub stylesheet: Option<String>,
    pub show_open: Option<bool>,
    pub show_closed: Option<bool>,
    pub show_host: Option<bool>,
}

/// Всё, что попадает в `paused.conf`.
#[derive(Debug, Clone, Default)]
pub struct FullConf {
    pub scan: ScanConfig,
    pub output: OutputConfPatch,
    pub pcap_filename: Option<String>,
    pub ndjson_status: bool,
}

/// Глубина вложенности `conf =` / `resume =` / `includefile =` (Р7): больше
/// 16 значит цикл, и это ошибка (в C бесконечная рекурсия).
pub const MAX_CONF_DEPTH: usize = 16;

fn format_name(f: Format) -> Option<&'static str> {
    // main-conf.c:1665-1690: `Output_Default` без echo_all ничего не печатает.
    Some(match f {
        Format::Default => return None,
        Format::Interactive => "interactive",
        Format::List => "list",
        Format::Json => "json",
        Format::Ndjson => "ndjson",
        Format::Grepable => "grepable",
        Format::Xml => "xml",
        Format::Binary => "binary",
        Format::Hostonly => "hostonly",
        Format::Unicornscan => "unicornscan",
        Format::None => "none",
    })
}

/// Секция вывода между двумя `SPACE` (main-conf.c:2402-2422): `output-filename`,
/// `output-format`, `output-append`, `output-flush`, `stylesheet`. `show` и
/// `noshow` C печатает только в `echo_all`, поэтому здесь их нет.
fn output_section(o: &OutputConfPatch) -> String {
    let mut s = String::new();
    // SET_output_filename (:1643) и SET_output_stylesheet (:2092) при формате 0 ставят XML.
    let format = o
        .format
        .unwrap_or(if o.filename.is_some() || o.stylesheet.is_some() {
            Format::Xml
        } else {
            Format::Default
        });
    if let Some(f) = o.filename.as_deref().filter(|f| !f.is_empty()) {
        let _ = writeln!(s, "output-filename = {f}");
    }
    if let Some(name) = format_name(format) {
        let _ = writeln!(s, "output-format = {name}");
    }
    if o.append == Some(true) {
        s.push_str("output-append = true\n");
    }
    if o.flush == Some(true) {
        s.push_str("output-flush = true\n");
    }
    if let Some(x) = o.stylesheet.as_deref().filter(|x| !x.is_empty()) {
        let _ = writeln!(s, "stylesheet = {x}");
    }
    s
}

/// Содержимое `paused.conf` (`masscan_save_state` -> `masscan_echo`,
/// main-conf.c:395-416, :3636-3780). `resume_index` это нормализованная база
/// возобновления `min_k(my_index - nic_offset)`, а не сырой индекс
/// (`ProbeCursor::resume_base`): `cursor_for_nic` прибавляет смещение
/// шарда/адаптера заново.
pub fn format_paused_conf(conf: &FullConf, resume_index: u64) -> String {
    let mut scan = conf.scan.clone();
    scan.resume_index = resume_index;
    let section = output_section(&conf.output);
    let extras = EchoExtras {
        pcap_filename: conf.pcap_filename.as_deref(),
        ndjson_status: conf.ndjson_status,
        output_section: &section,
    };
    let mut out = String::new();
    echo_with(&scan, false, &extras, &mut out);
    out
}

fn parse_format(value: &str) -> Result<Format, String> {
    // main-conf.c:1692-1708.
    let v = value.to_ascii_lowercase();
    Ok(match v.as_str() {
        "unknown(0)" | "interactive" => Format::Interactive,
        "list" => Format::List,
        "unicornscan" => Format::Unicornscan,
        "xml" => Format::Xml,
        "binary" => Format::Binary,
        "greppable" | "grepable" => Format::Grepable,
        "json" => Format::Json,
        "ndjson" => Format::Ndjson,
        "none" => Format::None,
        "hostonly" => Format::Hostonly,
        "certs" | "redis" => return Err(format!("unsupported output-format: {value}")),
        _ => return Err(format!("FAIL: unknown output-format: {value}")),
    })
}

/// `output-show` / `output-noshow` (main-conf.c:1715-1790): список через запятую.
fn apply_show(o: &mut OutputConfPatch, list: &str, on: bool, key: &str) -> Result<(), String> {
    for item in list.split(',').filter(|i| !i.is_empty()) {
        let v = Some(on);
        match item.to_ascii_lowercase().as_str() {
            "open" => o.show_open = v,
            "closed" | "close" => o.show_closed = v,
            "host" => o.show_host = v,
            "all" => (o.show_open, o.show_closed, o.show_host) = (v, v, v),
            _ => return Err(format!("FAIL: unknown '{key}' spec: {item}")),
        }
    }
    Ok(())
}

fn load(
    loader: &mut dyn FnMut(&Path) -> Result<String, String>,
    path: &str,
) -> Result<String, String> {
    loader(Path::new(path)).map_err(|e| format!("{path}: {e}"))
}

/// Применяет одну пару `name = value` в позиции разбора (ключи правее
/// переопределяют ключи левее, как в `masscan_set_parameter`, main-conf.c:2429).
/// Отличия от C: неизвестный ключ и нечитаемый файл возвращают `Err` (C на
/// `conf`/`resume` молча продолжает, :3889-3900).
pub fn apply_conf_key(
    name: &str,
    value: &str,
    base: &mut FullConf,
    include_loader: &mut dyn FnMut(&Path) -> Result<String, String>,
    depth: usize,
) -> Result<(), String> {
    let o = &mut base.output;
    match normalize_key(name).as_str() {
        "conf" | "config" => {
            let text = load(include_loader, value)?;
            parse_conf_str(&text, base, include_loader, depth + 1)?;
        }
        "resume" => {
            // main-conf.c:2926-2928: читаем файл, затем `output-append = true`.
            let text = load(include_loader, value)?;
            parse_conf_str(&text, base, include_loader, depth + 1)?;
            base.output.append = Some(true);
        }
        "includefile" => {
            // main-conf.c:2825-2836, `massip_parse_file`: по цели на строку, `#` комментарий.
            let text = load(include_loader, value)?;
            for line in text.lines() {
                let line = line.split('#').next().unwrap_or("").trim();
                if !line.is_empty() {
                    add_target_string(base.scan.targets.ipv4_mut(), line)
                        .map_err(|e| format!("{value}: bad target {line:?}: {e}"))?;
                }
            }
        }
        "pcapfilename" | "pcap" => base.pcap_filename = Some(value.to_string()),
        "ndjsonstatus" | "statusndjson" => base.ndjson_status = parse_bool(value),
        "jsonstatus" | "statusjson" => {
            return Err(format!("{name} not supported, use --ndjson-status"));
        }
        "outputfilename" | "outputfile" => {
            if o.format.is_none() {
                o.format = Some(Format::Xml);
            }
            o.filename = Some(value.to_string());
        }
        "outputformat" => o.format = Some(parse_format(value)?),
        "outputshow" | "outputstatus" | "show" => apply_show(o, value, true, "show")?,
        "outputnoshow" | "noshow" => apply_show(o, value, false, "noshow")?,
        "outputshowopen" | "open" | "openonly" => {
            (o.show_open, o.show_closed, o.show_host) = (Some(true), Some(false), Some(false));
        }
        "outputappend" | "appendoutput" => o.append = Some(parse_bool(value)),
        "outputflush" => o.flush = Some(parse_bool(value)),
        "stylesheet" => {
            if o.format.is_none() {
                o.format = Some(Format::Xml);
            }
            o.stylesheet = Some(value.to_string());
        }
        // Ротация вывода не поддерживается: ключи принимаются и не действуют.
        "rotate"
        | "outputrotate"
        | "rotateoutput"
        | "rotatetime"
        | "rotatedir"
        | "outputrotatedir"
        | "rotatedirectory"
        | "rotateoffset"
        | "outputrotateoffset"
        | "rotatesize"
        | "outputrotatefilesize"
        | "rotatefilesize" => {}
        _ => {
            let taken = apply_core_kv(&mut base.scan, name, value).map_err(|e| e.to_string())?;
            if !taken {
                return Err(format!("CONF: unknown config option: {name}={value}"));
            }
        }
    }
    Ok(())
}

/// Разбор текста файла конфигурации (`masscan_read_config_file`,
/// main-conf.c:3883-3924) поверх `base`: строки применяются по порядку.
/// `include_loader` читает вложенные файлы (`conf`, `resume`, `includefile`);
/// `depth` это текущая глубина, больше [`MAX_CONF_DEPTH`] даёт `Err`.
pub fn parse_conf_str(
    text: &str,
    base: &mut FullConf,
    include_loader: &mut dyn FnMut(&Path) -> Result<String, String>,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_CONF_DEPTH {
        return Err(format!(
            "configuration files nested deeper than {MAX_CONF_DEPTH} levels (a conf/resume cycle?)"
        ));
    }
    for raw in text.lines() {
        if let Some((name, value)) = conf_line_kv(raw) {
            apply_conf_key(name, value, base, include_loader, depth)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmasscan_core::config::NicConfig;
    use rmasscan_core::scan::Shard;
    use rmasscan_core::targets::{add_target_string, parse_ports};

    fn no_include(_: &Path) -> Result<String, String> {
        Err("no includes in this test".into())
    }

    fn sample() -> FullConf {
        let mut scan = ScanConfig {
            seed: 42,
            max_rate: 1000.0,
            retries: 2,
            shard: Shard { one: 2, of: 4 },
            ..ScanConfig::default()
        };
        add_target_string(scan.targets.ipv4_mut(), "198.18.0.0/24").unwrap();
        parse_ports(scan.targets.ports_mut(), "80,443").unwrap();
        add_target_string(scan.excludes.ipv4_mut(), "198.18.0.1").unwrap();
        scan.adapter_name = Some("eth0".into());
        scan.adapter_ip = Some(0xc612_0001);
        scan.adapter_mac = Some([2, 0, 0, 0, 0, 1]);
        scan.router_mac = Some([2, 0, 0, 0, 0, 2]);
        scan.nics = vec![
            NicConfig {
                adapter_name: Some("eth0".into()),
                adapter_ip: Some((0xc612_0001, 0xc612_0001)),
                adapter_mac: Some([2, 0, 0, 0, 0, 1]),
                router_mac_ipv4: Some([2, 0, 0, 0, 0, 2]),
                router_mac_ipv6: Some([2, 0, 0, 0, 0, 2]),
                ..NicConfig::default()
            },
            NicConfig {
                adapter_name: Some("eth1".into()),
                adapter_ip: Some((0xc612_0002, 0xc612_0002)),
                adapter_mac: Some([2, 0, 0, 0, 0, 3]),
                ..NicConfig::default()
            },
        ];
        FullConf {
            scan,
            output: OutputConfPatch {
                format: Some(Format::Json),
                filename: Some("scan.json".into()),
                ..OutputConfPatch::default()
            },
            pcap_filename: Some("cap.pcap".into()),
            ndjson_status: true,
        }
    }

    /// Порядок секций `masscan_echo` (main-conf.c:3636-3780) с таблицей
    /// `config_parameters[]` (:2369): resume, seed, rate, shard, retries,
    /// pcap-filename, ndjson-status, двойной nocapture, SPACE, вывод, SPACE,
    /// адаптеры, цели.
    #[test]
    fn paused_conf_section_order_and_roundtrip_match_c() {
        let conf = sample();
        let text = format_paused_conf(&conf, 420);
        let expected = "\n# resume information\nresume-index = 420\nseed = 42\n\
rate = 1000      \nshard = 2/4\nretries = 2\n\
pcap-filename = cap.pcap\nndjson-status = true\n\
nocapture = servername\nnocapture = servername\n\
\n\
output-filename = scan.json\noutput-format = json\n\
\n\
adapter[0] = eth0\nadapter-ip[0] = 198.18.0.1\nadapter-mac[0] = 02-00-00-00-00-01\n\
router-mac-ipv4[0] = 02-00-00-00-00-02\nrouter-mac-ipv6[0] = 02-00-00-00-00-02\n\
adapter[1] = eth1\nadapter-ip[1] = 198.18.0.2\nadapter-mac[1] = 02-00-00-00-00-03\n\
# TARGET SELECTION (IP, PORTS, EXCLUDES)\nports = 80,443\n\
range = 198.18.0.0\nrange = 198.18.0.2-198.18.0.255\n";
        assert_eq!(text, expected);

        let mut back = FullConf::default();
        parse_conf_str(&text, &mut back, &mut no_include, 0).unwrap();
        assert_eq!(back.scan.resume_index, 420);
        assert_eq!(back.scan.shard, Shard { one: 2, of: 4 });
        assert_eq!(back.scan.retries, 2);
        assert_eq!(back.pcap_filename.as_deref(), Some("cap.pcap"));
        assert!(back.ndjson_status);
        assert_eq!(back.output.filename.as_deref(), Some("scan.json"));
        assert_eq!(back.output.format, Some(Format::Json));
        assert_eq!(back.scan.nics, conf.scan.nics);
        assert_eq!(format_paused_conf(&back, 420), text);
    }

    /// Review Focus 2: C сам пишет `adapter-port` из 17 портов (main.c:1318);
    /// `--resume` читает такой файл, принудительно ставит `output-append`
    /// (main-conf.c:2926-2928), а ключи правее переопределяют файл.
    #[test]
    fn reads_c_paused_conf_with_17_port_quirk_and_cli_overrides() {
        let c_text = "\n# resume information\nresume-index = 77\nseed = 9\nrate = 250.000000\n\
shard = 1/1\nnocapture = servername\nnocapture = servername\n\n\
output-filename = a.json\noutput-format = json\n\n\
adapter = lo\nadapter-ip = 10.0.0.2\nadapter-mac = 02-00-00-00-00-01\n\
router-mac-ipv4 = 02-00-00-00-00-02\nrouter-mac-ipv6 = 02-00-00-00-00-02\n\
adapter-port = 41234-41250\n\
# TARGET SELECTION (IP, PORTS, EXCLUDES)\nports = 80\nrange = 10.0.0.0/30\n";
        let mut base = FullConf::default();
        let mut loader = |p: &Path| -> Result<String, String> {
            assert_eq!(p, Path::new("paused.conf"));
            Ok(c_text.to_string())
        };
        parse_conf_str(
            "resume = paused.conf\nrate = 500\n",
            &mut base,
            &mut loader,
            0,
        )
        .unwrap();

        assert_eq!(base.scan.source_port, Some((41234, 41250)));
        assert!(base.scan.nics[0].legacy_c_17_port_mask);
        assert_eq!(base.scan.resume_index, 77);
        assert_eq!(base.output.filename.as_deref(), Some("a.json"));
        assert_eq!(base.output.append, Some(true));
        // `rate = 500` стоит правее `resume` и переопределяет файл.
        assert_eq!(base.scan.max_rate, 500.0);
        assert_eq!(base.scan.seed, 9);
    }

    #[test]
    fn conf_include_resume_and_depth_limit() {
        // `conf = self` обрывается на глубине > 16 (Р7).
        let mut base = FullConf::default();
        let mut selfref = |_: &Path| -> Result<String, String> { Ok("conf = self.conf\n".into()) };
        let err = parse_conf_str("conf = self.conf\n", &mut base, &mut selfref, 0).unwrap_err();
        assert!(err.contains("nested deeper than 16"), "{err}");
        // includefile добавляет цели; позднее значение правее переопределяет файл.
        let mut loader = |p: &Path| -> Result<String, String> {
            if p == Path::new("t.txt") {
                Ok("10.0.0.0/30 # net\n\n".into())
            } else {
                Err("missing".into())
            }
        };
        let mut base = FullConf::default();
        parse_conf_str(
            "includefile = t.txt\nports = 80\nunknown-key = 1\n",
            &mut base,
            &mut loader,
            0,
        )
        .unwrap_err();
        assert_eq!(base.scan.targets.ipv4().len(), 1);
        let err = parse_conf_str("resume = gone.conf\n", &mut base, &mut loader, 0).unwrap_err();
        assert!(err.contains("gone.conf"), "{err}");
    }
}
