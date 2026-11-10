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
use rmasscan_core::ranges::RangeList;

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
    /// Группы вывода (`format`, `filename`, `append`, `flush`, `style`, `show`), которые задал последний применённый
    /// файл; [`crate::args::Cli`] очищает список перед каждым файлом и переносит его в `file_pos`.
    pub touched: Vec<&'static str>,
    /// Позиция в `argv` последнего файла, задавшего группу: опция командной строки правее неё побеждает файл.
    pub file_pos: std::collections::BTreeMap<&'static str, usize>,
}

impl OutputConfPatch {
    fn touch(&mut self, group: &'static str) {
        if !self.touched.contains(&group) {
            self.touched.push(group);
        }
    }
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
            base.output.touch("append");
        }
        "includefile" => {
            // main-conf.c:2825-2836, `massip_parse_file`.
            let text = load(include_loader, value)?;
            parse_include_text(text.as_bytes(), value, base.scan.targets.ipv4_mut())?;
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
            o.touch("filename");
        }
        "outputformat" => {
            o.format = Some(parse_format(value)?);
            o.touch("format");
        }
        "outputshow" | "outputstatus" | "show" => {
            apply_show(o, value, true, "show")?;
            o.touch("show");
        }
        "outputnoshow" | "noshow" => {
            apply_show(o, value, false, "noshow")?;
            o.touch("show");
        }
        "outputshowopen" | "open" | "openonly" => {
            (o.show_open, o.show_closed, o.show_host) = (Some(true), Some(false), Some(false));
            o.touch("show");
        }
        "outputappend" | "appendoutput" => {
            o.append = Some(parse_bool(value));
            o.touch("append");
        }
        "outputflush" => {
            o.flush = Some(parse_bool(value));
            o.touch("flush");
        }
        "stylesheet" => {
            if o.format.is_none() {
                o.format = Some(Format::Xml);
            }
            o.stylesheet = Some(value.to_string());
            o.touch("style");
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

/// Сообщение об ошибке файла целей в форме C: `[-] file:line:col: invalid IP address on line #line`
/// (`massip_parse_file`, `massip-parse.c:880-891`); номер столбца считает и сбойный байт (`char_number++`).
fn include_error(file: &str, line: u64, col: u64) -> String {
    format!("{file}:{line}:{col}: invalid IP address on line #{line}")
}

/// Файл целей `-iL` / `includefile = FILE` (`massip_parse_file`, `massip-parse.c:822-947`, конечный автомат
/// `_parser_next` :171-770): записи разделяются пробелом, табуляцией, `\r`, `\n` и запятой; в начале записи
/// `#`, `;`, `/` и `-` начинают комментарий до конца строки; запись это `a.b.c.d`, `a.b.c.d-e.f.g.h` (дефис, байт
/// `0x96` или юникодные тире U+2010-2015) или `a.b.c.d/n`; октет не длиннее трёх цифр и не больше 255, префикс
/// не больше 32. Последняя запись без `\n` принимается (C дописывает `\n` сам, :925-950).
///
/// Уже, чем C (Р1 стиля `--excludefile`, README): IPv6 отказывает (rmasscan сканирует только IPv4), пустой октет
/// (`1..2.3`), завершающая точка (`1.2.3.`), пустой префикс (`1.2.3.4/`) и перевёрнутый диапазон отказывают, а C
/// молча читает их как `1.0.2.3`, `1.2.3.0` и `/0`. Файл `-` (stdin) не поддерживается.
pub fn parse_include_text(text: &[u8], file: &str, out: &mut RangeList) -> Result<(), String> {
    let mut p = Include {
        b: text,
        i: 0,
        line: 1,
        col: 0,
        file,
    };
    while let Some(c) = p.peek() {
        match c {
            b' ' | b'\t' | b'\r' => p.bump(),
            b'\n' => p.newline(),
            b'#' | b';' | b'/' | b'-' => {
                while let Some(c) = p.peek() {
                    if c == b'\n' {
                        p.newline();
                        break;
                    }
                    p.bump();
                }
            }
            b'0'..=b'9' => {
                let (begin, end) = p.record()?;
                out.add_range(begin, end);
            }
            // Шестнадцатеричная буква, `:` и `[` начинают IPv6 в C.
            _ => return Err(p.fail()),
        }
    }
    Ok(())
}

struct Include<'a> {
    b: &'a [u8],
    i: usize,
    line: u64,
    col: u64,
    file: &'a str,
}

impl Include<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn bump(&mut self) {
        self.i += 1;
        self.col += 1;
    }

    fn newline(&mut self) {
        self.i += 1;
        self.line += 1;
        self.col = 0;
    }

    /// Ошибка на следующем (ещё не прочитанном) байте; в конце файла это дописанный `\n`.
    fn fail(&self) -> String {
        include_error(self.file, self.line, self.col + 1)
    }

    /// Десятичный октет: 1..=3 цифры, значение не больше 255.
    fn octet(&mut self) -> Result<u32, String> {
        let (mut v, mut digits) = (0u32, 0);
        while let Some(c @ b'0'..=b'9') = self.peek() {
            v = v * 10 + u32::from(c - b'0');
            digits += 1;
            if digits > 3 || v > 255 {
                self.bump();
                return Err(include_error(self.file, self.line, self.col));
            }
            self.bump();
        }
        if digits == 0 {
            return Err(self.fail());
        }
        Ok(v)
    }

    fn address(&mut self) -> Result<u32, String> {
        let mut a = self.octet()?;
        for _ in 0..3 {
            if self.peek() != Some(b'.') {
                return Err(self.fail());
            }
            self.bump();
            a = (a << 8) | self.octet()?;
        }
        Ok(a)
    }

    /// Разделитель после записи (`','`, пробел, табуляция, `\r`, `\n`, `':'`); конец файла это дописанный `\n`.
    fn terminator(&mut self) -> Result<(), String> {
        match self.peek() {
            Some(b',' | b' ' | b'\t' | b'\r' | b':') => self.bump(),
            Some(b'\n') => self.newline(),
            None => {}
            Some(_) => return Err(self.fail()),
        }
        Ok(())
    }

    /// Дефис диапазона: `-`, байт `0x96` или U+2010..U+2015 (`E2 80 90..95`), :540-555 и :593-620.
    fn dash(&mut self) -> bool {
        match (self.peek(), self.b.get(self.i + 1), self.b.get(self.i + 2)) {
            (Some(b'-' | 0x96), _, _) => self.bump(),
            (Some(0xe2), Some(0x80), Some(0x90..=0x95)) => {
                self.bump();
                self.bump();
                self.bump();
            }
            _ => return false,
        }
        true
    }

    fn record(&mut self) -> Result<(u32, u32), String> {
        let begin = self.address()?;
        if self.dash() {
            let end = self.address()?;
            if end < begin {
                return Err(self.fail());
            }
            self.terminator()?;
            return Ok((begin, end));
        }
        if self.peek() == Some(b'/') {
            self.bump();
            let (mut prefix, mut digits) = (0u32, 0);
            while let Some(c @ b'0'..=b'9') = self.peek() {
                prefix = prefix * 10 + u32::from(c - b'0');
                digits += 1;
                self.bump();
                if digits > 3 || prefix > 32 {
                    return Err(include_error(self.file, self.line, self.col));
                }
            }
            if digits == 0 {
                return Err(self.fail());
            }
            // `_ipv4_apply_cidr`: маска старших `prefix` бит, хвост заполняется единицами.
            let mask = (0xffff_ffff_0000_0000u64 >> prefix) as u32;
            let first = begin & mask;
            self.terminator()?;
            return Ok((first, first | !mask));
        }
        self.terminator()?;
        Ok((begin, begin))
    }
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

    /// T2 M-6: `-iL` разбирает файл как `massip_parse_file` (`massip-parse.c:171-880`): токены через пробелы,
    /// табуляции, `\r`, `\n` и запятую; комментарий (`#`, `;`, `/`, `-`) в начале токена до конца строки; адрес,
    /// `a.b.c.d-e.f.g.h` (в том числе юникодные тире), `a.b.c.d/n`; октеты до 255 и трёх цифр, префикс до 32.
    #[test]
    fn includefile_grammar_follows_massip_parse_file() {
        let parse = |text: &str| -> Result<Vec<(u32, u32)>, String> {
            let mut base = FullConf::default();
            parse_include_text(text.as_bytes(), "t.txt", base.scan.targets.ipv4_mut())?;
            let mut v: Vec<(u32, u32)> = base
                .scan
                .targets
                .ipv4()
                .as_slice()
                .iter()
                .map(|r| (r.begin, r.end))
                .collect();
            v.sort_unstable();
            Ok(v)
        };
        let ip = |a: u8, b: u8, c: u8, d: u8| u32::from_be_bytes([a, b, c, d]);
        // Несколько записей в строке через запятую и пробелы, комментарии всех видов, без завершающей строки.
        let got = parse(
            "10.0.0.1,10.0.0.3  10.1.0.0/24\t# comment\n; semi\n// slash\n- dash\r\n\n10.2.0.5-10.2.0.9\n10.3.0.7",
        )
        .unwrap();
        assert_eq!(
            got,
            [
                (ip(10, 0, 0, 1), ip(10, 0, 0, 1)),
                (ip(10, 0, 0, 3), ip(10, 0, 0, 3)),
                (ip(10, 1, 0, 0), ip(10, 1, 0, 255)),
                (ip(10, 2, 0, 5), ip(10, 2, 0, 9)),
                (ip(10, 3, 0, 7), ip(10, 3, 0, 7)),
            ]
        );
        // CIDR маскирует хвост адреса (`_ipv4_apply_cidr`), /0 и /32 допустимы.
        assert_eq!(
            parse("10.1.2.3/16").unwrap(),
            [(ip(10, 1, 0, 0), ip(10, 1, 255, 255))]
        );
        assert_eq!(
            parse("1.2.3.4/32").unwrap(),
            [(ip(1, 2, 3, 4), ip(1, 2, 3, 4))]
        );
        // Юникодное тире U+2013 (E2 80 93) и байт 0x96 как дефис в диапазоне.
        assert_eq!(
            parse("10.0.0.1\u{2013}10.0.0.4\n").unwrap(),
            [(ip(10, 0, 0, 1), ip(10, 0, 0, 4))]
        );
        // Ошибки с номером строки и столбца, как `[-] file:line:col: invalid IP address on line #line`.
        for (text, line, col) in [
            ("10.0.0.1\n10.0.0.256\n", 2, 10),
            ("10.0.0.1\n\n1.2.3.4/33\n", 3, 10),
            ("1.2.3\n", 1, 6),
            ("1.2.3.4x\n", 1, 8),
            ("1.2.3.4-5.6.7.8-9\n", 1, 16),
            (",1.2.3.4\n", 1, 1),
            ("1.2.3.4,,5.6.7.8\n", 1, 9),
            ("1.2.3.4#c\n", 1, 8),
        ] {
            let e = parse(text).unwrap_err();
            assert_eq!(
                e,
                format!("t.txt:{line}:{col}: invalid IP address on line #{line}"),
                "{text:?}"
            );
        }
        // Осознанно уже C: IPv6, пустой октет, завершающая точка, пустой префикс, перевёрнутый диапазон.
        for text in [
            "abc\n",
            "::1\n",
            "[2001:db8::1]\n",
            "1..2.3\n",
            "1.2.3.\n",
            "1.2.3.4/\n",
            "10.0.0.9-10.0.0.1\n",
        ] {
            assert!(parse(text).is_err(), "{text:?}");
        }
    }
}
