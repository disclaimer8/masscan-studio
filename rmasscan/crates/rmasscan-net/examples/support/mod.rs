//! Общее для лабораторного harness: JSON-хелперы, измерения процесса и
//! идентичность сборки. Идентичность попадает в КАЖДЫЙ JSON-вывод, чтобы
//! доказательство было привязано к точной сборке и среде.

pub mod metrics;

use std::fmt::Write as _;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

/// Коммит исходников. Подставляется при сборке окружением
/// `RMASSCAN_SOURCE_COMMIT` (скрипт упаковки передаёт `git rev-parse HEAD`);
/// без build.rs и без C. Сборка без переменной честно сообщает `unknown`.
pub const SOURCE_COMMIT: &str = match option_env!("RMASSCAN_SOURCE_COMMIT") {
    Some(c) => c,
    None => "unknown",
};

pub fn js(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

pub fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn json_opt_str(v: Option<&str>) -> String {
    v.map_or_else(|| "null".to_string(), js)
}

/// SHA-256 исполняемого файла, считается во время работы из `current_exe`.
fn exe_hash() -> (Option<String>, Option<String>) {
    let Ok(path) = std::env::current_exe() else {
        return (None, None);
    };
    let hash = std::fs::read(&path).ok().map(|b| sha256_hex(&b));
    (Some(path.display().to_string()), hash)
}

/// Идентификатор слоя сырого ввода-вывода текущей ОС. `npcap_abi` остаётся ради
/// существующего верификатора Windows.
pub fn raw_io_abi() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        rmasscan_net::BPF_ABI_ID
    }
    #[cfg(windows)]
    {
        rmasscan_net::NPCAP_ABI_ID
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        "AF_PACKET via libc"
    }
}

/// Часть идентичности, не зависящая от Npcap: коммит, хэш бинарника, ОС,
/// ABI-слой и права процесса. Вычисляется один раз.
pub fn identity_json() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let (path, hash) = exe_hash();
        format!(
            "{{\"source_commit\":{},\"binary_sha256\":{},\"binary_path\":{},\
\"os\":{{\"family\":{},\"arch\":{},\"version\":{}}},\"npcap_abi\":{},\"raw_io_abi\":{},\"elevated\":{},\"restricted_token\":{}}}",
            js(SOURCE_COMMIT),
            json_opt_str(hash.as_deref()),
            json_opt_str(path.as_deref()),
            js(std::env::consts::OS),
            js(std::env::consts::ARCH),
            json_opt_str(rmasscan_net::os_version().as_deref()),
            js(rmasscan_net::NPCAP_ABI_ID),
            js(raw_io_abi()),
            metrics::json_opt_bool(metrics::elevated()),
            metrics::json_opt_bool(metrics::restricted()),
        )
    })
}

/// JSON-блок Npcap из перечня (`null`, если перечень недоступен).
pub fn npcap_json(inv: &rmasscan_net::Inventory) -> String {
    let dlls = inv
        .dlls
        .iter()
        .map(|d| {
            format!(
                "{{\"name\":{},\"path\":{},\"sha256\":{},\"version\":{}}}",
                js(&d.name),
                js(&d.path),
                js(&d.sha256),
                json_opt_str(d.version.as_deref())
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"lib_version\":{},\"utf8_text\":{},\"driver_version\":{},\"dlls\":[{dlls}]}}",
        js(&inv.lib_version),
        inv.utf8_text,
        json_opt_str(inv.driver_version.as_deref()),
    )
}

pub fn mac_text(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_has_commit_hash_os_abi() {
        let id = identity_json();
        for k in [
            "\"source_commit\":",
            "\"binary_sha256\":\"",
            "\"os\":{",
            "\"npcap_abi\":",
            "\"raw_io_abi\":",
            "\"elevated\":",
            "\"restricted_token\":",
        ] {
            assert!(id.contains(k), "{k} missing from {id}");
        }
    }

    #[test]
    fn identity_has_raw_io_abi_and_os_version() {
        let id = identity_json();
        let abi = format!("\"raw_io_abi\":{}", js(raw_io_abi()));
        assert!(id.contains(&abi), "{abi} missing from {id}");
        #[cfg(target_os = "macos")]
        {
            assert_eq!(raw_io_abi(), rmasscan_net::BPF_ABI_ID);
            let v = rmasscan_net::os_version().expect("kern.osproductversion");
            assert!(id.contains(&format!("\"version\":{}", js(&v))), "{id}");
        }
        // npcap_abi остаётся для верификатора Windows.
        assert!(id.contains("\"npcap_abi\":\""), "{id}");
    }

    #[test]
    fn json_escaping() {
        assert_eq!(js("a\"b\\c\n\u{1}"), "\"a\\\"b\\\\c\\n\\u0001\"");
    }
}
