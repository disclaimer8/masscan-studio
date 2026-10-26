//! One bounded resolver invocation. The unprivileged parent owns the 3s deadline
//! and kills/reaps this process, including a stuck system NSS provider.
#[cfg(target_os = "macos")]
#[path = "../mac_dns.rs"]
mod mac_dns;
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 || args[0] != "--reverse" {
        std::process::exit(2);
    }
    let Ok(ip) = args[1].parse::<std::net::Ipv4Addr>() else {
        std::process::exit(2)
    };
    #[cfg(target_os = "macos")]
    let result = mac_dns::lookup(ip);
    #[cfg(not(target_os = "macos"))]
    let result = match dns_lookup::lookup_addr(&ip.into()) {
        Ok(name) => Ok(Some(name)),
        Err(e) => system_failure(e.kind(), &e.to_string()),
    };
    let valid = result.and_then(|name| match name {
        Some(name) => studio_inspection::valid_hostname(&name)
            .map(Some)
            .ok_or_else(|| "System DNS resolver returned an invalid hostname".to_string()),
        None => Ok(None),
    });
    match valid {
        Ok(name) => println!(
            "{}",
            serde_json::to_string(&name).expect("string serialization")
        ),
        Err(error) => {
            eprintln!("{}", studio_inspection::clean(&error));
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn system_failure(
    kind: dns_lookup::LookupErrorKind,
    detail: &str,
) -> studio_inspection::Result<Option<String>> {
    use dns_lookup::LookupErrorKind::{NoData, NoName};
    match kind {
        NoName | NoData => Ok(None),
        _ => Err(format!("System DNS resolver failed: {detail}")),
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;
    use dns_lookup::LookupErrorKind::*;
    #[test]
    fn only_missing_name_or_data_is_negative_answer() {
        for kind in [NoName, NoData] {
            assert_eq!(system_failure(kind, "missing").unwrap(), None);
        }
        for kind in [
            Again, Fail, Memory, System, IO, Badflags, Family, Socktype, Service, Unknown,
        ] {
            assert!(
                system_failure(kind, "fixture failure")
                    .unwrap_err()
                    .contains("fixture failure")
            );
        }
    }
}
