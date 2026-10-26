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
    let result = dns_lookup::lookup_addr(&ip.into()).ok();
    let valid = result.and_then(|s| studio_inspection::valid_hostname(&s));
    println!(
        "{}",
        serde_json::to_string(&valid).expect("string serialization")
    );
}
