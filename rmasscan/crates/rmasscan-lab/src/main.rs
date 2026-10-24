fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        help();
        return;
    };
    let result = match command.as_str() {
        "--help" | "-h" | "help" => {
            help();
            return;
        }
        "--version" | "-V" => {
            println!("rmasscan-lab {} (Rust)", env!("CARGO_PKG_VERSION"));
            return;
        }
        "verify-wire" => rmasscan_lab::pcap::run(rest),
        "windows-verify" => rmasscan_lab::verify::run(rest),
        "vm-lab" => rmasscan_lab::vm_lab::run(rest),
        "peer" => rmasscan_lab::peer::run(rest),
        "capture" => rmasscan_lab::capture::run(rest),
        "deploy-manifest" => rmasscan_lab::deploy::run(rest),
        "wire-suite" => rmasscan_lab::wire_suite::run(rest),
        "windows-suite" => rmasscan_lab::windows_suite::run(rest),
        "oracle-fixtures" => rmasscan_lab::oracle::run(rest),
        "oracle-util" => rmasscan_lab::oracle_util::run(rest),
        _ => Err(format!("unknown command {command}; use --help")),
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(message) => {
            eprintln!("NOT RUN: {message}");
            std::process::exit(2);
        }
    }
}
fn help() {
    println!(
        "rmasscan-lab — Rust laboratory tools\nCommands:\n  verify-wire       compare ordered SYN packets in classic pcap\n  windows-verify    verify saved Windows evidence (offline)\n  vm-lab            isolated Linux-hosted Windows VM network\n  peer              Linux peer/listeners/injection\n  capture           Linux recorder and evidence manifests\n  deploy-manifest   record the commit and sha256 of an installed rmasscan-lab (run on home-pc)\n  wire-suite        Linux acceptance and performance suites\n  windows-suite     explicit Windows VM orchestration\n  oracle-fixtures   independent pinned C-oracle wire fixtures\n  oracle-util       C-oracle build metadata helpers\n\nNo command runs implicitly. Raw operations require an explicit isolated lab."
    );
}
