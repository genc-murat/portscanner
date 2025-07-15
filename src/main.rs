mod os_fingerprinting;
mod port_parser;
mod scanner;
mod service_detection;
mod stealth;

use clap::{Arg, Command};
use scanner::PortScanner;

pub struct Args {
    pub target: String,
    pub ports: String,
    pub concurrency: usize,
    pub timeout: u64,
    pub json: bool,
    pub banner: bool,
    pub stealth: bool,
    pub scan_type: String,
    pub service_detection: bool,
    pub os_detection: bool,
    pub aggressive: bool,
}

#[tokio::main]
async fn main() {
    let matches = Command::new("portscanner")
        .version("0.4.0")
        .about("A fast, modern port scanner with advanced service detection and OS fingerprinting")
        .arg(
            Arg::new("target")
                .short('t')
                .long("target")
                .value_name("TARGET")
                .help("Target IP address or hostname")
                .required(true)
        )
        .arg(
            Arg::new("ports")
                .short('p')
                .long("ports")
                .value_name("PORTS")
                .help("Ports to scan (e.g., 80,443,22-25)")
                .default_value("1-1000")
        )
        .arg(
            Arg::new("concurrency")
                .short('c')
                .long("concurrency")
                .value_name("NUM")
                .help("Number of concurrent connections")
                .default_value("100")
        )
        .arg(
            Arg::new("timeout")
                .short('T')
                .long("timeout")
                .value_name("MS")
                .help("Connection timeout in milliseconds")
                .default_value("3000")
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .help("Output results in JSON format")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("banner")
                .short('b')
                .long("banner")
                .help("Enable banner grabbing")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("stealth")
                .short('s')
                .long("stealth")
                .help("Use stealth SYN scan (requires root/admin privileges)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("scan_type")
                .long("scan-type")
                .value_name("TYPE")
                .help("Scan type: tcp, syn, or auto")
                .default_value("auto")
        )
        .arg(
            Arg::new("service_detection")
                .long("service-detection")
                .help("Enable advanced service detection")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("os_detection")
                .short('O')
                .long("os-detection")
                .help("Enable OS fingerprinting")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("aggressive")
                .short('A')
                .long("aggressive")
                .help("Enable aggressive detection (service detection + banner grabbing + OS detection)")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    let mut args = Args {
        target: matches.get_one::<String>("target").unwrap().clone(),
        ports: matches.get_one::<String>("ports").unwrap().clone(),
        concurrency: matches
            .get_one::<String>("concurrency")
            .unwrap()
            .parse()
            .unwrap_or(100),
        timeout: matches
            .get_one::<String>("timeout")
            .unwrap()
            .parse()
            .unwrap_or(3000),
        json: matches.get_flag("json"),
        banner: matches.get_flag("banner"),
        stealth: matches.get_flag("stealth"),
        scan_type: matches.get_one::<String>("scan_type").unwrap().clone(),
        service_detection: matches.get_flag("service_detection"),
        os_detection: matches.get_flag("os_detection"),
        aggressive: matches.get_flag("aggressive"),
    };

    if args.aggressive {
        args.service_detection = true;
        args.banner = true;
        args.os_detection = true;
        println!("Aggressive mode enabled (service detection + banner grabbing + OS detection)");
    }

    println!("Port Scanner v0.4.0");
    println!("Target: {}", args.target);
    println!("Ports: {}", args.ports);
    println!("Concurrent connections: {}", args.concurrency);
    println!("Timeout: {}ms", args.timeout);

    if args.stealth {
        println!("Stealth SYN scan enabled");
        #[cfg(not(target_os = "linux"))]
        println!("Warning: SYN scan not fully supported on this OS, falling back to TCP connect");
        #[cfg(target_os = "linux")]
        println!("Note: SYN scan requires root privileges");
    }

    if args.banner && args.stealth {
        println!("Warning: Banner grabbing not available with stealth SYN scan");
    }

    if args.service_detection {
        println!("Advanced service detection enabled");
    }

    if args.os_detection {
        println!("OS fingerprinting enabled");
    }

    match PortScanner::new(args) {
        Ok(scanner) => scanner.run().await,
        Err(e) => {
            eprintln!("Error: {}", e);

            if e.contains("raw socket") || e.contains("root") {
                eprintln!("Hint: Try running with sudo for SYN scan, or use regular TCP scan");
                eprintln!(
                    "   Example: sudo ./portscanner -t {} --stealth",
                    matches.get_one::<String>("target").unwrap()
                );
            }

            std::process::exit(1);
        }
    }
}
