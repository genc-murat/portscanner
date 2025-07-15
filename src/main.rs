mod os_fingerprinting;
mod port_parser;
mod scanner;
mod service_detection;
mod stealth;
mod udp;

use clap::{Arg, Command};
use scanner::PortScanner;
use udp::UdpScanner; // Import to use get_common_udp_ports

pub struct Args {
    pub target: String,
    pub ports: String,
    pub concurrency: usize,
    pub timeout: u64,
    pub json: bool,
    pub banner: bool,
    pub stealth: bool,
    pub scan_type: String,
    pub protocol: Option<String>, // Add protocol option
    pub service_detection: bool,
    pub os_detection: bool,
    pub aggressive: bool,
}

#[tokio::main]
async fn main() {
    let matches = Command::new("portscanner")
        .version("0.4.0")
        .about("A fast, modern port scanner with TCP/UDP support, advanced service detection and OS fingerprinting")
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
            Arg::new("protocol")
                .long("protocol")
                .value_name("PROTOCOL")
                .help("Protocol to scan: tcp, udp, or both")
                .default_value("tcp")
                .value_parser(["tcp", "udp", "both", "all"])
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
                .help("Enable banner grabbing (TCP only)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("stealth")
                .short('s')
                .long("stealth")
                .help("Use stealth SYN scan for TCP (requires root/admin privileges)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("scan_type")
                .long("scan-type")
                .value_name("TYPE")
                .help("Scan type: tcp, syn, udp, or auto")
                .default_value("auto")
                .value_parser(["tcp", "syn", "udp", "auto"])
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
                .help("Enable OS fingerprinting (TCP only)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("aggressive")
                .short('A')
                .long("aggressive")
                .help("Enable aggressive detection (service detection + banner grabbing + OS detection)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("udp_common")
                .short('U')
                .long("udp-common")
                .help("Scan common UDP ports (equivalent to --protocol udp --ports <common_udp_ports>)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("top_ports")
                .long("top-ports")
                .value_name("NUM")
                .help("Scan top N most common ports for the selected protocol(s)")
                .value_parser(clap::value_parser!(u16))
        )
        .get_matches();

    let mut args = Args {
        target: matches.get_one::<String>("target").unwrap().clone(),
        ports: matches.get_one::<String>("ports").unwrap().clone(),
        protocol: matches.get_one::<String>("protocol").cloned(),
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

    // Handle special port options
    if matches.get_flag("udp_common") {
        args.protocol = Some("udp".to_string());
        let common_ports = UdpScanner::get_common_udp_ports();
        args.ports = common_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>()
            .join(",");
        println!("UDP common ports mode enabled");
    }

    if let Some(top_n) = matches.get_one::<u16>("top_ports") {
        args.ports = get_top_ports(*top_n, &args.protocol.as_deref().unwrap_or("tcp"));
        println!("Scanning top {} ports", top_n);
    }

    if args.aggressive {
        args.service_detection = true;
        args.banner = true;
        args.os_detection = true;
        println!("Aggressive mode enabled (service detection + banner grabbing + OS detection)");
    }

    // Validate protocol combinations
    if args.stealth && args.protocol.as_deref() == Some("udp") {
        eprintln!("Warning: Stealth SYN scan is not applicable to UDP. Using regular UDP scan.");
        args.stealth = false;
    }

    if args.banner && args.protocol.as_deref() == Some("udp") {
        eprintln!("Warning: Banner grabbing is not applicable to UDP scanning.");
        args.banner = false;
    }

    if args.os_detection && args.protocol.as_deref() == Some("udp") {
        eprintln!(
            "Warning: OS detection requires TCP ports. No OS detection will be performed for UDP-only scans."
        );
        args.os_detection = false;
    }

    println!("Port Scanner v0.4.0");
    println!("Target: {}", args.target);
    println!("Ports: {}", args.ports);
    println!("Protocol(s): {}", args.protocol.as_deref().unwrap_or("tcp"));
    println!("Concurrent connections: {}", args.concurrency);
    println!("Timeout: {}ms", args.timeout);

    if args.stealth {
        println!("Stealth SYN scan enabled");
        #[cfg(not(target_os = "linux"))]
        println!("Warning: SYN scan not fully supported on this OS, falling back to TCP connect");
        #[cfg(target_os = "linux")]
        println!("Note: SYN scan requires root privileges");
    }

    if args.banner && args.protocol.as_deref() != Some("udp") {
        println!("Banner grabbing enabled");
    }

    if args.service_detection {
        println!("Advanced service detection enabled");
    }

    if args.os_detection {
        println!("OS fingerprinting enabled");
    }

    // UDP-specific warnings
    if args.protocol.as_deref() == Some("udp") || args.protocol.as_deref() == Some("both") {
        println!("\nUDP Scanning Notes:");
        println!("• UDP scans may take longer due to protocol characteristics");
        println!("• Many UDP services may appear as 'open|filtered'");
        println!("• Consider using --udp-common for faster common port scanning");
        println!("• Increase timeout for better UDP detection accuracy");
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

fn get_top_ports(n: u16, protocol: &str) -> String {
    let tcp_top_ports = vec![
        80, 443, 22, 21, 25, 53, 110, 993, 995, 143, 23, 135, 139, 445, 3389, 5900, 1433, 3306,
        5432, 1521, 111, 2049, 2000, 8080, 8000, 8443, 8888, 9000, 9200, 5000, 5001, 6379, 27017,
        11211, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 1080, 1194, 1701, 1723, 500, 4500, 1900,
        5353, 5060, 5061, 554, 1935, 8554, 873, 548, 427, 631, 9100, 515, 512, 513, 514, 543, 544,
        5222, 5223, 5269, 6667, 6668, 6669, 7000, 7001, 8009, 8161, 8983, 9042, 9160, 11000, 11001,
        61613, 61614, 61616, 62078, 1099, 1098, 4848, 8081, 8086, 8125, 8126, 9090, 3000, 3001,
        4000, 5601, 9229, 2375, 2376, 2377, 4243, 6443, 8001, 10250, 10255,
    ];

    let udp_top_ports = vec![
        53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1701, 1900, 4500, 5353, 5060,
        6881, 27015, 27017, 1812, 1813, 1645, 1646, 2049, 111, 1434, 1433, 5432, 3306, 11211, 6379,
        27017, 27018, 27019, 28017, 50000, 389, 636, 3268, 3269, 179, 521, 546, 547, 1234, 3000,
        8086, 9200, 9300, 5601, 8125, 8126, 1099, 3690, 4848, 5000, 6000, 6001, 6002, 6003, 6004,
        6005, 7000, 7001, 8000, 8009, 8081, 8161, 8983, 9042, 9160, 11211, 1900, 5004, 554, 1935,
        8554, 873, 548, 6000, 631, 9100, 515, 79, 113, 119, 563, 31337, 12345, 11111, 1337, 2000,
        5984, 7474, 9418, 1414, 1830, 5984, 7474,
    ];

    let ports = match protocol {
        "udp" => &udp_top_ports,
        "tcp" | _ => &tcp_top_ports,
    };

    let selected_ports: Vec<u16> = ports.iter().take(n as usize).cloned().collect();
    selected_ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<String>>()
        .join(",")
}
