mod html_generator;
mod os_fingerprinting;
mod port_parser;
mod scanner;
mod service_detection;
mod ssl;
mod stealth;
mod udp;

use clap::{Arg, Command};
use scanner::PortScanner;
use std::net::IpAddr;
use udp::UdpScanner;

pub struct Args {
    pub target: String,
    pub ports: String,
    pub concurrency: usize,
    pub timeout: u64,
    pub json: bool,
    pub html_output: Option<String>,
    pub banner: bool,
    pub stealth: bool,
    pub scan_type: String,
    pub protocol: Option<String>,
    pub service_detection: bool,
    pub os_detection: bool,
    pub ssl_analysis: bool,
    pub aggressive: bool,
}

#[tokio::main]
async fn main() {
    let matches = Command::new("portscanner")
        .version("0.4.0") 
        .about("A fast, modern port scanner with IPv4/IPv6 dual-stack support, TCP/UDP scanning, advanced service detection, OS fingerprinting, and HTML reports")
        .arg(
            Arg::new("target")
                .short('t')
                .long("target")
                .value_name("TARGET")
                .help("Target IPv4/IPv6 address or hostname (e.g., 192.168.1.1, 2001:db8::1, example.com)")
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
                .help("Protocol to scan: tcp, udp, or both (works with IPv4 and IPv6)")
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
                .help("Connection timeout in milliseconds (IPv6 may require higher values)")
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
            Arg::new("html") // New HTML argument
                .long("html")
                .value_name("FILENAME")
                .help("Output results in an HTML file")
        )
        .arg(
            Arg::new("banner")
                .short('b')
                .long("banner")
                .help("Enable banner grabbing (TCP only, works with IPv4/IPv6)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("stealth")
                .short('s')
                .long("stealth")
                .help("Use stealth SYN scan for TCP (requires root/admin privileges, supports IPv4/IPv6)")
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
                .help("Enable advanced service detection (IPv4/IPv6)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("os_detection")
                .short('O')
                .long("os-detection")
                .help("Enable OS fingerprinting (TCP only, IPv4/IPv6)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("ssl_analysis")
                .long("ssl-analysis")
                .help("Enable SSL/TLS analysis for HTTPS and other SSL services (IPv4/IPv6)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("aggressive")
                .short('A')
                .long("aggressive")
                .help("Enable aggressive detection (service detection + banner grabbing + OS detection + SSL analysis)")
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
        .arg(
            Arg::new("ipv6_only")
                .long("ipv6-only")
                .help("Force IPv6 resolution for hostnames (ignore IPv4 A records)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .help("Force IPv4 resolution for hostnames (ignore IPv6 AAAA records)")
                .action(clap::ArgAction::SetTrue)
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
        html_output: matches.get_one::<String>("html").cloned(), // Get HTML filename
        banner: matches.get_flag("banner"),
        stealth: matches.get_flag("stealth"),
        scan_type: matches.get_one::<String>("scan_type").unwrap().clone(),
        service_detection: matches.get_flag("service_detection"),
        os_detection: matches.get_flag("os_detection"),
        ssl_analysis: matches.get_flag("ssl_analysis"),
        aggressive: matches.get_flag("aggressive"),
    };

    // IPv6/IPv4 resolution preferences
    let ipv6_only = matches.get_flag("ipv6_only");
    let ipv4_only = matches.get_flag("ipv4_only");

    if ipv6_only && ipv4_only {
        eprintln!("Error: Cannot specify both --ipv6-only and --ipv4-only");
        std::process::exit(1);
    }

    // Validate and normalize target address
    let target_info = validate_and_resolve_target(&args.target, ipv4_only, ipv6_only).await;
    match target_info {
        Ok((resolved_target, ip_version)) => {
            args.target = resolved_target;
            if !args.json {
                if let Some(version) = ip_version {
                    println!("Target IP version: {}", version);
                }
            }
        }
        Err(e) => {
            eprintln!("Error resolving target: {}", e);
            std::process::exit(1);
        }
    }

    // Handle special port options
    if matches.get_flag("udp_common") {
        args.protocol = Some("udp".to_string());
        let common_ports = UdpScanner::get_common_udp_ports();
        args.ports = common_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>()
            .join(",");
        if !args.json {
            println!("UDP common ports mode enabled");
        }
    }

    if let Some(top_n) = matches.get_one::<u16>("top_ports") {
        args.ports = get_top_ports(*top_n, &args.protocol.as_deref().unwrap_or("tcp"));
        if !args.json {
            println!("Scanning top {} ports", top_n);
        }
    }

    if args.aggressive {
        args.service_detection = true;
        args.banner = true;
        args.os_detection = true;
        args.ssl_analysis = true; // Include SSL analysis in aggressive mode
        if !args.json {
            println!("Aggressive mode enabled (service detection + banner grabbing + OS detection + SSL analysis)");
        }
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
        eprintln!("Warning: OS detection requires TCP ports. No OS detection will be performed for UDP-only scans.");
        args.os_detection = false;
    }

    // IPv6-specific warnings and recommendations
    if is_ipv6_target(&args.target) {
        if args.stealth && !is_root() {
            eprintln!("Note: IPv6 stealth SYN scan requires root privileges");
        }

        if args.timeout < 5000
            && (args.protocol.as_deref() == Some("udp") || args.protocol.as_deref() == Some("both"))
        {
            eprintln!("Recommendation: Consider increasing timeout for IPv6 UDP scanning (--timeout 5000 or higher)");
        }
    }

    if !args.json {
        println!("Port Scanner v0.4.0");
        println!("Target: {}", args.target);

        // Show IPv6 address format if applicable
        if is_ipv6_target(&args.target) {
            if let Ok(normalized) = normalize_ipv6_display(&args.target) {
                if normalized != args.target {
                    println!("Normalized: {}", normalized);
                }
            }
        }

        println!("Ports: {}", args.ports);
        println!("Protocol(s): {}", args.protocol.as_deref().unwrap_or("tcp"));
        println!("Concurrent connections: {}", args.concurrency);
        println!("Timeout: {}ms", args.timeout);

        if args.stealth {
            println!("Stealth SYN scan enabled");
            #[cfg(not(target_os = "linux"))]
            println!(
                "Warning: SYN scan not fully supported on this OS, falling back to TCP connect"
            );
            #[cfg(target_os = "linux")]
            println!("Note: SYN scan requires root privileges for both IPv4 and IPv6");
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

        if args.ssl_analysis {
            println!("SSL/TLS analysis enabled");
        }

        // IPv6-specific notes
        if is_ipv6_target(&args.target) {
            println!("\nIPv6 Scanning Notes:");
            println!("• IPv6 stealth scanning requires root privileges");
            println!("• All features (SSL, service detection, OS fingerprinting) work with IPv6");
            println!("• Consider using higher timeouts for IPv6 networks");

            if args.target.contains('%') {
                println!("• Link-local address detected with zone identifier");
            }
        }

        // UDP-specific warnings
        if args.protocol.as_deref() == Some("udp") || args.protocol.as_deref() == Some("both") {
            println!("\nUDP Scanning Notes:");
            println!("• UDP scans may take longer due to protocol characteristics");
            println!("• Many UDP services may appear as 'open|filtered'");
            println!("• Consider using --udp-common for faster common port scanning");
            println!("• Increase timeout for better UDP detection accuracy");
            if is_ipv6_target(&args.target) {
                println!("• IPv6 UDP scanning may require even higher timeouts");
            }
        }
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

            if e.contains("IPv6") || e.contains("address") {
                eprintln!("Hint: Check IPv6 address format or network connectivity");
                eprintln!("   IPv6 examples: 2001:db8::1, ::1, fe80::1%eth0");
                eprintln!("   Use --ipv4-only or --ipv6-only to force protocol version");
            }

            std::process::exit(1);
        }
    }
}

async fn validate_and_resolve_target(
    target: &str,
    ipv4_only: bool,
    ipv6_only: bool,
) -> Result<(String, Option<String>), String> {
    use std::net::ToSocketAddrs;

    // If it's already a valid IP address, return it
    if let Ok(ip) = target.parse::<IpAddr>() {
        let version = if ip.is_ipv4() { "IPv4" } else { "IPv6" };
        return Ok((target.to_string(), Some(version.to_string())));
    }

    // If it contains brackets, try to parse as IPv6
    if target.starts_with('[') && target.ends_with(']') {
        let inner = &target[1..target.len() - 1];
        if let Ok(ip) = inner.parse::<IpAddr>() {
            return Ok((inner.to_string(), Some("IPv6".to_string())));
        }
    }

    // Try hostname resolution
    let socket_addrs = format!("{}:80", target)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve hostname '{}': {}", target, e))?;

    let mut ipv4_addrs = Vec::new();
    let mut ipv6_addrs = Vec::new();

    for addr in socket_addrs {
        match addr.ip() {
            IpAddr::V4(ip) => ipv4_addrs.push(ip),
            IpAddr::V6(ip) => ipv6_addrs.push(ip),
        }
    }

    // Apply resolution preferences
    if ipv6_only {
        if let Some(ipv6) = ipv6_addrs.first() {
            return Ok((ipv6.to_string(), Some("IPv6".to_string())));
        } else {
            return Err(format!("No IPv6 address found for hostname '{}'", target));
        }
    }

    if ipv4_only {
        if let Some(ipv4) = ipv4_addrs.first() {
            return Ok((ipv4.to_string(), Some("IPv4".to_string())));
        } else {
            return Err(format!("No IPv4 address found for hostname '{}'", target));
        }
    }

    // Default: prefer IPv4, fallback to IPv6
    if let Some(ipv4) = ipv4_addrs.first() {
        Ok((ipv4.to_string(), Some("IPv4".to_string())))
    } else if let Some(ipv6) = ipv6_addrs.first() {
        Ok((ipv6.to_string(), Some("IPv6".to_string())))
    } else {
        Err(format!("No IP address found for hostname '{}'", target))
    }
}

fn is_ipv6_target(target: &str) -> bool {
    // Check if target contains IPv6 characteristics
    target.contains(':') && !target.contains("://") || target.starts_with('[')
}

fn normalize_ipv6_display(addr: &str) -> Result<String, String> {
    use std::net::Ipv6Addr;

    // Remove brackets if present
    let clean_addr = if addr.starts_with('[') && addr.ends_with(']') {
        &addr[1..addr.len() - 1]
    } else {
        addr
    };

    // Handle zone identifier
    let (addr_part, zone) = if let Some(percent_pos) = clean_addr.find('%') {
        (&clean_addr[..percent_pos], Some(&clean_addr[percent_pos..]))
    } else {
        (clean_addr, None)
    };

    let ipv6: Ipv6Addr = addr_part
        .parse()
        .map_err(|e| format!("Invalid IPv6 address: {}", e))?;

    let normalized = if let Some(zone) = zone {
        format!("{}{}", ipv6, zone)
    } else {
        ipv6.to_string()
    };

    Ok(normalized)
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

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}
