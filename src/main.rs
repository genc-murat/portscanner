mod html_generator;
mod os_fingerprinting;
mod port_parser;
mod progress;
mod scanner;
mod service_detection;
mod ssl;
mod stealth;
mod udp;

use clap::{Arg, Command};
use colored::*;
use progress::{
    print_error_help, print_scan_start_animation, print_welcome_banner,
    show_completion_celebration, Args, InteractiveScanner,
};
use scanner::PortScanner;
use std::io::{self, Write};
use std::net::IpAddr;
use std::time::Duration;
use udp::UdpScanner;

fn print_banner() {
    print_welcome_banner();
}

fn feature_showcase() {
    println!("{}", "\n✨ Features:".yellow().bold());
    println!("   {} TCP & UDP Scanning", "🔍".cyan());
    println!("   {} Stealth SYN Scan", "👤".cyan());
    println!("   {} Service Detection", "🔧".cyan());
    println!("   {} OS Fingerprinting", "🖥️".cyan());
    println!("   {} SSL/TLS Analysis", "🔐".cyan());
    println!("   {} IPv6 Support", "🌐".cyan());
    println!("   {} HTML Reports", "📊".cyan());
    println!("   {} JSON Export", "📋".cyan());
}

fn create_interactive_command() -> Command {
    Command::new("portscanner")
        .version("0.4.0")
        .about("🚀 A fast, modern port scanner with advanced features")
        .long_about(format!("{}

{}
  • TCP & UDP Scanning with concurrent connections
  • Stealth SYN scan for Linux/Unix systems
  • Advanced service detection with 150+ signatures
  • OS fingerprinting using TCP/IP stack analysis
  • SSL/TLS security analysis and vulnerability detection
  • Risk assessment and compliance checking
  • IPv6 support for modern networking
  • Professional HTML reports and JSON export",
            "🚀 Advanced Port Scanner with Modern Features".cyan().bold(),
            "Features:".yellow().bold()
        ))
        .arg(
            Arg::new("target")
                .short('t')
                .long("target")
                .value_name("IP/HOSTNAME")
                .help("🎯 Target IP address or hostname")
                .long_help("Target to scan (supports IPv4, IPv6, and hostnames)\nExamples: 192.168.1.1, 2001:db8::1, google.com")
                .required(true)
        )
        .arg(
            Arg::new("ports")
                .short('p')
                .long("ports")
                .value_name("PORT_RANGE")
                .help("📡 Ports to scan (supports ranges and lists)")
                .long_help("Port specification supports:\n  • Single ports: 80,443,22\n  • Ranges: 1-1000\n  • Mixed: 22,80,443,8000-9000")
                .default_value("1-1000")
        )
        .arg(
            Arg::new("protocol")
                .long("protocol")
                .value_name("PROTOCOL")
                .help("🔌 Protocol to scan")
                .long_help("Protocol selection:\n  • tcp: TCP ports only\n  • udp: UDP ports only\n  • both: Both TCP and UDP")
                .default_value("tcp")
                .value_parser(["tcp", "udp", "both", "all"])
        )
        .arg(
            Arg::new("concurrency")
                .short('c')
                .long("concurrency")
                .value_name("THREADS")
                .help("⚡ Number of concurrent connections")
                .long_help("Controls scan speed vs system load\nRecommended: 100-500 for local networks, 50-100 for internet")
                .default_value("100")
        )
        .arg(
            Arg::new("timeout")
                .short('T')
                .long("timeout")
                .value_name("MILLISECONDS")
                .help("⏱️ Connection timeout")
                .long_help("Connection timeout in milliseconds\nRecommended: 1000-3000 for local, 3000-5000 for internet")
                .default_value("3000")
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .help("📋 Output in JSON format")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("html")
                .long("html")
                .value_name("FILENAME")
                .help("📊 Generate HTML report")
                .long_help("Creates a professional HTML report with charts and analysis")
        )
        .arg(
            Arg::new("banner")
                .short('b')
                .long("banner")
                .help("🏷️ Enable banner grabbing")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("stealth")
                .short('s')
                .long("stealth")
                .help("👤 Use stealth SYN scan (requires root)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("scan_type")
                .long("scan-type")
                .value_name("TYPE")
                .help("🔍 Scan technique")
                .default_value("auto")
                .value_parser(["tcp", "syn", "udp", "auto"])
        )
        .arg(
            Arg::new("service_detection")
                .long("service-detection")
                .help("🔧 Enable advanced service detection")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("os_detection")
                .short('O')
                .long("os-detection")
                .help("🖥️ Enable OS fingerprinting")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("ssl_analysis")
                .long("ssl-analysis")
                .help("🔐 Enable SSL/TLS analysis")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("risk_assessment")
                .long("risk-assessment")
                .help("🛡️ Enable comprehensive security risk assessment")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("compliance_check")
                .long("compliance")
                .value_name("FRAMEWORK")
                .help("📋 Check compliance against security frameworks")
                .long_help("Check compliance against security frameworks:\n  • pci-dss: Payment Card Industry Data Security Standard\n  • nist: NIST Cybersecurity Framework\n  • all: Check all supported frameworks")
                .value_parser(["pci-dss", "nist", "all"])
        )
        .arg(
            Arg::new("threat_model")
                .long("threat-model")
                .help("🎯 Generate threat model and attack scenarios")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("aggressive")
                .short('A')
                .long("aggressive")
                .help("🚀 Enable all detection methods")
                .long_help("Enables: service detection + banner grabbing + OS detection + SSL analysis + risk assessment")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("udp_common")
                .short('U')
                .long("udp-common")
                .help("📡 Scan common UDP ports")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("top_ports")
                .long("top-ports")
                .value_name("NUMBER")
                .help("🎯 Scan top N most common ports")
                .value_parser(clap::value_parser!(u16))
        )
        .arg(
            Arg::new("ipv6_only")
                .long("ipv6-only")
                .help("🌐 Force IPv6 resolution")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .help("🌍 Force IPv4 resolution")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("interactive")
                .short('i')
                .long("interactive")
                .help("🎮 Interactive mode")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("quick")
                .short('q')
                .long("quick")
                .help("⚡ Quick scan mode (top 100 ports)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("📝 Verbose output")
                .action(clap::ArgAction::SetTrue)
        )
}

fn run_interactive_mode() -> Result<Args, String> {
    println!("{}", "\n🎮 Interactive Mode".cyan().bold());
    println!("{}", "═".repeat(50));

    print!("🎯 Enter target (IP/hostname): ");
    io::stdout().flush().unwrap();
    let mut target = String::new();
    io::stdin().read_line(&mut target).unwrap();
    let target = target.trim().to_string();

    print!("📡 Enter ports (default: 1-1000): ");
    io::stdout().flush().unwrap();
    let mut ports = String::new();
    io::stdin().read_line(&mut ports).unwrap();
    let ports = if ports.trim().is_empty() {
        "1-1000".to_string()
    } else {
        ports.trim().to_string()
    };

    print!("🔌 Protocol (tcp/udp/both) [tcp]: ");
    io::stdout().flush().unwrap();
    let mut protocol = String::new();
    io::stdin().read_line(&mut protocol).unwrap();
    let protocol = if protocol.trim().is_empty() {
        Some("tcp".to_string())
    } else {
        Some(protocol.trim().to_string())
    };

    print!("⚡ Concurrency (50-500) [100]: ");
    io::stdout().flush().unwrap();
    let mut concurrency = String::new();
    io::stdin().read_line(&mut concurrency).unwrap();
    let concurrency = if concurrency.trim().is_empty() {
        100
    } else {
        concurrency.trim().parse().unwrap_or(100)
    };

    print!("🔧 Enable service detection? (y/N): ");
    io::stdout().flush().unwrap();
    let mut service_detection = String::new();
    io::stdin().read_line(&mut service_detection).unwrap();
    let service_detection = service_detection.trim().to_lowercase() == "y";

    print!("🖥️ Enable OS detection? (y/N): ");
    io::stdout().flush().unwrap();
    let mut os_detection = String::new();
    io::stdin().read_line(&mut os_detection).unwrap();
    let os_detection = os_detection.trim().to_lowercase() == "y";

    print!("🔐 Enable SSL analysis? (y/N): ");
    io::stdout().flush().unwrap();
    let mut ssl_analysis = String::new();
    io::stdin().read_line(&mut ssl_analysis).unwrap();
    let ssl_analysis = ssl_analysis.trim().to_lowercase() == "y";

    Ok(Args {
        target,
        ports,
        protocol,
        concurrency,
        timeout: 3000,
        json: false,
        html_output: None,
        banner: service_detection,
        stealth: false,
        scan_type: "auto".to_string(),
        service_detection,
        os_detection,
        ssl_analysis,
        aggressive: false,
        risk_assessment: false,
        compliance_check: None,
        threat_model: false,
    })
}

fn print_scan_progress(current: usize, total: usize, target: &str) {
    let progress = (current as f64 / total as f64) * 100.0;
    let bar_length = 50;
    let filled_length = (progress / 100.0 * bar_length as f64) as usize;

    let bar = "█".repeat(filled_length) + &"░".repeat(bar_length - filled_length);

    print!(
        "\r🔍 Scanning {} [{bar}] {:.1}% ({}/{})",
        target.cyan().bold(),
        progress,
        current,
        total
    );
    io::stdout().flush().unwrap();
}

fn print_scan_tips() {
    println!("{}", "\n💡 Pro Tips:".yellow().bold());
    println!(
        "   • Use {} for faster scanning",
        "--concurrency 200".green()
    );
    println!("   • Try {} for detailed analysis", "--aggressive".green());
    println!("   • Use {} for common services", "--top-ports 100".green());
    println!(
        "   • Add {} for professional reports",
        "--html report.html".green()
    );
    println!(
        "   • Use {} for network security assessment",
        "--ssl-analysis".green()
    );
}

fn validate_target_with_feedback(target: &str) -> Result<(), String> {
    println!("🔍 Validating target: {}", target.cyan());

    if target.parse::<IpAddr>().is_ok() {
        println!("   ✅ Valid IP address");
        return Ok(());
    }

    print!("   🌐 Resolving hostname...");
    io::stdout().flush().unwrap();

    match std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:80", target)) {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                println!(" ✅ Resolved to {}", addr.ip().to_string().green());
                Ok(())
            } else {
                println!(" ❌ No addresses found");
                Err("Could not resolve hostname".to_string())
            }
        }
        Err(e) => {
            println!(" ❌ Resolution failed: {}", e);
            Err(format!("Failed to resolve hostname: {}", e))
        }
    }
}

fn print_scan_summary_header(target: &str, ports: &str, protocol: &str) {
    println!("\n{}", "═".repeat(80));
    println!("{}", "🚀 SCAN CONFIGURATION".cyan().bold());
    println!("{}", "═".repeat(80));

    println!("🎯 Target:    {}", target.yellow().bold());
    println!("📡 Ports:     {}", ports.green());
    println!("🔌 Protocol:  {}", protocol.blue());
    println!(
        "⏱️ Started:   {}",
        chrono::Utc::now()
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string()
            .dimmed()
    );

    println!("\n{}", "Starting scan...".bright_green().bold());
    println!("{}", "═".repeat(80));
}

#[tokio::main]
async fn main() {
    // Print banner
    print_banner();

    let matches = create_interactive_command().get_matches();

    let args = if matches.get_flag("interactive") {
        match run_interactive_mode() {
            Ok(args) => args,
            Err(e) => {
                print_error_help(&e);
                std::process::exit(1);
            }
        }
    } else {
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
            html_output: matches.get_one::<String>("html").cloned(),
            banner: matches.get_flag("banner"),
            stealth: matches.get_flag("stealth"),
            scan_type: matches.get_one::<String>("scan_type").unwrap().clone(),
            service_detection: matches.get_flag("service_detection"),
            os_detection: matches.get_flag("os_detection"),
            ssl_analysis: matches.get_flag("ssl_analysis"),
            aggressive: matches.get_flag("aggressive"),
            risk_assessment: matches.get_flag("risk_assessment"),
            compliance_check: matches.get_one::<String>("compliance_check").cloned(),
            threat_model: matches.get_flag("threat_model"),
        };

        // Handle aggressive mode - enable risk assessment by default
        if args.aggressive {
            args.risk_assessment = true;
            args.threat_model = true;
        }

        // Auto-enable risk assessment for compliance checks
        if args.compliance_check.is_some() {
            args.risk_assessment = true;
        }

        // Quick scan mode
        if matches.get_flag("quick") {
            args.ports = get_top_ports(100, &args.protocol.as_deref().unwrap_or("tcp"));
            args.concurrency = 200;
            if !args.json {
                println!("⚡ Quick scan mode enabled (top 100 ports)");
            }
        }

        args
    };

    // Validate target with feedback
    if let Err(e) = validate_target_with_feedback(&args.target) {
        print_error_help(&e);
        std::process::exit(1);
    }

    // Handle special configurations
    if args.aggressive {
        if !args.json {
            println!("🚀 Aggressive mode enabled - all detection methods active");
        }
    }

    // Show scan animation
    if !args.json {
        print_scan_start_animation();
    }

    // Start scanning
    let scan_start_time = std::time::Instant::now();
    let json_output = args.json;

    match PortScanner::new(args) {
        Ok(scanner) => {
            scanner.run().await;

            let scan_duration = scan_start_time.elapsed().as_secs_f64();

            if !json_output {
                // Count open ports for celebration
                let open_ports = 0; // This would need to be passed from the scanner
                show_completion_celebration(open_ports, scan_duration);
            }
        }
        Err(e) => {
            print_error_help(&e);
            std::process::exit(1);
        }
    }
}

// Helper functions (keeping the existing ones and adding new ones)
async fn validate_and_resolve_target(
    target: &str,
    ipv4_only: bool,
    ipv6_only: bool,
) -> Result<(String, Option<String>), String> {
    use std::net::ToSocketAddrs;

    if let Ok(ip) = target.parse::<IpAddr>() {
        let version = if ip.is_ipv4() { "IPv4" } else { "IPv6" };
        return Ok((target.to_string(), Some(version.to_string())));
    }

    if target.starts_with('[') && target.ends_with(']') {
        let inner = &target[1..target.len() - 1];
        if let Ok(ip) = inner.parse::<IpAddr>() {
            return Ok((inner.to_string(), Some("IPv6".to_string())));
        }
    }

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

    if let Some(ipv4) = ipv4_addrs.first() {
        Ok((ipv4.to_string(), Some("IPv4".to_string())))
    } else if let Some(ipv6) = ipv6_addrs.first() {
        Ok((ipv6.to_string(), Some("IPv6".to_string())))
    } else {
        Err(format!("No IP address found for hostname '{}'", target))
    }
}

fn is_ipv6_target(target: &str) -> bool {
    target.contains(':') && !target.contains("://") || target.starts_with('[')
}

fn normalize_ipv6_display(addr: &str) -> Result<String, String> {
    use std::net::Ipv6Addr;

    let clean_addr = if addr.starts_with('[') && addr.ends_with(']') {
        &addr[1..addr.len() - 1]
    } else {
        addr
    };

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
