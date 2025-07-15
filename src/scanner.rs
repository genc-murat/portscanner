use crate::os_fingerprinting::{OSDetector, OSFingerprint, format_os_info};
use crate::service_detection::{ServiceDetector, ServiceInfo, format_service_info};
use crate::stealth::{PortState, StealthScanResult, StealthScanner};
use crate::udp::{UdpPortState, UdpScanResult, UdpScanner};
use colored::*;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub port: u16,
    pub is_open: bool,
    pub service: Option<String>,
    pub service_info: Option<ServiceInfo>,
    pub banner: Option<String>,
    pub response_time: u64, // milliseconds
    pub scan_type: String,
    pub protocol: String,          // "TCP" or "UDP"
    pub udp_state: Option<String>, // For UDP: "open", "open|filtered", "closed", "filtered"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteScanResult {
    pub target: String,
    pub scan_results: Vec<ScanResult>,
    pub os_fingerprint: Option<OSFingerprint>,
    pub scan_summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_ports: usize,
    pub open_ports: usize,
    pub closed_ports: usize,
    pub filtered_ports: usize,
    pub open_filtered_ports: usize, // UDP specific
    pub scan_time: f64,
    pub scan_method: String,
    pub protocols_scanned: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum ScanType {
    TcpConnect,
    StealthSyn,
    UdpScan,
    Mixed, // Both TCP and UDP
}

#[derive(Debug, Clone)]
pub enum Protocol {
    Tcp,
    Udp,
    Both,
}

pub struct PortScanner {
    target: IpAddr,
    target_hostname: String,
    ports: Vec<u16>,
    concurrency: usize,
    timeout_ms: u64,
    json_output: bool,
    grab_banner: bool,
    scan_type: ScanType,
    protocol: Protocol,
    service_detection: bool,
    os_detection: bool,
    service_detector: Arc<ServiceDetector>,
    os_detector: Arc<tokio::sync::Mutex<OSDetector>>,
    udp_scanner: Arc<UdpScanner>,
}

impl PortScanner {
    pub fn new(args: crate::Args) -> Result<Self, String> {
        let target = resolve_hostname(&args.target)?;
        let ports = crate::port_parser::parse_ports(&args.ports)?;

        // Determine protocol based on args
        let protocol = match args.protocol.as_deref() {
            Some("tcp") => Protocol::Tcp,
            Some("udp") => Protocol::Udp,
            Some("both") | Some("all") => Protocol::Both,
            _ => Protocol::Tcp, // Default to TCP
        };

        let scan_type = match (&protocol, args.stealth, args.scan_type.as_str()) {
            (Protocol::Udp, _, _) => ScanType::UdpScan,
            (Protocol::Both, _, _) => ScanType::Mixed,
            (_, true, _) | (_, _, "syn") => ScanType::StealthSyn,
            (_, _, "tcp") => ScanType::TcpConnect,
            _ => {
                // Auto mode: use stealth if available, otherwise TCP
                if cfg!(target_os = "linux") && is_root() {
                    ScanType::StealthSyn
                } else {
                    ScanType::TcpConnect
                }
            }
        };

        Ok(Self {
            target,
            target_hostname: args.target.clone(),
            ports,
            concurrency: args.concurrency,
            timeout_ms: args.timeout,
            json_output: args.json,
            grab_banner: args.banner && !args.stealth,
            scan_type,
            protocol,
            service_detection: args.service_detection,
            os_detection: args.os_detection,
            service_detector: Arc::new(ServiceDetector::new()),
            os_detector: Arc::new(tokio::sync::Mutex::new(OSDetector::new())),
            udp_scanner: Arc::new(UdpScanner::new(target, args.timeout)),
        })
    }

    pub async fn run(&self) {
        let scan_start = std::time::Instant::now();

        let scan_method = match (&self.scan_type, &self.protocol) {
            (ScanType::UdpScan, _) => "UDP Scan",
            (ScanType::Mixed, _) => "Mixed TCP/UDP Scan",
            (ScanType::TcpConnect, _) => "TCP Connect",
            (ScanType::StealthSyn, _) => "Stealth SYN",
        };

        println!(
            "Starting scan: {} ({} ports)",
            self.target,
            match self.protocol {
                Protocol::Both => self.ports.len() * 2, // Both TCP and UDP
                _ => self.ports.len(),
            }
        );
        println!("Scan method: {}", scan_method);
        println!(
            "Protocol(s): {}",
            match self.protocol {
                Protocol::Tcp => "TCP",
                Protocol::Udp => "UDP",
                Protocol::Both => "TCP, UDP",
            }
        );

        if self.grab_banner {
            println!("Banner grabbing enabled!");
        }

        if self.service_detection {
            println!("Advanced service detection enabled!");
        }

        if self.os_detection {
            println!("OS fingerprinting enabled!");
        }

        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrency));
        let mut handles = Vec::new();

        // TCP Scanning
        if matches!(self.protocol, Protocol::Tcp | Protocol::Both) {
            match self.scan_type {
                ScanType::TcpConnect | ScanType::Mixed => {
                    for &port in &self.ports {
                        let sem = semaphore.clone();
                        let target = self.target;
                        let timeout_duration = Duration::from_millis(self.timeout_ms);
                        let grab_banner = self.grab_banner;
                        let service_detection = self.service_detection;
                        let service_detector = self.service_detector.clone();

                        let handle = tokio::spawn(async move {
                            let _permit = sem.acquire().await.unwrap();
                            tcp_scan_port(
                                target,
                                port,
                                timeout_duration,
                                grab_banner,
                                service_detection,
                                service_detector,
                            )
                            .await
                        });

                        handles.push(handle);
                    }
                }
                ScanType::StealthSyn => {
                    let stealth_scanner = match StealthScanner::new(self.target, self.timeout_ms) {
                        Ok(scanner) => Arc::new(scanner),
                        Err(e) => {
                            eprintln!("Failed to create stealth scanner: {}", e);
                            return;
                        }
                    };

                    for &port in &self.ports {
                        let sem = semaphore.clone();
                        let scanner = stealth_scanner.clone();
                        let service_detection = self.service_detection;
                        let service_detector = self.service_detector.clone();
                        let target = self.target;

                        let handle = tokio::spawn(async move {
                            let _permit = sem.acquire().await.unwrap();
                            let stealth_result = scanner.syn_scan(port).await;
                            convert_stealth_result(
                                stealth_result,
                                target,
                                service_detection,
                                service_detector,
                            )
                            .await
                        });

                        handles.push(handle);
                    }
                }
                _ => {}
            }
        }

        // UDP Scanning
        if matches!(self.protocol, Protocol::Udp | Protocol::Both) {
            for &port in &self.ports {
                let sem = semaphore.clone();
                let udp_scanner = self.udp_scanner.clone();
                let service_detection = self.service_detection;
                let service_detector = self.service_detector.clone();
                let target = self.target;

                let handle = tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    let udp_result = udp_scanner.scan_port(port).await;
                    convert_udp_result(udp_result, target, service_detection, service_detector)
                        .await
                });

                handles.push(handle);
            }
        }

        let mut results = Vec::new();
        for handle in handles {
            if let Ok(result) = handle.await {
                results.push(result);
            }
        }

        let os_fingerprint = if self.os_detection {
            let open_tcp_ports: Vec<u16> = results
                .iter()
                .filter(|r| r.is_open && r.protocol == "TCP")
                .map(|r| r.port)
                .collect();

            if !open_tcp_ports.is_empty() {
                let mut os_detector = self.os_detector.lock().await;
                os_detector.detect_os(self.target, &open_tcp_ports).await
            } else {
                println!("⚠️  No open TCP ports found for OS detection");
                None
            }
        } else {
            None
        };

        let scan_time = scan_start.elapsed().as_secs_f64();

        let summary = ScanSummary {
            total_ports: results.len(),
            open_ports: results.iter().filter(|r| r.is_open).count(),
            closed_ports: results
                .iter()
                .filter(|r| !r.is_open && r.udp_state.as_deref() != Some("open|filtered"))
                .count(),
            filtered_ports: results
                .iter()
                .filter(|r| !r.is_open && r.udp_state.as_deref() == Some("filtered"))
                .count(),
            open_filtered_ports: results
                .iter()
                .filter(|r| r.udp_state.as_deref() == Some("open|filtered"))
                .count(),
            scan_time,
            scan_method: scan_method.to_string(),
            protocols_scanned: match self.protocol {
                Protocol::Tcp => vec!["TCP".to_string()],
                Protocol::Udp => vec!["UDP".to_string()],
                Protocol::Both => vec!["TCP".to_string(), "UDP".to_string()],
            },
        };

        let complete_result = CompleteScanResult {
            target: self.target_hostname.clone(),
            scan_results: results,
            os_fingerprint: os_fingerprint.clone(),
            scan_summary: summary,
        };

        self.display_results(complete_result);
    }

    fn display_results(&self, complete_result: CompleteScanResult) {
        if self.json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&complete_result).unwrap()
            );
            return;
        }

        let mut results = complete_result.scan_results;
        results.sort_by_key(|r| (r.port, r.protocol.clone()));

        println!("\n{}", "=".repeat(80));
        println!("Port Scan Results - {}", self.target);
        println!("{}", "=".repeat(80));

        // Separate TCP and UDP results
        let tcp_results: Vec<_> = results.iter().filter(|r| r.protocol == "TCP").collect();
        let udp_results: Vec<_> = results.iter().filter(|r| r.protocol == "UDP").collect();

        // Display TCP results
        if !tcp_results.is_empty() {
            println!("\n{}", "TCP Ports".cyan().bold());
            println!("{}", "-".repeat(40));

            let open_tcp_ports: Vec<_> = tcp_results.iter().filter(|r| r.is_open).collect();
            let closed_tcp_ports: Vec<_> = tcp_results.iter().filter(|r| !r.is_open).collect();

            if open_tcp_ports.is_empty() {
                println!("{}", "No open TCP ports found!".red());
            } else {
                println!(
                    "{} open TCP ports found:\n",
                    open_tcp_ports.len().to_string().green()
                );

                for result in &open_tcp_ports {
                    let scan_indicator = match result.scan_type.as_str() {
                        "SYN" => "⚡",
                        _ => "🔗",
                    };

                    let service_display = if let Some(service_info) = &result.service_info {
                        format_service_info(service_info)
                    } else {
                        result.service.as_deref().unwrap_or("unknown").to_string()
                    };

                    println!(
                        "{} {:5}/tcp {} {:25} ({:4}ms)",
                        scan_indicator,
                        result.port.to_string().green().bold(),
                        "open".green(),
                        service_display.blue(),
                        result.response_time
                    );

                    if let Some(banner) = &result.banner {
                        let truncated_banner = if banner.len() > 80 {
                            format!("{}...", &banner[..77])
                        } else {
                            banner.clone()
                        };
                        println!("        Banner: {}", truncated_banner.dimmed());
                    }

                    if let Some(service_info) = &result.service_info {
                        if service_info.confidence < 70 {
                            println!(
                                "        Confidence: {}%",
                                service_info.confidence.to_string().yellow()
                            );
                        }

                        if let Some(cpe) = &service_info.cpe {
                            println!("        CPE: {}", cpe.dimmed());
                        }
                    }
                }
            }

            if matches!(self.scan_type, ScanType::StealthSyn) && !closed_tcp_ports.is_empty() {
                let filtered_count = closed_tcp_ports
                    .iter()
                    .filter(|r| r.service.as_deref() == Some("filtered"))
                    .count();
                let closed_count = closed_tcp_ports.len() - filtered_count;

                if filtered_count > 0 {
                    println!(
                        "\n{} TCP ports filtered (no response)",
                        filtered_count.to_string().yellow()
                    );
                }
                if closed_count > 0 {
                    println!(
                        "{} TCP ports closed (RST received)",
                        closed_count.to_string().red()
                    );
                }
            }
        }

        // Display UDP results
        if !udp_results.is_empty() {
            println!("\n{}", "UDP Ports".cyan().bold());
            println!("{}", "-".repeat(40));

            let open_udp_ports: Vec<_> = udp_results.iter().filter(|r| r.is_open).collect();
            let open_filtered_udp: Vec<_> = udp_results
                .iter()
                .filter(|r| r.udp_state.as_deref() == Some("open|filtered"))
                .collect();
            let closed_udp_ports: Vec<_> = udp_results
                .iter()
                .filter(|r| r.udp_state.as_deref() == Some("closed"))
                .collect();
            let filtered_udp_ports: Vec<_> = udp_results
                .iter()
                .filter(|r| r.udp_state.as_deref() == Some("filtered"))
                .collect();

            if !open_udp_ports.is_empty() {
                println!(
                    "{} open UDP ports found:\n",
                    open_udp_ports.len().to_string().green()
                );

                for result in &open_udp_ports {
                    let service_display = if let Some(service_info) = &result.service_info {
                        format_service_info(service_info)
                    } else {
                        result.service.as_deref().unwrap_or("unknown").to_string()
                    };

                    println!(
                        "📡 {:5}/udp {} {:25} ({:4}ms)",
                        result.port.to_string().green().bold(),
                        "open".green(),
                        service_display.blue(),
                        result.response_time
                    );

                    if let Some(banner) = &result.banner {
                        let truncated_banner = if banner.len() > 80 {
                            format!("{}...", &banner[..77])
                        } else {
                            banner.clone()
                        };
                        println!("        Response: {}", truncated_banner.dimmed());
                    }
                }
            }

            if !open_filtered_udp.is_empty() {
                println!(
                    "\n{} UDP ports open|filtered (no response):",
                    open_filtered_udp.len().to_string().yellow()
                );

                for result in &open_filtered_udp {
                    let service_display = result.service.as_deref().unwrap_or("unknown");
                    println!(
                        "❓ {:5}/udp {} {}",
                        result.port.to_string().yellow(),
                        "open|filtered".yellow(),
                        service_display.blue()
                    );
                }
            }

            if !closed_udp_ports.is_empty() {
                println!(
                    "\n{} UDP ports closed (ICMP unreachable)",
                    closed_udp_ports.len().to_string().red()
                );
            }

            if !filtered_udp_ports.is_empty() {
                println!(
                    "{} UDP ports filtered",
                    filtered_udp_ports.len().to_string().red()
                );
            }

            if open_udp_ports.is_empty() && open_filtered_udp.is_empty() {
                println!("{}", "No responsive UDP ports found!".red());
                println!(
                    "Note: UDP scanning can produce false negatives. Services may be running but not responding to probes."
                );
            }
        }

        if let Some(os_info) = &complete_result.os_fingerprint {
            println!("\n{}", "OS Detection Results".cyan().bold());
            println!("{}", "-".repeat(40));
            println!("🖥️  Operating System: {}", format_os_info(os_info).green());
            println!(
                "    Confidence: {}%",
                os_info.confidence.to_string().yellow()
            );

            if !os_info.details.is_empty() {
                println!("    Details:");
                for detail in &os_info.details {
                    println!("      • {}", detail.dimmed());
                }
            }

            if let Some(cpe) = &os_info.cpe {
                println!("    CPE: {}", cpe.dimmed());
            }
        }

        println!("\n{}", "Scan Summary".cyan().bold());
        println!("{}", "-".repeat(40));
        println!(
            "Total ports scanned: {}",
            complete_result.scan_summary.total_ports
        );
        println!(
            "Open ports: {}",
            complete_result.scan_summary.open_ports.to_string().green()
        );

        if complete_result.scan_summary.open_filtered_ports > 0 {
            println!(
                "Open|Filtered ports: {}",
                complete_result
                    .scan_summary
                    .open_filtered_ports
                    .to_string()
                    .yellow()
            );
        }

        println!(
            "Closed ports: {}",
            complete_result.scan_summary.closed_ports.to_string().red()
        );
        println!(
            "Filtered ports: {}",
            complete_result
                .scan_summary
                .filtered_ports
                .to_string()
                .red()
        );
        println!("Scan time: {:.2}s", complete_result.scan_summary.scan_time);
        println!("Scan method: {}", complete_result.scan_summary.scan_method);
        println!(
            "Protocols: {}",
            complete_result.scan_summary.protocols_scanned.join(", ")
        );

        let avg_time = results.iter().map(|r| r.response_time).sum::<u64>() as f64
            / results.len() as f64
            / 1000.0;
        println!("Average response time: {:.3}s", avg_time);

        if self.service_detection {
            let tcp_identified = tcp_results
                .iter()
                .filter(|r| {
                    r.is_open && r.service_info.as_ref().map_or(false, |s| s.confidence > 70)
                })
                .count();
            let udp_identified = udp_results
                .iter()
                .filter(|r| {
                    r.is_open && r.service_info.as_ref().map_or(false, |s| s.confidence > 70)
                })
                .count();

            println!(
                "Services identified with high confidence: TCP {}/{}, UDP {}/{}",
                tcp_identified,
                tcp_results.iter().filter(|r| r.is_open).count(),
                udp_identified,
                udp_results.iter().filter(|r| r.is_open).count()
            );
        }

        if self.os_detection {
            if let Some(os_info) = &complete_result.os_fingerprint {
                if os_info.confidence > 80 {
                    println!("OS detection: {} (High confidence)", "Success".green());
                } else {
                    println!("OS detection: {} (Low confidence)", "Partial".yellow());
                }
            } else {
                println!("OS detection: {}", "Failed".red());
            }
        }

        println!("\n{}", "=".repeat(80));
    }
}

async fn tcp_scan_port(
    target: IpAddr,
    port: u16,
    timeout_duration: Duration,
    grab_banner: bool,
    service_detection: bool,
    service_detector: Arc<ServiceDetector>,
) -> ScanResult {
    let start_time = std::time::Instant::now();
    let socket_addr = SocketAddr::new(target, port);

    let (is_open, banner) = match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
        Ok(Ok(mut stream)) => {
            let banner = if grab_banner {
                grab_banner_from_stream(&mut stream, port, timeout_duration).await
            } else {
                None
            };
            (true, banner)
        }
        _ => (false, None),
    };

    let response_time = start_time.elapsed();

    let (service, service_info) = if is_open && service_detection {
        let detected_service = service_detector
            .detect_service(target, port, banner.as_deref())
            .await;
        (Some(detected_service.name.clone()), Some(detected_service))
    } else {
        (detect_basic_service(port), None)
    };

    ScanResult {
        port,
        is_open,
        service,
        service_info,
        banner,
        response_time: response_time.as_millis() as u64,
        scan_type: "TCP".to_string(),
        protocol: "TCP".to_string(),
        udp_state: None,
    }
}

async fn convert_stealth_result(
    stealth_result: StealthScanResult,
    target: IpAddr,
    service_detection: bool,
    service_detector: Arc<ServiceDetector>,
) -> ScanResult {
    let (is_open, service) = match stealth_result.state {
        PortState::Open => (true, detect_basic_service(stealth_result.port)),
        PortState::Closed => (false, Some("closed".to_string())),
        PortState::Filtered => (false, Some("filtered".to_string())),
        PortState::Unknown => (false, Some("unknown".to_string())),
    };

    let service_info = if is_open && service_detection {
        Some(
            service_detector
                .detect_service(target, stealth_result.port, None)
                .await,
        )
    } else {
        None
    };

    ScanResult {
        port: stealth_result.port,
        is_open,
        service,
        service_info,
        banner: None,
        response_time: stealth_result.response_time,
        scan_type: "SYN".to_string(),
        protocol: "TCP".to_string(),
        udp_state: None,
    }
}

async fn convert_udp_result(
    udp_result: UdpScanResult,
    target: IpAddr,
    service_detection: bool,
    service_detector: Arc<ServiceDetector>,
) -> ScanResult {
    let (is_open, udp_state_str) = match udp_result.state {
        UdpPortState::Open => (true, "open"),
        UdpPortState::OpenFiltered => (false, "open|filtered"),
        UdpPortState::Closed => (false, "closed"),
        UdpPortState::Filtered => (false, "filtered"),
    };

    let service = detect_basic_udp_service(udp_result.port);

    let service_info = if is_open && service_detection {
        Some(
            service_detector
                .detect_service(
                    target,
                    udp_result.port,
                    udp_result.service_response.as_deref(),
                )
                .await,
        )
    } else {
        None
    };

    let banner = udp_result.service_response.or_else(|| {
        udp_result.response_data.as_ref().map(|data| {
            if data.len() > 100 {
                format!(
                    "UDP response ({} bytes): {}...",
                    data.len(),
                    String::from_utf8_lossy(&data[..100])
                )
            } else {
                format!("UDP response: {}", String::from_utf8_lossy(data))
            }
        })
    });

    ScanResult {
        port: udp_result.port,
        is_open,
        service,
        service_info,
        banner,
        response_time: udp_result.response_time,
        scan_type: "UDP".to_string(),
        protocol: "UDP".to_string(),
        udp_state: Some(udp_state_str.to_string()),
    }
}

fn detect_basic_service(port: u16) -> Option<String> {
    let services = [
        // FTP and File Transfer
        (20, "ftp-data"),
        (21, "ftp"),
        (69, "tftp"),
        (115, "sftp"),
        (989, "ftps-data"),
        (990, "ftps"),
        // SSH and Remote Access
        (22, "ssh"),
        (23, "telnet"),
        (513, "rlogin"),
        (514, "rsh"),
        (992, "telnets"),
        (2222, "ssh-alt"),
        (3389, "rdp"),
        (5900, "vnc"),
        (5901, "vnc-1"),
        (5902, "vnc-2"),
        (5903, "vnc-3"),
        (5904, "vnc-4"),
        (5905, "vnc-5"),
        // Email Services
        (25, "smtp"),
        (110, "pop3"),
        (143, "imap"),
        (465, "smtps"),
        (587, "smtp-submission"),
        (993, "imaps"),
        (995, "pop3s"),
        (2525, "smtp-alt"),
        // DNS
        (53, "dns"),
        (853, "dns-over-tls"),
        (5353, "mdns"),
        // Web Services
        (80, "http"),
        (443, "https"),
        (8000, "http-alt"),
        (8008, "http-alt"),
        (8080, "http-proxy"),
        (8081, "http-alt"),
        (8443, "https-alt"),
        (8888, "http-alt"),
        (9000, "http-alt"),
        (9080, "http-alt"),
        (9090, "http-alt"),
        (9443, "https-alt"),
        // Databases
        (1433, "mssql"),
        (1521, "oracle"),
        (1526, "oracle-alt"),
        (3306, "mysql"),
        (5432, "postgresql"),
        (6379, "redis"),
        (27017, "mongodb"),
        (27018, "mongodb-shard"),
        (27019, "mongodb-config"),
        (28017, "mongodb-web"),
        (50000, "db2"),
        // LDAP and Directory Services
        (389, "ldap"),
        (636, "ldaps"),
        (3268, "globalcatalog"),
        (3269, "globalcatalog-ssl"),
        // Network Services
        (67, "dhcp-server"),
        (68, "dhcp-client"),
        (123, "ntp"),
        (161, "snmp"),
        (162, "snmp-trap"),
        (179, "bgp"),
        (520, "rip"),
        (521, "ripng"),
        (546, "dhcpv6-client"),
        (547, "dhcpv6-server"),
        // File Sharing
        (135, "rpc-endpoint"),
        (137, "netbios-ns"),
        (138, "netbios-dgm"),
        (139, "netbios-ssn"),
        (445, "smb"),
        (548, "afp"),
        (2049, "nfs"),
        // Additional services truncated for brevity...
    ];

    services
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, service)| service.to_string())
}

fn detect_basic_udp_service(port: u16) -> Option<String> {
    let udp_services = [
        (53, "dns"),
        (67, "dhcp-server"),
        (68, "dhcp-client"),
        (69, "tftp"),
        (123, "ntp"),
        (137, "netbios-ns"),
        (138, "netbios-dgm"),
        (161, "snmp"),
        (162, "snmp-trap"),
        (500, "ipsec-ike"),
        (514, "syslog"),
        (520, "rip"),
        (1194, "openvpn"),
        (1701, "l2tp"),
        (1900, "upnp-ssdp"),
        (4500, "ipsec-nat-t"),
        (5353, "mdns"),
        (5060, "sip"),
        (6881, "bittorrent-dht"),
        (27015, "steam"),
        (27017, "mongodb"),
    ];

    udp_services
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, service)| service.to_string())
}

fn resolve_hostname(hostname: &str) -> Result<IpAddr, String> {
    use std::net::ToSocketAddrs;

    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(ip);
    }

    let socket_addrs = format!("{}:80", hostname)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve hostname: {}", e))?;

    for addr in socket_addrs {
        return Ok(addr.ip());
    }

    Err("Failed to resolve hostname".to_string())
}

async fn grab_banner_from_stream(
    stream: &mut TcpStream,
    port: u16,
    timeout_duration: Duration,
) -> Option<String> {
    match port {
        21 | 22 | 23 | 25 | 110 | 143 | 993 | 995 => read_banner(stream, timeout_duration).await,
        80 | 8080 | 8081 | 8000 => grab_http_banner(stream, timeout_duration).await,
        443 | 8443 => read_banner(stream, timeout_duration).await,
        53 => grab_dns_banner(stream, timeout_duration).await,
        3306 => read_banner(stream, timeout_duration).await,
        5432 => read_banner(stream, timeout_duration).await,
        _ => read_banner(stream, timeout_duration).await,
    }
}

async fn read_banner(stream: &mut TcpStream, timeout_duration: Duration) -> Option<String> {
    use tokio::io::AsyncReadExt;
    let mut buffer = [0; 1024];
    match timeout(timeout_duration, stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let banner = String::from_utf8_lossy(&buffer[..n]);
            let clean_banner = banner
                .trim()
                .lines()
                .next()
                .unwrap_or("")
                .trim_end_matches('\r')
                .trim_end_matches('\n')
                .to_string();
            if clean_banner.is_empty() {
                None
            } else {
                Some(clean_banner)
            }
        }
        _ => None,
    }
}

async fn grab_http_banner(stream: &mut TcpStream, timeout_duration: Duration) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let http_request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(http_request).await.is_err() {
        return None;
    }
    let mut buffer = [0; 2048];
    match timeout(timeout_duration, stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buffer[..n]);
            for line in response.lines() {
                if line.to_lowercase().starts_with("server:") {
                    return Some(line.trim().to_string());
                }
            }
            if let Some(first_line) = response.lines().next() {
                if first_line.contains("HTTP/") {
                    return Some(format!("HTTP Server ({})", first_line.trim()));
                }
            }
            Some("HTTP Server".to_string())
        }
        _ => None,
    }
}

async fn grab_dns_banner(_stream: &mut TcpStream, _timeout_duration: Duration) -> Option<String> {
    Some("DNS Server".to_string())
}

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}
