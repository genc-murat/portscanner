use crate::os_fingerprinting::{OSDetector, OSFingerprint, format_os_info};
use crate::service_detection::{ServiceDetector, ServiceInfo, format_service_info};
use crate::stealth::{PortState, StealthScanResult, StealthScanner};
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
    pub scan_time: f64,
    pub scan_method: String,
}

#[derive(Debug, Clone)]
pub enum ScanType {
    TcpConnect,
    StealthSyn,
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
    service_detection: bool,
    os_detection: bool,
    service_detector: Arc<ServiceDetector>,
    os_detector: Arc<tokio::sync::Mutex<OSDetector>>,
}

impl PortScanner {
    pub fn new(args: crate::Args) -> Result<Self, String> {
        let target = resolve_hostname(&args.target)?;
        let ports = crate::port_parser::parse_ports(&args.ports)?;

        let scan_type = if args.stealth || args.scan_type == "syn" {
            ScanType::StealthSyn
        } else if args.scan_type == "tcp" {
            ScanType::TcpConnect
        } else {
            // Auto mode: use stealth if available, otherwise TCP
            if cfg!(target_os = "linux") && is_root() {
                ScanType::StealthSyn
            } else {
                ScanType::TcpConnect
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
            service_detection: args.service_detection,
            os_detection: args.os_detection,
            service_detector: Arc::new(ServiceDetector::new()),
            os_detector: Arc::new(tokio::sync::Mutex::new(OSDetector::new())),
        })
    }

    pub async fn run(&self) {
        let scan_start = std::time::Instant::now();

        let scan_method = match self.scan_type {
            ScanType::TcpConnect => "TCP Connect",
            ScanType::StealthSyn => "Stealth SYN",
        };

        println!(
            "Starting scan: {} ({} ports)",
            self.target,
            self.ports.len()
        );
        println!("Scan method: {}", scan_method);

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

        match self.scan_type {
            ScanType::TcpConnect => {
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
        }

        let mut results = Vec::new();
        for handle in handles {
            if let Ok(result) = handle.await {
                results.push(result);
            }
        }

        let os_fingerprint = if self.os_detection {
            let open_ports: Vec<u16> = results
                .iter()
                .filter(|r| r.is_open)
                .map(|r| r.port)
                .collect();

            if !open_ports.is_empty() {
                let mut os_detector = self.os_detector.lock().await;
                os_detector.detect_os(self.target, &open_ports).await
            } else {
                println!("⚠️  No open ports found for OS detection");
                None
            }
        } else {
            None
        };

        let scan_time = scan_start.elapsed().as_secs_f64();

        let summary = ScanSummary {
            total_ports: self.ports.len(),
            open_ports: results.iter().filter(|r| r.is_open).count(),
            closed_ports: results
                .iter()
                .filter(|r| !r.is_open && r.service.as_deref() == Some("closed"))
                .count(),
            filtered_ports: results
                .iter()
                .filter(|r| !r.is_open && r.service.as_deref() == Some("filtered"))
                .count(),
            scan_time,
            scan_method: scan_method.to_string(),
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
        results.sort_by_key(|r| r.port);

        println!("\n{}", "=".repeat(80));
        println!("Port Scan Results - {}", self.target);
        println!("{}", "=".repeat(80));

        let open_ports: Vec<_> = results.iter().filter(|r| r.is_open).collect();
        let closed_ports: Vec<_> = results.iter().filter(|r| !r.is_open).collect();

        if open_ports.is_empty() {
            println!("{}", "No open ports found!".red());
        } else {
            println!(
                "{} open ports found:\n",
                open_ports.len().to_string().green()
            );

            for result in &open_ports {
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
                    "{} {:5} {} {:25} ({:4}ms)",
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

        if matches!(self.scan_type, ScanType::StealthSyn) && !closed_ports.is_empty() {
            let filtered_count = closed_ports
                .iter()
                .filter(|r| r.service.as_deref() == Some("filtered"))
                .count();
            let closed_count = closed_ports.len() - filtered_count;

            if filtered_count > 0 {
                println!(
                    "\n{} ports filtered (no response)",
                    filtered_count.to_string().yellow()
                );
            }
            if closed_count > 0 {
                println!(
                    "{} ports closed (RST received)",
                    closed_count.to_string().red()
                );
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
                .yellow()
        );
        println!("Scan time: {:.2}s", complete_result.scan_summary.scan_time);
        println!("Scan method: {}", complete_result.scan_summary.scan_method);

        let avg_time = results.iter().map(|r| r.response_time).sum::<u64>() as f64
            / results.len() as f64
            / 1000.0;
        println!("Average response time: {:.3}s", avg_time);

        if self.service_detection {
            let identified_services = open_ports
                .iter()
                .filter(|r| r.service_info.as_ref().map_or(false, |s| s.confidence > 70))
                .count();
            println!(
                "Services identified with high confidence: {}/{}",
                identified_services,
                open_ports.len()
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
        // Messaging and Chat
        (194, "irc"),
        (994, "ircs"),
        (5222, "xmpp-client"),
        (5223, "xmpp-client-ssl"),
        (5269, "xmpp-server"),
        (6667, "irc-alt"),
        (6668, "irc-alt"),
        (6669, "irc-alt"),
        (8010, "xmpp-alt"),
        // Gaming
        (25565, "minecraft"),
        (27015, "steam-source"),
        (7777, "teamspeak"),
        (9987, "teamspeak3"),
        (28960, "cod4"),
        // Monitoring and Management
        (199, "smux"),
        (1234, "hotline"),
        (3000, "grafana"),
        (8086, "influxdb"),
        (9090, "prometheus"),
        (9200, "elasticsearch"),
        (9300, "elasticsearch-cluster"),
        (5601, "kibana"),
        (8125, "statsd"),
        (8126, "statsd-admin"),
        // Application Servers
        (1099, "java-rmi"),
        (1337, "waste"),
        (3690, "svn"),
        (4848, "glassfish-admin"),
        (5000, "flask-dev"),
        (5432, "postgresql"),
        (6379, "redis"),
        (7000, "cassandra"),
        (7001, "cassandra-ssl"),
        (8000, "django-dev"),
        (8009, "ajp13"),
        (8081, "blackice-icecap"),
        (8161, "activemq-admin"),
        (8983, "solr"),
        (9042, "cassandra-client"),
        (9160, "cassandra-thrift"),
        (11211, "memcached"),
        // Security and VPN
        (500, "ipsec"),
        (1701, "l2tp"),
        (1723, "pptp"),
        (4500, "ipsec-nat"),
        (1194, "openvpn"),
        // Proxy and Load Balancers
        (1080, "socks"),
        (3128, "squid"),
        (8118, "privoxy"),
        (9050, "tor-socks"),
        (9051, "tor-control"),
        // Media and Streaming
        (554, "rtsp"),
        (1935, "rtmp"),
        (5004, "rtp"),
        (5060, "sip"),
        (5061, "sips"),
        (8554, "rtsp-alt"),
        // Backup and Sync
        (873, "rsync"),
        (6000, "x11"),
        (6001, "x11-1"),
        (6002, "x11-2"),
        (6003, "x11-3"),
        (6004, "x11-4"),
        (6005, "x11-5"),
        // IoT and Embedded
        (1883, "mqtt"),
        (8883, "mqtt-ssl"),
        (5683, "coap"),
        // Development and Testing
        (3000, "node-dev"),
        (3001, "node-dev-alt"),
        (4000, "node-dev-alt2"),
        (5000, "python-dev"),
        (8000, "python-dev-alt"),
        (9229, "node-inspector"),
        // Cloud and Container Services
        (2375, "docker"),
        (2376, "docker-ssl"),
        (2377, "docker-swarm"),
        (4243, "docker-alt"),
        (6443, "kubernetes-api"),
        (8001, "kubernetes-api-alt"),
        (10250, "kubelet"),
        (10255, "kubelet-readonly"),
        // Enterprise Software
        (1414, "ibm-mq"),
        (1521, "oracle-db"),
        (1830, "oracle-alt"),
        (5060, "sip"),
        (5984, "couchdb"),
        (7474, "neo4j"),
        (9418, "git"),
        // Print Services
        (515, "lpr"),
        (631, "ipp"),
        (9100, "jetdirect"),
        // Miscellaneous
        (79, "finger"),
        (113, "ident"),
        (119, "nntp"),
        (563, "nntps"),
        (1900, "upnp"),
        (2000, "cisco-sccp"),
        (5432, "postgresql"),
        (11111, "vce"),
        (12345, "netbus"),
        (31337, "back-orifice"),
    ];

    services
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
