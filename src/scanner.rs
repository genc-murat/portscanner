use crate::os_fingerprinting::{format_os_info, OSDetector, OSFingerprint};
use crate::service_detection::{format_service_info, ServiceDetector, ServiceInfo};
use crate::ssl::{format_ssl_analysis, SslAnalysisResult, SslAnalyzer};
use crate::stealth::{PortState, StealthScanResult, StealthScanner};
use crate::udp::{UdpPortState, UdpScanResult, UdpScanner};
use colored::*;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

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
    pub ssl_analysis: Vec<SslAnalysisResult>,
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
    pub ssl_services_found: usize,
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
    ssl_analysis: bool,
    service_detector: Arc<ServiceDetector>,
    os_detector: Arc<tokio::sync::Mutex<OSDetector>>,
    udp_scanner: Arc<UdpScanner>,
    ssl_analyzer: Arc<SslAnalyzer>,
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
            ssl_analysis: args.ssl_analysis,
            service_detector: Arc::new(ServiceDetector::new()),
            os_detector: Arc::new(tokio::sync::Mutex::new(OSDetector::new())),
            udp_scanner: Arc::new(UdpScanner::new(target, args.timeout)),
            ssl_analyzer: Arc::new(SslAnalyzer::new(args.timeout)),
        })
    }

    pub async fn run(&self) {
        let scan_start = std::time::Instant::now();

        self.print_scan_header();

        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrency));
        let mut handles = Vec::new();

        // TCP Scanning
        if matches!(self.protocol, Protocol::Tcp | Protocol::Both) {
            handles.extend(self.start_tcp_scans(&semaphore).await);
        }

        // UDP Scanning
        if matches!(self.protocol, Protocol::Udp | Protocol::Both) {
            handles.extend(self.start_udp_scans(&semaphore).await);
        }

        // Collect results
        let mut results = Vec::new();
        for handle in handles {
            if let Ok(result) = handle.await {
                results.push(result);
            }
        }

        // Post-processing analysis
        let os_fingerprint = self.perform_os_detection(&results).await;
        let ssl_analysis = self.perform_ssl_analysis(&results).await;

        let scan_time = scan_start.elapsed().as_secs_f64();
        let summary = self.create_scan_summary(&results, &ssl_analysis, scan_time);

        let complete_result = CompleteScanResult {
            target: self.target_hostname.clone(),
            scan_results: results,
            os_fingerprint: os_fingerprint.clone(),
            ssl_analysis,
            scan_summary: summary,
        };

        self.display_results(complete_result);
    }

    fn print_scan_header(&self) {
        let scan_method = match (&self.scan_type, &self.protocol) {
            (ScanType::UdpScan, _) => "UDP Scan",
            (ScanType::Mixed, _) => "Mixed TCP/UDP Scan",
            (ScanType::TcpConnect, _) => "TCP Connect",
            (ScanType::StealthSyn, _) => "Stealth SYN",
        };

        let protocol_info = match self.protocol {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Both => "TCP, UDP",
        };

        let total_ports = match self.protocol {
            Protocol::Both => self.ports.len() * 2,
            _ => self.ports.len(),
        };

        println!("Starting scan: {} ({} ports)", self.target, total_ports);
        println!("Scan method: {}", scan_method);
        println!("Protocol(s): {}", protocol_info);

        if self.grab_banner {
            println!("Banner grabbing enabled!");
        }

        if self.service_detection {
            println!("Advanced service detection enabled!");
        }

        if self.os_detection {
            println!("OS fingerprinting enabled!");
        }

        if self.ssl_analysis {
            println!("SSL/TLS analysis enabled!");
        }
    }

    async fn start_tcp_scans(
        &self,
        semaphore: &Arc<tokio::sync::Semaphore>,
    ) -> Vec<tokio::task::JoinHandle<ScanResult>> {
        let mut handles = Vec::new();

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
                        return handles;
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

        handles
    }

    async fn start_udp_scans(
        &self,
        semaphore: &Arc<tokio::sync::Semaphore>,
    ) -> Vec<tokio::task::JoinHandle<ScanResult>> {
        let mut handles = Vec::new();

        for &port in &self.ports {
            let sem = semaphore.clone();
            let udp_scanner = self.udp_scanner.clone();
            let service_detection = self.service_detection;
            let service_detector = self.service_detector.clone();
            let target = self.target;

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let udp_result = udp_scanner.scan_port(port).await;
                convert_udp_result(udp_result, target, service_detection, service_detector).await
            });

            handles.push(handle);
        }

        handles
    }

    async fn perform_os_detection(&self, results: &[ScanResult]) -> Option<OSFingerprint> {
        if !self.os_detection {
            return None;
        }

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
    }

    async fn perform_ssl_analysis(&self, results: &[ScanResult]) -> Vec<SslAnalysisResult> {
        if !self.ssl_analysis {
            return Vec::new();
        }

        let ssl_ports: Vec<u16> = results
            .iter()
            .filter(|r| r.is_open && r.protocol == "TCP" && self.is_ssl_port(r.port))
            .map(|r| r.port)
            .collect();

        if ssl_ports.is_empty() {
            println!("⚠️  No SSL/TLS ports found for analysis");
            return Vec::new();
        }

        println!(
            "🔍 Performing SSL/TLS analysis on {} ports",
            ssl_ports.len()
        );

        let mut ssl_results = Vec::new();
        for &port in &ssl_ports {
            let ssl_result = self
                .ssl_analyzer
                .analyze_ssl(self.target, port, Some(&self.target_hostname))
                .await;
            ssl_results.push(ssl_result);
        }

        ssl_results
    }

    fn create_scan_summary(
        &self,
        results: &[ScanResult],
        ssl_analysis: &[SslAnalysisResult],
        scan_time: f64,
    ) -> ScanSummary {
        let scan_method = match (&self.scan_type, &self.protocol) {
            (ScanType::UdpScan, _) => "UDP Scan",
            (ScanType::Mixed, _) => "Mixed TCP/UDP Scan",
            (ScanType::TcpConnect, _) => "TCP Connect",
            (ScanType::StealthSyn, _) => "Stealth SYN",
        };

        let protocols_scanned = match self.protocol {
            Protocol::Tcp => vec!["TCP".to_string()],
            Protocol::Udp => vec!["UDP".to_string()],
            Protocol::Both => vec!["TCP".to_string(), "UDP".to_string()],
        };

        ScanSummary {
            total_ports: results.len(),
            open_ports: results.iter().filter(|r| r.is_open).count(),
            closed_ports: results
                .iter()
                .filter(|r| !r.is_open && r.udp_state.as_deref() != Some("open|filtered"))
                .count(),
            filtered_ports: results
                .iter()
                .filter(|r| r.udp_state.as_deref() == Some("filtered"))
                .count(),
            open_filtered_ports: results
                .iter()
                .filter(|r| r.udp_state.as_deref() == Some("open|filtered"))
                .count(),
            scan_time,
            scan_method: scan_method.to_string(),
            protocols_scanned,
            ssl_services_found: ssl_analysis.iter().filter(|s| s.is_ssl_enabled).count(),
        }
    }

    fn display_results(&self, complete_result: CompleteScanResult) {
        if self.json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&complete_result).unwrap()
            );
            return;
        }

        self.display_formatted_results(complete_result);
    }

    fn display_formatted_results(&self, complete_result: CompleteScanResult) {
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
            self.display_tcp_results(&tcp_results);
        }

        // Display UDP results
        if !udp_results.is_empty() {
            self.display_udp_results(&udp_results);
        }

        // Display OS Detection
        if let Some(os_info) = &complete_result.os_fingerprint {
            self.display_os_detection(os_info);
        }

        // Display SSL/TLS Analysis
        if !complete_result.ssl_analysis.is_empty() {
            for ssl_result in &complete_result.ssl_analysis {
                print!("{}", format_ssl_analysis(ssl_result));
            }
        }

        // Display Summary
        self.display_scan_summary(&complete_result.scan_summary, &tcp_results, &udp_results);
    }

    fn display_tcp_results(&self, tcp_results: &[&ScanResult]) {
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

    fn display_udp_results(&self, udp_results: &[&ScanResult]) {
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
            println!("Note: UDP scanning can produce false negatives. Services may be running but not responding to probes.");
        }
    }

    fn display_os_detection(&self, os_info: &OSFingerprint) {
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

    fn display_scan_summary(
        &self,
        summary: &ScanSummary,
        tcp_results: &[&ScanResult],
        udp_results: &[&ScanResult],
    ) {
        println!("\n{}", "Scan Summary".cyan().bold());
        println!("{}", "-".repeat(40));
        println!("Total ports scanned: {}", summary.total_ports);
        println!("Open ports: {}", summary.open_ports.to_string().green());

        if summary.open_filtered_ports > 0 {
            println!(
                "Open|Filtered ports: {}",
                summary.open_filtered_ports.to_string().yellow()
            );
        }

        println!("Closed ports: {}", summary.closed_ports.to_string().red());
        println!(
            "Filtered ports: {}",
            summary.filtered_ports.to_string().red()
        );
        println!("Scan time: {:.2}s", summary.scan_time);
        println!("Scan method: {}", summary.scan_method);
        println!("Protocols: {}", summary.protocols_scanned.join(", "));

        if summary.ssl_services_found > 0 {
            println!(
                "SSL/TLS services found: {}",
                summary.ssl_services_found.to_string().green()
            );
        }

        // Calculate and display statistics
        let total_results = tcp_results.len() + udp_results.len();
        if total_results > 0 {
            let all_results: Vec<&ScanResult> = tcp_results
                .iter()
                .chain(udp_results.iter())
                .copied()
                .collect();
            let avg_time = all_results.iter().map(|r| r.response_time).sum::<u64>() as f64
                / all_results.len() as f64
                / 1000.0;
            println!("Average response time: {:.3}s", avg_time);
        }

        if self.service_detection && summary.open_ports > 0 {
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
            println!("OS detection: Completed");
        }

        if self.ssl_analysis && summary.ssl_services_found > 0 {
            println!(
                "SSL/TLS analysis: {} services analyzed",
                summary.ssl_services_found
            );
        }

        println!("\n{}", "=".repeat(80));
    }

    // Helper method to identify SSL/TLS ports
    fn is_ssl_port(&self, port: u16) -> bool {
        // Common SSL/TLS ports
        matches!(
            port,
            443 |   // HTTPS
            465 |   // SMTPS
            587 |   // SMTP with TLS
            993 |   // IMAPS
            995 |   // POP3S
            636 |   // LDAPS
            853 |   // DNS over TLS
            990 |   // FTPS
            992 |   // Telnets
            1443 |  // HTTPS alt
            2376 |  // Docker TLS
            3269 |  // Global Catalog SSL
            5061 |  // SIP TLS
            5986 |  // WinRM HTTPS
            8443 |  // HTTPS alt
            8834 |  // Nessus HTTPS
            9443 // VMware HTTPS
        ) || {
            // Also check for common HTTPS alternative ports
            matches!(port, 8080 | 8000 | 9000 | 3000 | 4443 | 7443 | 10443)
        }
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
        // Web Services
        (80, "http"),
        (443, "https"),
        (8080, "http-proxy"),
        (8000, "http-alt"),
        (8443, "https-alt"),
        (8888, "http-alt"),
        (9000, "http-alt"),
        (3000, "http-dev"),
        // Remote Access
        (22, "ssh"),
        (23, "telnet"),
        (3389, "rdp"),
        (5900, "vnc"),
        (2222, "ssh-alt"),
        // Mail Services
        (25, "smtp"),
        (110, "pop3"),
        (143, "imap"),
        (465, "smtps"),
        (587, "submission"),
        (993, "imaps"),
        (995, "pop3s"),
        (2525, "smtp-alt"),
        // File Transfer
        (20, "ftp-data"),
        (21, "ftp"),
        (69, "tftp"),
        (990, "ftps"),
        (115, "sftp"),
        (989, "ftps-data"),
        // Databases
        (3306, "mysql"),
        (5432, "postgresql"),
        (1433, "mssql"),
        (1521, "oracle"),
        (27017, "mongodb"),
        (6379, "redis"),
        (50000, "db2"),
        (1526, "oracle-alt"),
        (27018, "mongodb-shard"),
        (27019, "mongodb-config"),
        (28017, "mongodb-web"),
        // Directory Services
        (389, "ldap"),
        (636, "ldaps"),
        (3268, "globalcatalog"),
        (3269, "globalcatalog-ssl"),
        // Network Services
        (53, "dns"),
        (123, "ntp"),
        (161, "snmp"),
        (162, "snmp-trap"),
        (67, "dhcp-server"),
        (68, "dhcp-client"),
        (179, "bgp"),
        (520, "rip"),
        (521, "ripng"),
        (853, "dns-over-tls"),
        (5353, "mdns"),
        (546, "dhcpv6-client"),
        (547, "dhcpv6-server"),
        // File Sharing
        (135, "msrpc"),
        (139, "netbios-ssn"),
        (445, "smb"),
        (2049, "nfs"),
        (548, "afp"),
        (137, "netbios-ns"),
        (138, "netbios-dgm"),
        // Security & VPN
        (500, "ipsec"),
        (1194, "openvpn"),
        (1701, "l2tp"),
        (1723, "pptp"),
        (4500, "ipsec-nat"),
        // Application Servers
        (1099, "java-rmi"),
        (8009, "ajp13"),
        (8161, "activemq"),
        (9042, "cassandra"),
        (11211, "memcached"),
        (9200, "elasticsearch"),
        (5601, "kibana"),
        (8983, "solr"),
        (9160, "cassandra-thrift"),
        (7000, "cassandra"),
        (7001, "cassandra-ssl"),
        // Development & Testing
        (4000, "node-dev"),
        (5000, "flask-dev"),
        (8000, "django-dev"),
        (9229, "node-inspector"),
        (3001, "node-dev-alt"),
        (4848, "glassfish-admin"),
        // Container & Cloud
        (2375, "docker"),
        (2376, "docker-ssl"),
        (6443, "kubernetes"),
        (10250, "kubelet"),
        (2377, "docker-swarm"),
        (4243, "docker-alt"),
        (8001, "kubernetes-api-alt"),
        (10255, "kubelet-readonly"),
        // Media & Streaming
        (554, "rtsp"),
        (1935, "rtmp"),
        (5060, "sip"),
        (5061, "sips"),
        (8554, "rtsp-alt"),
        (5004, "rtp"),
        // Monitoring & Management
        (3000, "grafana"),
        (8086, "influxdb"),
        (9090, "prometheus"),
        (8125, "statsd"),
        (8126, "statsd-admin"),
        (199, "smux"),
        (1234, "hotline"),
        (9300, "elasticsearch-cluster"),
        // Gaming
        (25565, "minecraft"),
        (27015, "steam"),
        (7777, "teamspeak"),
        (9987, "teamspeak3"),
        (28960, "cod4"),
        // Enterprise Software
        (1414, "ibm-mq"),
        (1830, "oracle-alt"),
        (5984, "couchdb"),
        (7474, "neo4j"),
        (9418, "git"),
        // Print Services
        (515, "lpr"),
        (631, "ipp"),
        (9100, "jetdirect"),
        // Proxy & Load Balancers
        (1080, "socks"),
        (3128, "squid"),
        (8118, "privoxy"),
        (9050, "tor-socks"),
        (9051, "tor-control"),
        // Backup & Sync
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
        // Miscellaneous
        (79, "finger"),
        (113, "ident"),
        (119, "nntp"),
        (563, "nntps"),
        (1900, "upnp"),
        (2000, "cisco-sccp"),
        (11111, "vce"),
        (12345, "netbus"),
        (31337, "back-orifice"),
        (992, "telnets"),
        (513, "rlogin"),
        (514, "rsh"),
        (5901, "vnc-1"),
        (5902, "vnc-2"),
        (5903, "vnc-3"),
        (5904, "vnc-4"),
        (5905, "vnc-5"),
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
        (500, "ipsec"),
        (514, "syslog"),
        (520, "rip"),
        (1194, "openvpn"),
        (1701, "l2tp"),
        (1900, "upnp"),
        (4500, "ipsec-nat"),
        (5353, "mdns"),
        (5060, "sip"),
        (6881, "bittorrent"),
        (27015, "steam"),
        (27017, "mongodb"),
        (521, "ripng"),
        (546, "dhcpv6-client"),
        (547, "dhcpv6-server"),
        (853, "dns-over-tls"),
        (1812, "radius"),
        (1813, "radius-acct"),
        (1645, "radius-alt"),
        (1646, "radius-acct-alt"),
        (2049, "nfs"),
        (111, "rpc"),
        (1434, "mssql-m"),
        (1433, "mssql"),
        (5432, "postgresql"),
        (3306, "mysql"),
        (11211, "memcached"),
        (6379, "redis"),
        (27018, "mongodb-shard"),
        (27019, "mongodb-config"),
        (28017, "mongodb-web"),
        (50000, "db2"),
        (389, "ldap"),
        (636, "ldaps"),
        (3268, "globalcatalog"),
        (3269, "globalcatalog-ssl"),
        (179, "bgp"),
        (1883, "mqtt"),
        (8883, "mqtt-ssl"),
        (5683, "coap"),
        (5004, "rtp"),
        (1935, "rtmp"),
        (8554, "rtsp-alt"),
        (873, "rsync"),
        (548, "afp"),
        (6000, "x11"),
        (631, "ipp"),
        (9100, "jetdirect"),
        (515, "lpr"),
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
        80 | 8080 | 8081 | 8000 | 3000 => grab_http_banner(stream, timeout_duration).await,
        443 | 8443 => read_banner(stream, timeout_duration).await,
        53 => Some("DNS Server".to_string()),
        3306 => read_banner(stream, timeout_duration).await,
        5432 => read_banner(stream, timeout_duration).await,
        1433 => read_banner(stream, timeout_duration).await,
        1521 => read_banner(stream, timeout_duration).await,
        27017 => read_banner(stream, timeout_duration).await,
        6379 => read_banner(stream, timeout_duration).await,
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

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}
