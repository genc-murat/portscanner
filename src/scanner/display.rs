use super::config::ScanConfig;
use super::scan_results::{CompleteScanResult, ScanResult, ScanSummary};
use crate::os_fingerprinting::{format_os_info, OSFingerprint};
use crate::service_detection::format_service_info;
use crate::ssl::format_ssl_analysis;
use colored::*;

pub fn print_scan_header(config: &ScanConfig) {
    let scan_method = config.get_scan_method_name();
    let protocol_info = config.get_protocol_info();
    let total_ports = config.get_total_ports();

    println!("Starting scan: {} ({} ports)", config.target, total_ports);
    println!("Scan method: {}", scan_method);
    println!("Protocol(s): {}", protocol_info);

    if config.grab_banner {
        println!("Banner grabbing enabled!");
    }

    if config.service_detection {
        println!("Advanced service detection enabled!");
    }

    if config.os_detection {
        println!("OS fingerprinting enabled!");
    }

    if config.ssl_analysis {
        println!("SSL/TLS analysis enabled!");
    }
}

pub fn display_formatted_results(complete_result: CompleteScanResult, config: &ScanConfig) {
    let mut results = complete_result.scan_results;
    results.sort_by_key(|r| (r.port, r.protocol.clone()));

    println!("\n{}", "=".repeat(80));
    println!("Port Scan Results - {}", complete_result.target);
    println!("{}", "=".repeat(80));

    // Separate TCP and UDP results
    let tcp_results: Vec<_> = results.iter().filter(|r| r.protocol == "TCP").collect();
    let udp_results: Vec<_> = results.iter().filter(|r| r.protocol == "UDP").collect();

    // Display TCP results
    if !tcp_results.is_empty() {
        display_tcp_results(&tcp_results, &config.scan_type);
    }

    // Display UDP results
    if !udp_results.is_empty() {
        display_udp_results(&udp_results);
    }

    // Display OS Detection
    if let Some(os_info) = &complete_result.os_fingerprint {
        display_os_detection(os_info);
    }

    // Display SSL/TLS Analysis
    if !complete_result.ssl_analysis.is_empty() {
        for ssl_result in &complete_result.ssl_analysis {
            print!("{}", format_ssl_analysis(ssl_result));
        }
    }

    // Display Summary
    display_scan_summary(
        &complete_result.scan_summary,
        &tcp_results,
        &udp_results,
        config,
    );
}

fn display_tcp_results(tcp_results: &[&ScanResult], scan_type: &super::config::ScanType) {
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

    if matches!(scan_type, super::config::ScanType::StealthSyn) && !closed_tcp_ports.is_empty() {
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

fn display_udp_results(udp_results: &[&ScanResult]) {
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

fn display_os_detection(os_info: &OSFingerprint) {
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
    summary: &ScanSummary,
    tcp_results: &[&ScanResult],
    udp_results: &[&ScanResult],
    config: &ScanConfig,
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

    if config.service_detection && summary.open_ports > 0 {
        let tcp_identified = tcp_results
            .iter()
            .filter(|r| r.is_open && r.service_info.as_ref().map_or(false, |s| s.confidence > 70))
            .count();
        let udp_identified = udp_results
            .iter()
            .filter(|r| r.is_open && r.service_info.as_ref().map_or(false, |s| s.confidence > 70))
            .count();

        println!(
            "Services identified with high confidence: TCP {}/{}, UDP {}/{}",
            tcp_identified,
            tcp_results.iter().filter(|r| r.is_open).count(),
            udp_identified,
            udp_results.iter().filter(|r| r.is_open).count()
        );
    }

    if config.os_detection {
        println!("OS detection: Completed");
    }

    if config.ssl_analysis && summary.ssl_services_found > 0 {
        println!(
            "SSL/TLS analysis: {} services analyzed",
            summary.ssl_services_found
        );
    }

    println!("\n{}", "=".repeat(80));
}
