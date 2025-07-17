use super::config::ScanConfig;
use super::scan_results::{CompleteScanResult, ScanResult, ScanSummary};
use crate::os_fingerprinting::{format_os_info, OSFingerprint};
use crate::service_detection::format_service_info;
use crate::ssl::format_ssl_analysis;
use chrono::Utc;
use colored::*;
use std::collections::HashMap;
use std::time::Instant;

pub fn print_scan_header(config: &ScanConfig) {
    let scan_method = config.get_scan_method_name();
    let protocol_info = config.get_protocol_info();
    let total_ports = config.get_total_ports();

    println!(
        "\n{}",
        "╔═══════════════════════════════════════════════════════════════╗".cyan()
    );
    println!(
        "{}",
        "║                    🚀 SCAN INITIALIZATION                     ║".cyan()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════╝".cyan()
    );

    println!(
        "🎯 Target:           {}",
        config.target.to_string().yellow().bold()
    );
    println!(
        "📡 Total Ports:      {}",
        total_ports.to_string().green().bold()
    );
    println!("🔧 Scan Method:      {}", scan_method.blue().bold());
    println!("🔌 Protocol(s):      {}", protocol_info.magenta().bold());
    println!(
        "⚡ Concurrency:      {}",
        config.concurrency.to_string().cyan()
    );
    println!(
        "⏱️ Timeout:          {}ms",
        config.timeout_ms.to_string().yellow()
    );

    if config.grab_banner {
        println!("🏷️ Banner Grabbing:  {}", "ENABLED".green().bold());
    }

    if config.service_detection {
        println!("🔍 Service Detection: {}", "ENABLED".green().bold());
    }

    if config.os_detection {
        println!("🖥️ OS Fingerprinting: {}", "ENABLED".green().bold());
    }

    if config.ssl_analysis {
        println!("🔐 SSL/TLS Analysis:  {}", "ENABLED".green().bold());
    }

    println!(
        "\n{}",
        "Initializing scan engines...".bright_green().italic()
    );

    // Animation for scan start
    for i in 0..3 {
        print!("\r{} Loading{}", "⚡".yellow(), ".".repeat(i + 1));
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    println!("\r{} Ready to scan! 🚀", "✅".green());
}

pub fn display_formatted_results(complete_result: CompleteScanResult, config: &ScanConfig) {
    let mut results = complete_result.scan_results;
    results.sort_by_key(|r| (r.port, r.protocol.clone()));

    print_results_header(&complete_result.target);

    // Separate TCP and UDP results
    let tcp_results: Vec<_> = results.iter().filter(|r| r.protocol == "TCP").collect();
    let udp_results: Vec<_> = results.iter().filter(|r| r.protocol == "UDP").collect();

    // Display TCP results with enhanced formatting
    if !tcp_results.is_empty() {
        display_enhanced_tcp_results(&tcp_results, &config.scan_type);
    }

    // Display UDP results with enhanced formatting
    if !udp_results.is_empty() {
        display_enhanced_udp_results(&udp_results);
    }

    // Display OS Detection with enhanced formatting
    if let Some(os_info) = &complete_result.os_fingerprint {
        display_enhanced_os_detection(os_info);
    }

    // Display SSL/TLS Analysis with enhanced formatting
    if !complete_result.ssl_analysis.is_empty() {
        display_enhanced_ssl_analysis(&complete_result.ssl_analysis);
    }

    // Display Enhanced Summary
    display_enhanced_scan_summary(
        &complete_result.scan_summary,
        &tcp_results,
        &udp_results,
        config,
    );
}

fn print_results_header(target: &str) {
    println!(
        "\n{}",
        "╔═══════════════════════════════════════════════════════════════╗".cyan()
    );
    println!(
        "{}",
        format!(
            "║{}SCAN RESULTS FOR {}{}║",
            " ".repeat(15),
            target.yellow().bold(),
            " ".repeat(15 - target.len().min(15))
        )
        .cyan()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════╝".cyan()
    );
}

fn display_enhanced_tcp_results(tcp_results: &[&ScanResult], scan_type: &super::config::ScanType) {
    println!(
        "\n{}",
        "┌─────────────────────────────────────────────────────────────┐".blue()
    );
    println!(
        "{}",
        "│                     🌐 TCP SCAN RESULTS                      │".blue()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────┘".blue()
    );

    let open_tcp_ports: Vec<_> = tcp_results.iter().filter(|r| r.is_open).collect();
    let closed_tcp_ports: Vec<_> = tcp_results.iter().filter(|r| !r.is_open).collect();

    if open_tcp_ports.is_empty() {
        println!("\n{}", "   ❌ No open TCP ports found".red().bold());
        print_scan_tips_for_no_results();
    } else {
        println!(
            "\n{} {} open TCP ports discovered:",
            "🎯".green(),
            open_tcp_ports.len().to_string().green().bold()
        );

        println!("\n{}", "─".repeat(80).dimmed());
        println!(
            "{:<8} {:<12} {:<25} {:<15} {:<12}",
            "PORT".cyan().bold(),
            "STATE".cyan().bold(),
            "SERVICE".cyan().bold(),
            "VERSION".cyan().bold(),
            "RESPONSE".cyan().bold()
        );
        println!("{}", "─".repeat(80).dimmed());

        for (i, result) in open_tcp_ports.iter().enumerate() {
            let scan_indicator = match result.scan_type.as_str() {
                "SYN" => "⚡",
                _ => "🔗",
            };

            let service_display = if let Some(service_info) = &result.service_info {
                format_service_info(service_info)
            } else {
                result.service.as_deref().unwrap_or("unknown").to_string()
            };

            let version_display = if let Some(service_info) = &result.service_info {
                service_info.version.as_deref().unwrap_or("-").to_string()
            } else {
                "-".to_string()
            };

            // Color code based on port type
            let port_color = match result.port {
                22 => result.port.to_string().yellow(),
                80 | 8080 | 8000 => result.port.to_string().blue(),
                443 | 8443 => result.port.to_string().green(),
                21 | 23 | 25 | 110 | 143 => result.port.to_string().red(),
                _ => result.port.to_string().white(),
            };

            println!(
                "{} {}/tcp {} {:<25} {:<15} {:<8}ms",
                scan_indicator,
                port_color.bold(),
                "open".green().bold(),
                truncate_string(&service_display, 25).blue(),
                truncate_string(&version_display, 15).yellow(),
                result.response_time.to_string().dimmed()
            );

            if let Some(banner) = &result.banner {
                let truncated_banner = truncate_string(banner, 70);
                println!("         └─ Banner: {}", truncated_banner.dimmed().italic());
            }

            if let Some(service_info) = &result.service_info {
                if service_info.confidence < 70 {
                    println!(
                        "         └─ Confidence: {}%",
                        service_info.confidence.to_string().yellow()
                    );
                }
            }

            // Add spacing between entries
            if i < open_tcp_ports.len() - 1 {
                println!("{}", "│".dimmed());
            }
        }

        println!("{}", "─".repeat(80).dimmed());
    }

    // Display closed/filtered ports summary
    if matches!(scan_type, super::config::ScanType::StealthSyn) && !closed_tcp_ports.is_empty() {
        let closed_slice: Vec<&ScanResult> = closed_tcp_ports.iter().map(|r| **r).collect();
        display_closed_ports_summary(&closed_slice);
    }
}

fn display_enhanced_udp_results(udp_results: &[&ScanResult]) {
    println!(
        "\n{}",
        "┌─────────────────────────────────────────────────────────────┐".magenta()
    );
    println!(
        "{}",
        "│                     📡 UDP SCAN RESULTS                      │".magenta()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────┘".magenta()
    );

    let open_udp_ports: Vec<_> = udp_results.iter().filter(|r| r.is_open).collect();
    let open_filtered_udp: Vec<_> = udp_results
        .iter()
        .filter(|r| r.udp_state.as_deref() == Some("open|filtered"))
        .collect();
    let closed_udp_ports: Vec<_> = udp_results
        .iter()
        .filter(|r| r.udp_state.as_deref() == Some("closed"))
        .collect();

    if !open_udp_ports.is_empty() {
        println!(
            "\n{} {} open UDP ports discovered:",
            "🎯".green(),
            open_udp_ports.len().to_string().green().bold()
        );

        println!("\n{}", "─".repeat(80).dimmed());
        println!(
            "{:<8} {:<12} {:<25} {:<15} {:<12}",
            "PORT".cyan().bold(),
            "STATE".cyan().bold(),
            "SERVICE".cyan().bold(),
            "RESPONSE".cyan().bold(),
            "TIME".cyan().bold()
        );
        println!("{}", "─".repeat(80).dimmed());

        for result in &open_udp_ports {
            let service_display = if let Some(service_info) = &result.service_info {
                format_service_info(service_info)
            } else {
                result.service.as_deref().unwrap_or("unknown").to_string()
            };

            println!(
                "📡 {}/udp {} {:<25} {:<15} {:<8}ms",
                result.port.to_string().green().bold(),
                "open".green().bold(),
                truncate_string(&service_display, 25).blue(),
                "-".dimmed(),
                result.response_time.to_string().dimmed()
            );

            if let Some(banner) = &result.banner {
                let truncated_banner = truncate_string(banner, 70);
                println!(
                    "         └─ Response: {}",
                    truncated_banner.dimmed().italic()
                );
            }
        }

        println!("{}", "─".repeat(80).dimmed());
    }

    if !open_filtered_udp.is_empty() {
        println!(
            "\n{} {} UDP ports are open|filtered:",
            "❓".yellow(),
            open_filtered_udp.len().to_string().yellow().bold()
        );

        let open_filtered_slice: Vec<&ScanResult> = open_filtered_udp.iter().map(|r| **r).collect();
        let port_groups = group_consecutive_ports(&open_filtered_slice);

        for group in port_groups {
            if group.len() > 3 {
                println!(
                    "   📡 {}-{} ({})",
                    group[0].port.to_string().yellow(),
                    group[group.len() - 1].port.to_string().yellow(),
                    group.len().to_string().dimmed()
                );
            } else {
                for result in group {
                    let service = result.service.as_deref().unwrap_or("unknown");
                    println!(
                        "   📡 {}/udp {} {}",
                        result.port.to_string().yellow(),
                        "open|filtered".yellow(),
                        service.blue()
                    );
                }
            }
        }
    }

    if !closed_udp_ports.is_empty() {
        println!(
            "\n{} {} UDP ports closed (ICMP unreachable)",
            "❌".red(),
            closed_udp_ports.len().to_string().red()
        );
    }

    if open_udp_ports.is_empty() && open_filtered_udp.is_empty() {
        println!("\n{}", "   ❌ No responsive UDP ports found".red().bold());
        println!("   💡 Note: UDP scanning can produce false negatives");
        println!("   💡 Services may be running but not responding to probes");
    }
}

fn display_enhanced_os_detection(os_info: &OSFingerprint) {
    println!(
        "\n{}",
        "┌─────────────────────────────────────────────────────────────┐".green()
    );
    println!(
        "{}",
        "│                  🖥️ OS DETECTION RESULTS                    │".green()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────┘".green()
    );

    // OS confidence indicator
    let confidence_indicator = match os_info.confidence {
        90..=100 => "🟢",
        75..=89 => "🟡",
        60..=74 => "🟠",
        _ => "🔴",
    };

    println!(
        "\n{} Operating System: {}",
        confidence_indicator,
        format_os_info(os_info).cyan().bold()
    );

    println!(
        "   {} Confidence: {}% ({})",
        "📊".blue(),
        os_info.confidence.to_string().yellow().bold(),
        os_info.confidence_text().dimmed()
    );

    if let Some(device_type) = &os_info.device_type {
        println!("   {} Device Type: {}", "💻".blue(), device_type.green());
    }

    if let Some(vendor) = &os_info.vendor {
        println!("   {} Vendor: {}", "🏢".blue(), vendor.yellow());
    }

    if let Some(architecture) = &os_info.architecture {
        println!(
            "   {} Architecture: {}",
            "⚙️".blue(),
            architecture.magenta()
        );
    }

    if !os_info.details.is_empty() {
        println!("\n   {} Technical Details:", "🔧".blue());
        for detail in &os_info.details {
            println!("      • {}", detail.dimmed());
        }
    }

    if let Some(cpe) = &os_info.cpe {
        println!("\n   {} CPE: {}", "🏷️".blue(), cpe.dimmed());
    }
}

fn display_enhanced_ssl_analysis(ssl_results: &[crate::ssl::SslAnalysisResult]) {
    println!(
        "\n{}",
        "┌─────────────────────────────────────────────────────────────┐".cyan()
    );
    println!(
        "{}",
        "│                  🔐 SSL/TLS ANALYSIS RESULTS                │".cyan()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────┘".cyan()
    );

    for (i, ssl_result) in ssl_results.iter().enumerate() {
        if i > 0 {
            println!("{}", "─".repeat(60).dimmed());
        }

        let score_indicator = match ssl_result.security_score {
            90..=100 => "🟢",
            80..=89 => "🟡",
            70..=79 => "🟠",
            60..=69 => "🔴",
            _ => "💀",
        };

        let score_text = match ssl_result.security_score {
            90..=100 => "Excellent",
            80..=89 => "Good",
            70..=79 => "Fair",
            60..=69 => "Poor",
            _ => "Critical",
        };

        println!(
            "\n{} Port {}: {} {}/100 ({})",
            score_indicator,
            ssl_result.port.to_string().cyan().bold(),
            "Security Score".blue(),
            ssl_result.security_score.to_string().yellow().bold(),
            score_text.dimmed()
        );

        if let Some(cert) = &ssl_result.certificate_info {
            println!("   {} Certificate: {}", "📜".blue(), cert.subject.green());
            println!("   {} Issuer: {}", "🏢".blue(), cert.issuer.yellow());

            let expiry_indicator = if cert.is_expired {
                "🔴"
            } else if cert.days_until_expiry < 7 {
                "🔴"
            } else if cert.days_until_expiry < 30 {
                "🟡"
            } else {
                "🟢"
            };

            println!(
                "   {} Expires: {} ({} days)",
                expiry_indicator,
                cert.not_after.blue(),
                cert.days_until_expiry.to_string().yellow()
            );
        }

        // Protocol support
        let supported_protocols: Vec<_> = ssl_result
            .supported_protocols
            .iter()
            .filter(|p| p.supported)
            .collect();

        if !supported_protocols.is_empty() {
            println!(
                "   {} Protocols: {}",
                "🔌".blue(),
                supported_protocols
                    .iter()
                    .map(|p| {
                        let color = match p.security_level {
                            crate::ssl::SecurityLevel::Secure => p.version.green(),
                            crate::ssl::SecurityLevel::Warning => p.version.yellow(),
                            crate::ssl::SecurityLevel::Weak => p.version.red(),
                            crate::ssl::SecurityLevel::Insecure => p.version.red().bold(),
                        };
                        color.to_string()
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        // Vulnerabilities
        if !ssl_result.vulnerabilities.is_empty() {
            println!("   {} Vulnerabilities:", "⚠️".red());
            for vuln in &ssl_result.vulnerabilities {
                let severity_icon = match vuln.severity {
                    crate::ssl::VulnerabilitySeverity::Critical => "💀",
                    crate::ssl::VulnerabilitySeverity::High => "🔴",
                    crate::ssl::VulnerabilitySeverity::Medium => "🟠",
                    crate::ssl::VulnerabilitySeverity::Low => "🟡",
                    crate::ssl::VulnerabilitySeverity::Info => "ℹ️",
                };
                println!("      {} {}", severity_icon, vuln.name.red());
            }
        }
    }
}

fn display_enhanced_scan_summary(
    summary: &ScanSummary,
    tcp_results: &[&ScanResult],
    udp_results: &[&ScanResult],
    config: &ScanConfig,
) {
    println!(
        "\n{}",
        "┌─────────────────────────────────────────────────────────────┐".white()
    );
    println!(
        "{}",
        "│                      📊 SCAN SUMMARY                        │".white()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────┘".white()
    );

    // Create a nice statistics table
    println!("\n{}", "📈 Statistics:".blue().bold());
    println!("   ┌─────────────────────┬─────────────────────┐");
    println!(
        "   │ Total Ports Scanned │ {:>19} │",
        summary.total_ports.to_string().cyan()
    );
    println!(
        "   │ Open Ports          │ {:>19} │",
        summary.open_ports.to_string().green()
    );

    if summary.open_filtered_ports > 0 {
        println!(
            "   │ Open|Filtered       │ {:>19} │",
            summary.open_filtered_ports.to_string().yellow()
        );
    }

    println!(
        "   │ Closed Ports        │ {:>19} │",
        summary.closed_ports.to_string().red()
    );
    println!(
        "   │ Filtered Ports      │ {:>19} │",
        summary.filtered_ports.to_string().red()
    );
    println!("   │ Scan Time           │ {:>17.2}s │", summary.scan_time);
    println!("   └─────────────────────┴─────────────────────┘");

    // Performance metrics
    if summary.total_ports > 0 {
        let ports_per_second = summary.total_ports as f64 / summary.scan_time;
        println!(
            "\n{} Performance: {:.0} ports/second",
            "⚡".yellow(),
            ports_per_second.to_string().cyan().bold()
        );
    }

    // Security assessment
    if summary.open_ports > 0 {
        println!("\n{} Security Assessment:", "🛡️".blue().bold());

        let security_score = calculate_security_score(&tcp_results, &udp_results);
        let (score_color, score_text) = match security_score {
            80..=100 => (security_score.to_string().green(), "Good"),
            60..=79 => (security_score.to_string().yellow(), "Fair"),
            40..=59 => (security_score.to_string().red(), "Poor"),
            _ => (security_score.to_string().red().bold(), "Critical"),
        };

        println!(
            "   Overall Security Score: {}/100 ({})",
            score_color,
            score_text.dimmed()
        );

        // Risk analysis
        let high_risk_ports = count_high_risk_ports(&tcp_results);
        if high_risk_ports > 0 {
            println!(
                "   {} High-risk ports detected: {}",
                "⚠️".red(),
                high_risk_ports.to_string().red().bold()
            );
        }
    }

    // Protocol breakdown
    println!("\n{} Protocol Breakdown:", "🔌".blue().bold());
    if !tcp_results.is_empty() {
        let tcp_open = tcp_results.iter().filter(|r| r.is_open).count();
        println!(
            "   TCP: {} open / {} scanned",
            tcp_open.to_string().green(),
            tcp_results.len().to_string().dimmed()
        );
    }

    if !udp_results.is_empty() {
        let udp_open = udp_results.iter().filter(|r| r.is_open).count();
        let udp_open_filtered = udp_results
            .iter()
            .filter(|r| r.udp_state.as_deref() == Some("open|filtered"))
            .count();
        println!(
            "   UDP: {} open, {} open|filtered / {} scanned",
            udp_open.to_string().green(),
            udp_open_filtered.to_string().yellow(),
            udp_results.len().to_string().dimmed()
        );
    }

    // Additional insights
    if config.service_detection && summary.open_ports > 0 {
        let tcp_identified = tcp_results
            .iter()
            .filter(|r| r.is_open && r.service_info.as_ref().map_or(false, |s| s.confidence > 70))
            .count();

        println!("\n{} Service Identification:", "🔍".blue().bold());
        println!(
            "   TCP services identified: {}/{}",
            tcp_identified.to_string().green(),
            tcp_results
                .iter()
                .filter(|r| r.is_open)
                .count()
                .to_string()
                .dimmed()
        );
    }

    if config.ssl_analysis && summary.ssl_services_found > 0 {
        println!(
            "\n{} SSL/TLS Services: {} analyzed",
            "🔐".blue().bold(),
            summary.ssl_services_found.to_string().cyan()
        );
    }

    // Recommendations
    print_security_recommendations(&tcp_results, &udp_results, config);

    // Final footer
    println!("\n{}", "─".repeat(80).dimmed());
    println!(
        "{} Scan completed at {}",
        "✅".green(),
        chrono::Utc::now()
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string()
            .dimmed()
    );
    println!("{}", "─".repeat(80).dimmed());
}

fn print_security_recommendations(
    tcp_results: &[&ScanResult],
    udp_results: &[&ScanResult],
    config: &ScanConfig,
) {
    println!("\n{} Security Recommendations:", "💡".yellow().bold());

    let mut recommendations = Vec::new();

    // Check for common security issues
    let has_telnet = tcp_results.iter().any(|r| r.is_open && r.port == 23);
    let has_ftp = tcp_results.iter().any(|r| r.is_open && r.port == 21);
    let has_ssh = tcp_results.iter().any(|r| r.is_open && r.port == 22);
    let has_rdp = tcp_results.iter().any(|r| r.is_open && r.port == 3389);

    if has_telnet {
        recommendations.push("🔴 Disable Telnet (port 23) - use SSH instead");
    }

    if has_ftp {
        recommendations.push("🟡 Consider using SFTP instead of FTP (port 21)");
    }

    if has_ssh {
        recommendations.push("🟢 SSH detected - ensure key-based authentication");
    }

    if has_rdp {
        recommendations.push("🟡 RDP detected - ensure strong passwords and VPN access");
    }

    // Check for unnecessary services
    let open_count = tcp_results.iter().filter(|r| r.is_open).count();
    if open_count > 5 {
        recommendations.push("🟡 Consider reducing the number of exposed services");
    }

    if recommendations.is_empty() {
        recommendations.push("🟢 No immediate security concerns detected");
    }

    for rec in recommendations {
        println!("   {}", rec);
    }
}

fn print_scan_tips_for_no_results() {
    println!("\n{} Troubleshooting Tips:", "💡".yellow().bold());
    println!("   • Try increasing concurrency: --concurrency 200");
    println!("   • Use stealth scan: --stealth (requires root)");
    println!("   • Check firewall settings on target");
    println!("   • Try different port ranges: --ports 1-65535");
    println!("   • Enable UDP scanning: --protocol both");
}

fn display_closed_ports_summary(closed_ports: &[&ScanResult]) {
    let filtered_count = closed_ports
        .iter()
        .filter(|r| r.service.as_deref() == Some("filtered"))
        .count();
    let closed_count = closed_ports.len() - filtered_count;

    println!("\n{} Port Status Summary:", "📊".blue());

    if filtered_count > 0 {
        println!(
            "   {} {} ports filtered (no response)",
            "🟡".yellow(),
            filtered_count.to_string().yellow()
        );
    }

    if closed_count > 0 {
        println!(
            "   {} {} ports closed (RST received)",
            "🔴".red(),
            closed_count.to_string().red()
        );
    }
}

// Helper functions
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

fn group_consecutive_ports<'a>(results: &'a [&ScanResult]) -> Vec<Vec<&'a ScanResult>> {
    let mut groups = Vec::new();
    let mut current_group = Vec::new();

    for result in results {
        if current_group.is_empty() {
            current_group.push(*result);
        } else {
            let last_port = current_group.last().unwrap().port;
            if result.port == last_port + 1 {
                current_group.push(*result);
            } else {
                groups.push(current_group);
                current_group = vec![*result];
            }
        }
    }

    if !current_group.is_empty() {
        groups.push(current_group);
    }

    groups
}

fn calculate_security_score(tcp_results: &[&ScanResult], udp_results: &[&ScanResult]) -> u8 {
    let mut score = 100u8;

    // Deduct points for risky open ports
    for result in tcp_results.iter().filter(|r| r.is_open) {
        match result.port {
            23 => score = score.saturating_sub(30),              // Telnet
            21 => score = score.saturating_sub(20),              // FTP
            135 | 139 | 445 => score = score.saturating_sub(15), // SMB
            3389 => score = score.saturating_sub(10),            // RDP
            1433 | 3306 | 5432 => score = score.saturating_sub(15), // Databases
            _ => score = score.saturating_sub(2),                // Other open ports
        }
    }

    // Deduct points for UDP services
    for result in udp_results.iter().filter(|r| r.is_open) {
        match result.port {
            161 => score = score.saturating_sub(10), // SNMP
            69 => score = score.saturating_sub(15),  // TFTP
            _ => score = score.saturating_sub(1),
        }
    }

    score
}

fn count_high_risk_ports(tcp_results: &[&ScanResult]) -> usize {
    tcp_results
        .iter()
        .filter(|r| r.is_open && matches!(r.port, 23 | 21 | 135 | 139 | 445 | 1433 | 3306 | 5432))
        .count()
}
