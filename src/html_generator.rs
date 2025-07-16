use crate::os_fingerprinting::OSFingerprint;
use crate::scanner::{CompleteScanResult, ScanResult};
use crate::ssl::SslAnalysisResult;
use std::fs::File;
use std::io::Write;

pub fn write_html_report(result: &CompleteScanResult, filename: &str) -> std::io::Result<()> {
    let html_content = generate_html_report(result);
    let mut file = File::create(filename)?;
    file.write_all(html_content.as_bytes())?;
    Ok(())
}

fn generate_html_report(result: &CompleteScanResult) -> String {
    let body = format!(
        r#"
        <div class="container">
            <h1>Port Scan Report for {target}</h1>
            {summary}
            {os_detection}
            {tcp_results}
            {udp_results}
            {ssl_analysis}
        </div>
        "#,
        target = result.target,
        summary = generate_summary_section(result),
        os_detection = generate_os_detection_section(&result.os_fingerprint),
        tcp_results = generate_results_table(&result.scan_results, "TCP"),
        udp_results = generate_results_table(&result.scan_results, "UDP"),
        ssl_analysis = generate_ssl_analysis_section(&result.ssl_analysis),
    );

    wrap_with_html_template(&body, &result.target)
}

fn generate_summary_section(result: &CompleteScanResult) -> String {
    format!(
        r#"
        <div class="card">
            <h2>Scan Summary</h2>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Scan Time:</strong> {scan_time:.2}s</p>
            <p><strong>Total Ports Scanned:</strong> {total_ports}</p>
            <p><strong>Open Ports:</strong> <span class="status-open">{open_ports}</span></p>
            <p><strong>Scan Method:</strong> {scan_method}</p>
        </div>
        "#,
        target = result.target,
        scan_time = result.scan_summary.scan_time,
        total_ports = result.scan_summary.total_ports,
        open_ports = result.scan_summary.open_ports,
        scan_method = result.scan_summary.scan_method,
    )
}

fn generate_os_detection_section(os_fingerprint: &Option<OSFingerprint>) -> String {
    if let Some(os) = os_fingerprint {
        format!(
            r#"
            <div class="card">
                <h2>Operating System Detection</h2>
                <p><strong>OS Name:</strong> {os_name}</p>
                <p><strong>Confidence:</strong> {confidence}%</p>
                <p><strong>Details:</strong></p>
                <ul>
                    {details}
                </ul>
            </div>
            "#,
            os_name = os.os_name,
            confidence = os.confidence,
            details = os
                .details
                .iter()
                .map(|d| format!("<li>{}</li>", d))
                .collect::<String>()
        )
    } else {
        String::new()
    }
}

fn generate_results_table(scan_results: &[ScanResult], protocol_filter: &str) -> String {
    let open_ports: Vec<_> = scan_results
        .iter()
        .filter(|r| r.is_open && r.protocol.to_uppercase() == protocol_filter)
        .collect();

    if open_ports.is_empty() {
        return String::new();
    }

    let rows = open_ports
        .iter()
        .map(|r| {
            format!(
                r#"
            <tr>
                <td>{port}</td>
                <td><span class="status-open">Open</span></td>
                <td>{service}</td>
                <td>{banner}</td>
                <td>{response_time}ms</td>
            </tr>
            "#,
                port = r.port,
                service = r.service.as_deref().unwrap_or(""),
                banner = r.banner.as_deref().unwrap_or(""),
                response_time = r.response_time
            )
        })
        .collect::<String>();

    format!(
        r#"
        <div class="card">
            <h2>Open {protocol_filter} Ports</h2>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Banner</th>
                        <th>Response Time</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        "#,
        protocol_filter = protocol_filter,
        rows = rows
    )
}

fn generate_ssl_analysis_section(ssl_results: &[SslAnalysisResult]) -> String {
    if ssl_results.is_empty() {
        return String::new();
    }

    let details = ssl_results.iter().map(|s| {
        let cert_info = if let Some(cert) = &s.certificate_info {
            format!(
                "<p><strong>Subject:</strong> {subject}</p><p><strong>Issuer:</strong> {issuer}</p><p><strong>Expires in:</strong> {expiry} days</p>",
                subject = cert.subject,
                issuer = cert.issuer,
                expiry = cert.days_until_expiry
            )
        } else {
            "<p>No certificate information available.</p>".to_string()
        };

        format!(
            r#"
            <div class="ssl-details">
                <h3>Port {port} - Score: <span class="score score-{score_level}">{score}/100</span></h3>
                {cert_info}
                <h4>Supported Protocols</h4>
                <ul>{protocols}</ul>
                <h4>Vulnerabilities</h4>
                <ul>{vulnerabilities}</ul>
            </div>
            "#,
            port = s.port,
            score = s.security_score,
            score_level = if s.security_score > 80 { "high" } else if s.security_score > 50 { "medium" } else { "low" },
            cert_info = cert_info,
            protocols = s.supported_protocols.iter().filter(|p| p.supported).map(|p| format!("<li>{}</li>", p.version)).collect::<String>(),
            vulnerabilities = s.vulnerabilities.iter().map(|v| format!("<li><strong>{name}:</strong> {desc}</li>", name=v.name, desc=v.description)).collect::<String>()
        )
    }).collect::<String>();

    format!(
        r#"
        <div class="card">
            <h2>SSL/TLS Analysis</h2>
            {details}
        </div>
        "#,
        details = details
    )
}

fn wrap_with_html_template(body: &str, title: &str) -> String {
    format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Port Scan Report - {title}</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.6; color: #e0e0e0; background-color: #121212; margin: 0; padding: 20px; }}
                .container {{ max-width: 1000px; margin: auto; }}
                .card {{ background-color: #1e1e1e; border: 1px solid #333; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
                h1, h2, h3 {{ color: #00aaff; border-bottom: 2px solid #00aaff; padding-bottom: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
                th, td {{ padding: 12px; border: 1px solid #333; text-align: left; }}
                th {{ background-color: #252525; }}
                .status-open {{ color: #28a745; font-weight: bold; }}
                .score {{ font-weight: bold; }}
                .score-high {{ color: #28a745; }}
                .score-medium {{ color: #ffc107; }}
                .score-low {{ color: #dc3545; }}
                ul {{ padding-left: 20px; }}
            </style>
        </head>
        <body>
            {body}
        </body>
        </html>
        "#,
        title = title,
        body = body
    )
}
