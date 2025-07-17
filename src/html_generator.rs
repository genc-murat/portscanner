use crate::os_fingerprinting::OSFingerprint;
use crate::scanner::{CompleteScanResult, RiskAssessment, ScanResult}; // RiskAssessment'i scanner'dan import et
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
            {risk_assessment}
            {os_detection}
            {tcp_results}
            {udp_results}
            {ssl_analysis}
        </div>
        "#,
        target = result.target,
        summary = generate_summary_section(result),
        risk_assessment = generate_risk_assessment_section(&result.risk_assessment),
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

fn generate_risk_assessment_section(risk_assessment: &Option<RiskAssessment>) -> String {
    if let Some(assessment) = risk_assessment {
        let posture_color = match assessment.overall_risk_score {
            0..=30 => "critical",
            31..=50 => "high",
            51..=70 => "medium",
            71..=85 => "good",
            86..=100 => "excellent",
            _ => "excellent",
        };

        let critical_findings_html = if !assessment.critical_findings.is_empty() {
            let findings = assessment
                .critical_findings
                .iter()
                .map(|f| {
                    format!(
                        "<div class='finding-item'><strong>{}</strong><br/>{}</div>",
                        f.title, f.description
                    )
                })
                .collect::<String>();
            format!(
                "<h4>Critical Findings</h4><div class='findings-list'>{}</div>",
                findings
            )
        } else {
            String::new()
        };

        let risk_categories_html = assessment.risk_categories.iter()
            .map(|cat| {
                let category_color = match cat.score {
                    0..=30 => "critical",
                    31..=50 => "high",
                    51..=70 => "medium", 
                    _ => "good",
                };
                format!(
                    "<div class='risk-category'><span class='category-name'>{:?}</span><span class='risk-score risk-{}'>{}/100</span></div>",
                    cat.category, category_color, cat.score
                )
            })
            .collect::<String>();

        let recommendations_html = assessment
            .recommendations
            .iter()
            .take(5)
            .map(|rec| {
                let priority_class = match rec.priority {
                    crate::scanner::Priority::Immediate => "immediate",
                    crate::scanner::Priority::High => "high",
                    crate::scanner::Priority::Medium => "medium",
                    crate::scanner::Priority::Low => "low",
                };
                format!(
                    "<li class='recommendation priority-{}'><strong>{}</strong><br/>{}</li>",
                    priority_class, rec.title, rec.description
                )
            })
            .collect::<String>();

        format!(
            r#"
            <div class="card">
                <h2>🛡️ Security Risk Assessment</h2>
                <div class="risk-overview">
                    <div class="overall-score">
                        <h3>Overall Risk Score</h3>
                        <div class="score-circle risk-{}">
                            <span class="score-value">{}/100</span>
                            <span class="score-label">{:?}</span>
                        </div>
                    </div>
                </div>
                
                {}
                
                <h4>Risk Categories</h4>
                <div class="risk-categories">
                    {}
                </div>
                
                <h4>Top Security Recommendations</h4>
                <ul class="recommendations-list">
                    {}
                </ul>
                
                <div class="compliance-status">
                    <h4>Compliance Status</h4>
                    <p><strong>Overall Compliance:</strong> {}%</p>
                </div>
            </div>
            "#,
            posture_color,
            assessment.overall_risk_score,
            assessment.security_posture,
            critical_findings_html,
            risk_categories_html,
            recommendations_html,
            assessment.compliance_status.overall_compliance_score
        )
    } else {
        String::new()
    }
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
                
                /* Risk Assessment Styles */
                .risk-overview {{ display: flex; justify-content: center; margin: 20px 0; }}
                .overall-score {{ text-align: center; }}
                .score-circle {{ width: 120px; height: 120px; border-radius: 50%; display: flex; flex-direction: column; justify-content: center; align-items: center; margin: 10px auto; }}
                .score-circle.risk-excellent {{ background: linear-gradient(135deg, #28a745, #20c997); }}
                .score-circle.risk-good {{ background: linear-gradient(135deg, #ffc107, #fd7e14); }}
                .score-circle.risk-medium {{ background: linear-gradient(135deg, #fd7e14, #dc3545); }}
                .score-circle.risk-high {{ background: linear-gradient(135deg, #dc3545, #6f42c1); }}
                .score-circle.risk-critical {{ background: linear-gradient(135deg, #6f42c1, #000); }}
                .score-value {{ font-size: 24px; font-weight: bold; color: white; }}
                .score-label {{ font-size: 12px; color: white; text-transform: uppercase; }}
                
                .findings-list {{ margin: 15px 0; }}
                .finding-item {{ background: #2d1b1b; border-left: 4px solid #dc3545; padding: 10px; margin: 8px 0; border-radius: 4px; }}
                
                .risk-categories {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin: 15px 0; }}
                .risk-category {{ background: #252525; padding: 15px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }}
                .category-name {{ font-weight: bold; }}
                .risk-score {{ padding: 5px 10px; border-radius: 15px; color: white; font-weight: bold; }}
                .risk-score.risk-good {{ background: #28a745; }}
                .risk-score.risk-medium {{ background: #ffc107; }}
                .risk-score.risk-high {{ background: #fd7e14; }}
                .risk-score.risk-critical {{ background: #dc3545; }}
                
                .recommendations-list {{ list-style: none; padding: 0; }}
                .recommendation {{ background: #252525; margin: 8px 0; padding: 12px; border-radius: 6px; border-left: 4px solid #00aaff; }}
                .recommendation.priority-immediate {{ border-left-color: #dc3545; }}
                .recommendation.priority-high {{ border-left-color: #fd7e14; }}
                .recommendation.priority-medium {{ border-left-color: #ffc107; }}
                .recommendation.priority-low {{ border-left-color: #28a745; }}
                
                .compliance-status {{ background: #1a1a2e; padding: 15px; border-radius: 8px; margin-top: 20px; }}
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
