use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub os_type: Option<String>,
    pub device_type: Option<String>,
    pub confidence: u8,      // 0-100
    pub cpe: Option<String>, // Common Platform Enumeration
    pub extra_info: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ServiceProbe {
    pub name: String,
    pub probe_string: Vec<u8>,
    pub matches: Vec<ServiceMatch>,
    pub ports: Vec<u16>,
    pub ssl_ports: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct ServiceMatch {
    pub regex: Regex,
    pub service: String,
    pub version_info: Option<String>,
    pub product_info: Option<String>,
    pub os_info: Option<String>,
    pub device_info: Option<String>,
    pub cpe: Option<String>,
}

pub struct ServiceDetector {
    probes: Vec<ServiceProbe>,
    port_services: HashMap<u16, Vec<String>>,
    #[allow(dead_code)]
    ssl_services: HashMap<u16, Vec<String>>,
}

impl ServiceDetector {
    pub fn new() -> Self {
        let mut detector = Self {
            probes: Vec::new(),
            port_services: HashMap::new(),
            ssl_services: HashMap::new(),
        };

        detector.load_builtin_probes();
        detector.load_port_mappings();
        detector
    }

    pub async fn detect_service(
        &self,
        target: IpAddr,
        port: u16,
        banner: Option<&str>,
    ) -> ServiceInfo {
        let mut service_info = self.detect_by_port(port);

        if let Some(banner_text) = banner {
            if let Some(enhanced_info) = self.analyze_banner(port, banner_text) {
                service_info = self.merge_service_info(service_info, enhanced_info);
            }
        }

        if service_info.confidence < 70 {
            if let Some(probed_info) = self.active_probe(target, port).await {
                service_info = self.merge_service_info(service_info, probed_info);
            }
        }

        service_info
    }

    fn detect_by_port(&self, port: u16) -> ServiceInfo {
        let service_name = self
            .port_services
            .get(&port)
            .and_then(|services| services.first())
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        ServiceInfo {
            name: service_name,
            version: None,
            product: None,
            os_type: None,
            device_type: None,
            confidence: if port <= 1024 { 60 } else { 30 }, // Well-known ports get higher confidence
            cpe: None,
            extra_info: None,
        }
    }

    /// Analyze a banner string to identify the service
    ///
    /// # Note
    /// This method is primarily intended for internal use and testing.
    #[doc(hidden)]
    pub fn analyze_banner(&self, port: u16, banner: &str) -> Option<ServiceInfo> {
        for probe in &self.probes {
            if probe.ports.contains(&port) || probe.ports.is_empty() {
                for service_match in &probe.matches {
                    if let Some(captures) = service_match.regex.captures(banner) {
                        return Some(self.extract_service_info(&service_match, &captures, banner));
                    }
                }
            }
        }
        None
    }

    async fn active_probe(&self, target: IpAddr, port: u16) -> Option<ServiceInfo> {
        for probe in &self.probes {
            if probe.ports.contains(&port) || probe.ports.is_empty() {
                if let Some(response) = self.send_probe(target, port, &probe).await {
                    for service_match in &probe.matches {
                        if let Some(captures) = service_match.regex.captures(&response) {
                            return Some(self.extract_service_info(
                                &service_match,
                                &captures,
                                &response,
                            ));
                        }
                    }
                }
            }
        }
        None
    }

    async fn send_probe(&self, target: IpAddr, port: u16, probe: &ServiceProbe) -> Option<String> {
        let socket_addr = std::net::SocketAddr::new(target, port);

        match timeout(Duration::from_secs(5), TcpStream::connect(socket_addr)).await {
            Ok(Ok(mut stream)) => {
                if !probe.probe_string.is_empty() {
                    if stream.write_all(&probe.probe_string).await.is_err() {
                        return None;
                    }
                }

                let mut buffer = [0; 4096];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => Some(String::from_utf8_lossy(&buffer[..n]).to_string()),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn extract_service_info(
        &self,
        service_match: &ServiceMatch,
        captures: &regex::Captures,
        response: &str,
    ) -> ServiceInfo {
        let mut info = ServiceInfo {
            name: service_match.service.clone(),
            version: None,
            product: None,
            os_type: None,
            device_type: None,
            confidence: 85,
            cpe: service_match.cpe.clone(),
            extra_info: None,
        };

        if let Some(version_template) = &service_match.version_info {
            info.version = Some(self.substitute_captures(version_template, captures));
        }

        if let Some(product_template) = &service_match.product_info {
            info.product = Some(self.substitute_captures(product_template, captures));
        }

        if let Some(os_template) = &service_match.os_info {
            info.os_type = Some(self.substitute_captures(os_template, captures));
        }

        if let Some(device_template) = &service_match.device_info {
            info.device_type = Some(self.substitute_captures(device_template, captures));
        }

        if response.len() > 100 {
            info.extra_info = Some(format!("Response: {}...", &response[..100]));
        } else {
            info.extra_info = Some(format!("Response: {}", response));
        }

        info
    }

    fn substitute_captures(&self, template: &str, captures: &regex::Captures) -> String {
        let mut result = template.to_string();

        for i in 1..captures.len() {
            if let Some(capture) = captures.get(i) {
                let placeholder = format!("${}", i);
                result = result.replace(&placeholder, capture.as_str());
            }
        }

        result
    }

    fn merge_service_info(&self, mut base: ServiceInfo, enhancement: ServiceInfo) -> ServiceInfo {
        if enhancement.confidence > base.confidence {
            base.name = enhancement.name;
            base.confidence = enhancement.confidence;
        }

        if enhancement.version.is_some() && base.version.is_none() {
            base.version = enhancement.version;
        }
        if enhancement.product.is_some() && base.product.is_none() {
            base.product = enhancement.product;
        }
        if enhancement.os_type.is_some() && base.os_type.is_none() {
            base.os_type = enhancement.os_type;
        }
        if enhancement.device_type.is_some() && base.device_type.is_none() {
            base.device_type = enhancement.device_type;
        }
        if enhancement.cpe.is_some() && base.cpe.is_none() {
            base.cpe = enhancement.cpe;
        }
        if enhancement.extra_info.is_some() {
            base.extra_info = enhancement.extra_info;
        }

        base
    }

    fn load_builtin_probes(&mut self) {
        // HTTP probe
        self.probes.push(ServiceProbe {
    name: "HTTP".to_string(),
    probe_string: b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: ServiceDetector/1.0\r\nConnection: close\r\n\r\n".to_vec(),
    matches: vec![
        // More specific patterns first
        ServiceMatch {
            regex: Regex::new(r"Apache/(\d+\.\d+\.\d+)").unwrap(),
            service: "http".to_string(),
            version_info: Some("$1".to_string()),
            product_info: Some("Apache httpd".to_string()),
            os_info: None,
            device_info: None,
            cpe: Some("cpe:/a:apache:http_server:$1".to_string()),
        },
        ServiceMatch {
            regex: Regex::new(r"nginx/(\d+\.\d+\.\d+)").unwrap(),
            service: "http".to_string(),
            version_info: Some("$1".to_string()),
            product_info: Some("nginx".to_string()),
            os_info: None,
            device_info: None,
            cpe: Some("cpe:/a:nginx:nginx:$1".to_string()),
        },
        ServiceMatch {
            regex: Regex::new(r"Microsoft-IIS/(\d+\.\d+)").unwrap(),
            service: "http".to_string(),
            version_info: Some("$1".to_string()),
            product_info: Some("Microsoft IIS httpd".to_string()),
            os_info: Some("Windows".to_string()),
            device_info: None,
            cpe: Some("cpe:/a:microsoft:iis:$1".to_string()),
        },
        // General pattern last
        ServiceMatch {
            regex: Regex::new(r"Server:\s*([^\r\n]+)").unwrap(),
            service: "http".to_string(),
            version_info: None,
            product_info: Some("$1".to_string()),
            os_info: None,
            device_info: None,
            cpe: None,
        },
    ],
    ports: vec![80, 8000, 8080, 8081, 8443, 8888, 9000, 9080, 9090],
    ssl_ports: vec![443, 8443, 9443],
});

        // SSH probe
        self.probes.push(ServiceProbe {
            name: "SSH".to_string(),
            probe_string: Vec::new(), // SSH sends banner on connection
            matches: vec![
                ServiceMatch {
                    regex: Regex::new(r"SSH-(\d+\.\d+)-OpenSSH_(\d+\.\d+)").unwrap(),
                    service: "ssh".to_string(),
                    version_info: Some("$2".to_string()),
                    product_info: Some("OpenSSH".to_string()),
                    os_info: None,
                    device_info: None,
                    cpe: Some("cpe:/a:openbsd:openssh:$2".to_string()),
                },
                ServiceMatch {
                    regex: Regex::new(r"SSH-(\d+\.\d+)-([^\s\r\n]+)").unwrap(),
                    service: "ssh".to_string(),
                    version_info: Some("$1".to_string()),
                    product_info: Some("$2".to_string()),
                    os_info: None,
                    device_info: None,
                    cpe: None,
                },
            ],
            ports: vec![22, 2222],
            ssl_ports: Vec::new(),
        });

        // FTP probe
        self.probes.push(ServiceProbe {
            name: "FTP".to_string(),
            probe_string: Vec::new(), // FTP sends banner on connection
            matches: vec![
                ServiceMatch {
                    regex: Regex::new(r"220.*vsftpd (\d+\.\d+\.\d+)").unwrap(),
                    service: "ftp".to_string(),
                    version_info: Some("$1".to_string()),
                    product_info: Some("vsftpd".to_string()),
                    os_info: None,
                    device_info: None,
                    cpe: Some("cpe:/a:beasts:vsftpd:$1".to_string()),
                },
                ServiceMatch {
                    regex: Regex::new(r"220.*ProFTPD (\d+\.\d+\.\d+)").unwrap(),
                    service: "ftp".to_string(),
                    version_info: Some("$1".to_string()),
                    product_info: Some("ProFTPD".to_string()),
                    os_info: None,
                    device_info: None,
                    cpe: Some("cpe:/a:proftpd:proftpd:$1".to_string()),
                },
                ServiceMatch {
                    regex: Regex::new(r"220.*Microsoft FTP Service").unwrap(),
                    service: "ftp".to_string(),
                    version_info: None,
                    product_info: Some("Microsoft FTP Service".to_string()),
                    os_info: Some("Windows".to_string()),
                    device_info: None,
                    cpe: Some("cpe:/a:microsoft:ftp_service".to_string()),
                },
            ],
            ports: vec![21, 990],
            ssl_ports: vec![990],
        });

        // SMTP probe
        self.probes.push(ServiceProbe {
            name: "SMTP".to_string(),
            probe_string: b"EHLO scanner.local\r\n".to_vec(),
            matches: vec![
                ServiceMatch {
                    regex: Regex::new(r"220.*Postfix").unwrap(),
                    service: "smtp".to_string(),
                    version_info: None,
                    product_info: Some("Postfix smtpd".to_string()),
                    os_info: None,
                    device_info: None,
                    cpe: Some("cpe:/a:postfix:postfix".to_string()),
                },
                ServiceMatch {
                    regex: Regex::new(r"220.*Sendmail (\d+\.\d+\.\d+)").unwrap(),
                    service: "smtp".to_string(),
                    version_info: Some("$1".to_string()),
                    product_info: Some("Sendmail smtpd".to_string()),
                    os_info: None,
                    device_info: None,
                    cpe: Some("cpe:/a:sendmail:sendmail:$1".to_string()),
                },
                ServiceMatch {
                    regex: Regex::new(r"220.*Microsoft ESMTP MAIL Service").unwrap(),
                    service: "smtp".to_string(),
                    version_info: None,
                    product_info: Some("Microsoft ESMTP".to_string()),
                    os_info: Some("Windows".to_string()),
                    device_info: None,
                    cpe: Some("cpe:/a:microsoft:exchange_server".to_string()),
                },
            ],
            ports: vec![25, 465, 587],
            ssl_ports: vec![465, 587],
        });

        // DNS probe
        self.probes.push(ServiceProbe {
            name: "DNS".to_string(),
            probe_string: vec![
                // DNS query for version.bind CHAOS TXT
                0x00, 0x1e, // Length
                0x12, 0x34, // Transaction ID
                0x01, 0x00, // Standard query
                0x00, 0x01, // Questions: 1
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer, Authority, Additional: 0
                0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
                0x04, 0x62, 0x69, 0x6e, 0x64, // "bind"
                0x00, // End of name
                0x00, 0x10, // Type: TXT
                0x00, 0x03, // Class: CHAOS
            ],
            matches: vec![ServiceMatch {
                regex: Regex::new(r".*").unwrap(), // Generic DNS response
                service: "dns".to_string(),
                version_info: None,
                product_info: Some("DNS Server".to_string()),
                os_info: None,
                device_info: None,
                cpe: None,
            }],
            ports: vec![53],
            ssl_ports: vec![853],
        });

        // MySQL probe
        self.probes.push(ServiceProbe {
            name: "MySQL".to_string(),
            probe_string: Vec::new(), // MySQL sends handshake on connection
            matches: vec![ServiceMatch {
                regex: Regex::new(r".*(\d+\.\d+\.\d+).*").unwrap(),
                service: "mysql".to_string(),
                version_info: Some("$1".to_string()),
                product_info: Some("MySQL".to_string()),
                os_info: None,
                device_info: None,
                cpe: Some("cpe:/a:mysql:mysql:$1".to_string()),
            }],
            ports: vec![3306],
            ssl_ports: Vec::new(),
        });
    }

    fn load_port_mappings(&mut self) {
        let port_mappings = [
            // Web services
            (80, vec!["http"]),
            (443, vec!["https", "http"]),
            (8000, vec!["http-alt"]),
            (8080, vec!["http-proxy", "http"]),
            (8443, vec!["https-alt", "https"]),
            (8888, vec!["http-alt"]),
            (9000, vec!["http-alt"]),
            // Remote access
            (22, vec!["ssh"]),
            (23, vec!["telnet"]),
            (3389, vec!["ms-wbt-server", "rdp"]),
            (5900, vec!["vnc"]),
            // Mail services
            (25, vec!["smtp"]),
            (110, vec!["pop3"]),
            (143, vec!["imap"]),
            (465, vec!["smtps"]),
            (587, vec!["submission"]),
            (993, vec!["imaps"]),
            (995, vec!["pop3s"]),
            // File transfer
            (20, vec!["ftp-data"]),
            (21, vec!["ftp"]),
            (69, vec!["tftp"]),
            (990, vec!["ftps"]),
            // Databases
            (1433, vec!["ms-sql-s"]),
            (1521, vec!["oracle"]),
            (3306, vec!["mysql"]),
            (5432, vec!["postgresql"]),
            (6379, vec!["redis"]),
            (27017, vec!["mongodb"]),
            // Directory services
            (389, vec!["ldap"]),
            (636, vec!["ldaps"]),
            // Network services
            (53, vec!["domain", "dns"]),
            (123, vec!["ntp"]),
            (161, vec!["snmp"]),
            (162, vec!["snmptrap"]),
            // File sharing
            (135, vec!["msrpc"]),
            (139, vec!["netbios-ssn"]),
            (445, vec!["microsoft-ds", "smb"]),
            (2049, vec!["nfs"]),
            // Other services
            (79, vec!["finger"]),
            (113, vec!["ident"]),
            (194, vec!["irc"]),
            (515, vec!["printer"]),
            (631, vec!["ipp"]),
            (1080, vec!["socks"]),
        ];

        for (port, services) in port_mappings {
            self.port_services
                .insert(port, services.iter().map(|s| s.to_string()).collect());
        }
    }
}

pub fn format_service_info(service: &ServiceInfo) -> String {
    let mut parts = vec![service.name.clone()];

    if let Some(version) = &service.version {
        if let Some(product) = &service.product {
            parts.push(format!("{} {}", product, version));
        } else {
            parts.push(version.clone());
        }
    } else if let Some(product) = &service.product {
        parts.push(product.clone());
    }

    if let Some(os) = &service.os_type {
        parts.push(format!("({})", os));
    }

    if service.confidence < 70 {
        parts.push(format!("({:.0}% confidence)", service.confidence));
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_detection_creation() {
        let detector = ServiceDetector::new();
        assert!(!detector.probes.is_empty());
        assert!(!detector.port_services.is_empty());
    }

    #[test]
    fn test_port_based_detection() {
        let detector = ServiceDetector::new();
        let service = detector.detect_by_port(80);
        assert_eq!(service.name, "http");
        assert!(service.confidence > 0);
    }

    #[test]
    fn test_banner_analysis() {
        let detector = ServiceDetector::new();
        let banner = "Server: Apache/2.4.41 (Ubuntu)";
        let service = detector.analyze_banner(80, banner);
        assert!(service.is_some());
        let service = service.unwrap();
        assert_eq!(service.name, "http");
        assert_eq!(service.product.as_deref(), Some("Apache httpd"));
        assert_eq!(service.version.as_deref(), Some("2.4.41"));
    }

    #[test]
    fn test_service_info_formatting() {
        let service = ServiceInfo {
            name: "http".to_string(),
            version: Some("2.4.41".to_string()),
            product: Some("Apache httpd".to_string()),
            os_type: Some("Linux".to_string()),
            device_type: None,
            confidence: 90,
            cpe: Some("cpe:/a:apache:http_server:2.4.41".to_string()),
            extra_info: None,
        };

        let formatted = format_service_info(&service);
        assert!(formatted.contains("http"));
        assert!(formatted.contains("Apache httpd"));
        assert!(formatted.contains("2.4.41"));
        assert!(formatted.contains("Linux"));
    }
}
