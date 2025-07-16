use crate::scanner::utils;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    TcpConnect,
    StealthSyn,
    UdpScan,
    Mixed, // Both TCP and UDP
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Both,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target: IpAddr,
    pub target_hostname: String,
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub json_output: bool,
    pub html_output: Option<String>,
    pub grab_banner: bool,
    pub scan_type: ScanType,
    pub protocol: Protocol,
    pub service_detection: bool,
    pub os_detection: bool,
    pub ssl_analysis: bool,
}

impl ScanConfig {
    pub fn from_args(args: crate::Args) -> Result<Self, String> {
        let target = utils::resolve_hostname(&args.target)?;
        let ports = crate::port_parser::parse_ports(&args.ports)?;

        // Determine protocol based on args
        let protocol = match args.protocol.as_deref() {
            Some("tcp") => Protocol::Tcp,
            Some("udp") => Protocol::Udp,
            Some("both") | Some("all") => Protocol::Both,
            _ => Protocol::Tcp, // Default to TCP
        };

        let scan_type = Self::determine_scan_type(&protocol, args.stealth, &args.scan_type);

        Ok(Self {
            target,
            target_hostname: args.target.clone(),
            ports,
            concurrency: args.concurrency,
            timeout_ms: args.timeout,
            json_output: args.json,
            html_output: args.html_output,
            grab_banner: args.banner && !args.stealth,
            scan_type,
            protocol,
            service_detection: args.service_detection,
            os_detection: args.os_detection,
            ssl_analysis: args.ssl_analysis,
        })
    }

    fn determine_scan_type(protocol: &Protocol, stealth: bool, scan_type: &str) -> ScanType {
        match (protocol, stealth, scan_type) {
            (Protocol::Udp, _, _) => ScanType::UdpScan,
            (Protocol::Both, _, _) => ScanType::Mixed,
            (_, true, _) | (_, _, "syn") => ScanType::StealthSyn,
            (_, _, "tcp") => ScanType::TcpConnect,
            _ => {
                // Auto mode: use stealth if available, otherwise TCP
                if cfg!(target_os = "linux") && utils::is_root() {
                    ScanType::StealthSyn
                } else {
                    ScanType::TcpConnect
                }
            }
        }
    }

    pub fn get_scan_method_name(&self) -> &'static str {
        match (&self.scan_type, &self.protocol) {
            (ScanType::UdpScan, _) => "UDP Scan",
            (ScanType::Mixed, _) => "Mixed TCP/UDP Scan",
            (ScanType::TcpConnect, _) => "TCP Connect",
            (ScanType::StealthSyn, _) => "Stealth SYN",
        }
    }

    pub fn get_protocol_info(&self) -> &'static str {
        match self.protocol {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Both => "TCP, UDP",
        }
    }

    pub fn get_total_ports(&self) -> usize {
        match self.protocol {
            Protocol::Both => self.ports.len() * 2,
            _ => self.ports.len(),
        }
    }

    pub fn get_protocols_scanned(&self) -> Vec<String> {
        match self.protocol {
            Protocol::Tcp => vec!["TCP".to_string()],
            Protocol::Udp => vec!["UDP".to_string()],
            Protocol::Both => vec!["TCP".to_string(), "UDP".to_string()],
        }
    }
}
