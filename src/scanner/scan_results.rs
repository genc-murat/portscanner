use super::config::ScanConfig;
use crate::os_fingerprinting::OSFingerprint;
use crate::service_detection::ServiceInfo;
use crate::ssl::SslAnalysisResult;
use serde::{Deserialize, Serialize};

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

impl ScanResult {
    pub fn new_tcp(
        port: u16,
        is_open: bool,
        service: Option<String>,
        service_info: Option<ServiceInfo>,
        banner: Option<String>,
        response_time: u64,
        scan_type: &str,
    ) -> Self {
        Self {
            port,
            is_open,
            service,
            service_info,
            banner,
            response_time,
            scan_type: scan_type.to_string(),
            protocol: "TCP".to_string(),
            udp_state: None,
        }
    }

    pub fn new_udp(
        port: u16,
        is_open: bool,
        service: Option<String>,
        service_info: Option<ServiceInfo>,
        banner: Option<String>,
        response_time: u64,
        udp_state: &str,
    ) -> Self {
        Self {
            port,
            is_open,
            service,
            service_info,
            banner,
            response_time,
            scan_type: "UDP".to_string(),
            protocol: "UDP".to_string(),
            udp_state: Some(udp_state.to_string()),
        }
    }
}

pub fn create_scan_summary(
    results: &[ScanResult],
    ssl_analysis: &[SslAnalysisResult],
    scan_time: f64,
    config: &ScanConfig,
) -> ScanSummary {
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
        scan_method: config.get_scan_method_name().to_string(),
        protocols_scanned: config.get_protocols_scanned(),
        ssl_services_found: ssl_analysis.iter().filter(|s| s.is_ssl_enabled).count(),
    }
}
