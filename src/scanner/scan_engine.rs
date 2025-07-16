use super::config::{ScanConfig, ScanType};
use super::scan_results::ScanResult;
use super::services;
use super::utils;
use crate::service_detection::ServiceDetector;
use crate::stealth::{
    utils as stealth_utils, PortState, ScanConfig as StealthScanConfig, ScanTechnique,
    StealthScanResult, StealthScanner,
};
use crate::udp::{UdpPortState, UdpScanResult, UdpScanner};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub async fn start_tcp_scans(
    config: &ScanConfig,
    semaphore: &Arc<tokio::sync::Semaphore>,
    service_detector: &Arc<ServiceDetector>,
) -> Vec<tokio::task::JoinHandle<ScanResult>> {
    let mut handles = Vec::new();

    match config.scan_type {
        ScanType::TcpConnect | ScanType::Mixed => {
            for &port in &config.ports {
                let sem = semaphore.clone();
                let target = config.target;
                let timeout_duration = Duration::from_millis(config.timeout_ms);
                let grab_banner = config.grab_banner;
                let service_detection = config.service_detection;
                let service_detector = service_detector.clone();

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
            // Create stealth configuration
            let stealth_config = StealthScanConfig {
                timeout: Duration::from_millis(config.timeout_ms),
                technique: ScanTechnique::StealthSyn,
                retries: 2,
                randomize_order: false,
                delay_between_probes: None,
                source_port_range: None,
            };

            let stealth_scanner = match StealthScanner::new(config.target, stealth_config) {
                Ok(scanner) => Arc::new(scanner),
                Err(e) => {
                    eprintln!("Failed to create stealth scanner: {}", e);
                    return handles;
                }
            };

            for &port in &config.ports {
                let sem = semaphore.clone();
                let scanner = stealth_scanner.clone();
                let service_detection = config.service_detection;
                let service_detector = service_detector.clone();
                let target = config.target;

                let handle = tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    let stealth_result = scanner.scan_port(port).await;
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

pub async fn start_udp_scans(
    config: &ScanConfig,
    semaphore: &Arc<tokio::sync::Semaphore>,
    udp_scanner: &Arc<UdpScanner>,
    service_detector: &Arc<ServiceDetector>,
) -> Vec<tokio::task::JoinHandle<ScanResult>> {
    let mut handles = Vec::new();

    for &port in &config.ports {
        let sem = semaphore.clone();
        let udp_scanner = udp_scanner.clone();
        let service_detection = config.service_detection;
        let service_detector = service_detector.clone();
        let target = config.target;

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let udp_result = udp_scanner.scan_port(port).await;
            convert_udp_result(udp_result, target, service_detection, service_detector).await
        });

        handles.push(handle);
    }

    handles
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
                utils::grab_banner_from_stream(&mut stream, port, timeout_duration).await
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
        (services::detect_basic_service(port), None)
    };

    ScanResult::new_tcp(
        port,
        is_open,
        service,
        service_info,
        banner,
        response_time.as_millis() as u64,
        "TCP",
    )
}

async fn convert_stealth_result(
    stealth_result: Result<StealthScanResult, crate::stealth::types::StealthScanError>,
    target: IpAddr,
    service_detection: bool,
    service_detector: Arc<ServiceDetector>,
) -> ScanResult {
    match stealth_result {
        Ok(result) => {
            let (is_open, service) = match result.state {
                PortState::Open => (true, services::detect_basic_service(result.port)),
                PortState::Closed => (false, Some("closed".to_string())),
                PortState::Filtered => (false, Some("filtered".to_string())),
                PortState::Unknown => (false, Some("unknown".to_string())),
            };

            let service_info = if is_open && service_detection {
                Some(
                    service_detector
                        .detect_service(target, result.port, None)
                        .await,
                )
            } else {
                None
            };

            ScanResult::new_tcp(
                result.port,
                is_open,
                service,
                service_info,
                None,
                result.response_time.as_millis() as u64,
                "SYN",
            )
        }
        Err(e) => {
            // Create a default error result for failed scans
            eprintln!("Stealth scan error: {}", e);
            ScanResult::new_tcp(
                0, // Port will be set by caller if needed
                false,
                Some("error".to_string()),
                None,
                None,
                0,
                "SYN",
            )
        }
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

    let service = services::detect_basic_udp_service(udp_result.port);

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

    ScanResult::new_udp(
        udp_result.port,
        is_open,
        service,
        service_info,
        banner,
        udp_result.response_time,
        udp_state_str,
    )
}

/// Helper function to create a stealth scanner with appropriate fallback
pub async fn create_stealth_scanner_with_fallback(
    target: IpAddr,
    timeout_ms: u64,
    prefer_stealth: bool,
) -> Result<StealthScanner, String> {
    let technique = if prefer_stealth && stealth_utils::is_platform_supported() {
        match stealth_utils::validate_privileges() {
            Ok(_) => ScanTechnique::StealthSyn,
            Err(_) => {
                eprintln!("Warning: Root privileges required for stealth SYN scan, falling back to TCP connect");
                ScanTechnique::TcpConnect
            }
        }
    } else {
        ScanTechnique::TcpConnect
    };

    let config = StealthScanConfig {
        timeout: Duration::from_millis(timeout_ms),
        technique,
        retries: 2,
        randomize_order: false,
        delay_between_probes: None,
        source_port_range: None,
    };

    StealthScanner::new(target, config)
        .map_err(|e| format!("Failed to create stealth scanner: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_tcp_scan_port() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let service_detector = Arc::new(ServiceDetector::new());

        let result = tcp_scan_port(
            target,
            12345, // Likely closed port
            Duration::from_millis(1000),
            false,
            false,
            service_detector,
        )
        .await;

        assert_eq!(result.port, 12345);
        assert!(!result.is_open); // Should be closed
    }

    #[tokio::test]
    async fn test_stealth_scanner_creation() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let result = create_stealth_scanner_with_fallback(target, 3000, true).await;

        // Should succeed with either stealth or TCP connect fallback
        assert!(result.is_ok());

        let scanner = result.unwrap();
        let technique = scanner.get_technique();

        // Should be either TcpConnect or StealthSyn depending on platform/privileges
        assert!(matches!(
            technique,
            ScanTechnique::TcpConnect | ScanTechnique::StealthSyn
        ));
    }

    #[test]
    fn test_stealth_config_creation() {
        let config = StealthScanConfig {
            timeout: Duration::from_millis(3000),
            technique: ScanTechnique::TcpConnect,
            retries: 1,
            randomize_order: false,
            delay_between_probes: None,
            source_port_range: None,
        };

        assert_eq!(config.timeout, Duration::from_millis(3000));
        assert_eq!(config.technique, ScanTechnique::TcpConnect);
        assert_eq!(config.retries, 1);
    }
}
