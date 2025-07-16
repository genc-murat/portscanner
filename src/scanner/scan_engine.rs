use super::config::{ScanConfig, ScanType};
use super::scan_results::ScanResult;
use super::services;
use super::utils;
use crate::service_detection::ServiceDetector;
use crate::stealth::{PortState, StealthScanResult, StealthScanner};
use crate::udp::{UdpPortState, UdpScanResult, UdpScanner};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

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
            let stealth_scanner = match StealthScanner::new(config.target, config.timeout_ms) {
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
    stealth_result: StealthScanResult,
    target: IpAddr,
    service_detection: bool,
    service_detector: Arc<ServiceDetector>,
) -> ScanResult {
    let (is_open, service) = match stealth_result.state {
        PortState::Open => (true, services::detect_basic_service(stealth_result.port)),
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

    ScanResult::new_tcp(
        stealth_result.port,
        is_open,
        service,
        service_info,
        None,
        stealth_result.response_time,
        "SYN",
    )
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
