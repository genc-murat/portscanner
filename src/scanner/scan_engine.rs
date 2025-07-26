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
use futures::stream::{self, StreamExt};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

// Batch processing configuration
const DEFAULT_BATCH_SIZE: usize = 50;
const DEFAULT_CONCURRENT_BATCHES: usize = 4;

#[derive(Debug, Clone)]
pub struct BatchConfig {
    pub batch_size: usize,
    pub concurrent_batches: usize,
    pub enable_adaptive_batching: bool,
    pub max_retries: u8, // Changed from u32 to u8 for consistency
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
            concurrent_batches: DEFAULT_CONCURRENT_BATCHES,
            enable_adaptive_batching: true,
            max_retries: 2,
        }
    }
}

// Adaptive batch manager that adjusts batch sizes based on performance
pub struct AdaptiveBatchManager {
    current_batch_size: usize,
    min_batch_size: usize,
    max_batch_size: usize,
    success_rate_threshold: f64,
    recent_performance: VecDeque<f64>,
    max_history: usize,
}

impl AdaptiveBatchManager {
    pub fn new() -> Self {
        Self {
            current_batch_size: DEFAULT_BATCH_SIZE,
            min_batch_size: 10,
            max_batch_size: 200,
            success_rate_threshold: 0.85,
            recent_performance: VecDeque::new(),
            max_history: 10,
        }
    }

    pub fn get_batch_size(&self) -> usize {
        self.current_batch_size
    }

    pub fn update_performance(&mut self, success_rate: f64, avg_response_time: f64) {
        self.recent_performance.push_back(success_rate);
        if self.recent_performance.len() > self.max_history {
            self.recent_performance.pop_front();
        }

        let avg_success_rate =
            self.recent_performance.iter().sum::<f64>() / self.recent_performance.len() as f64;

        // Adjust batch size based on performance
        if avg_success_rate > self.success_rate_threshold && avg_response_time < 0.5 {
            // Performance is good, try increasing batch size
            self.current_batch_size = (self.current_batch_size + 10).min(self.max_batch_size);
        } else if avg_success_rate < 0.7 || avg_response_time > 2.0 {
            // Performance is poor, decrease batch size
            self.current_batch_size =
                (self.current_batch_size.saturating_sub(10)).max(self.min_batch_size);
        }
    }
}

// Optimized TCP scanning with batch processing
pub async fn start_tcp_scans_optimized(
    config: &ScanConfig,
    semaphore: &Arc<tokio::sync::Semaphore>,
    service_detector: &Arc<ServiceDetector>,
    batch_config: Option<BatchConfig>,
) -> Vec<tokio::task::JoinHandle<Vec<ScanResult>>> {
    let batch_cfg = batch_config.unwrap_or_default();

    match config.scan_type {
        ScanType::TcpConnect | ScanType::Mixed => {
            tcp_batch_scan_optimized(config, semaphore, service_detector, &batch_cfg).await
        }
        ScanType::StealthSyn => {
            stealth_batch_scan_optimized(config, semaphore, service_detector, &batch_cfg).await
        }
        _ => Vec::new(),
    }
}

async fn tcp_batch_scan_optimized(
    config: &ScanConfig,
    semaphore: &Arc<tokio::sync::Semaphore>,
    service_detector: &Arc<ServiceDetector>,
    batch_config: &BatchConfig,
) -> Vec<tokio::task::JoinHandle<Vec<ScanResult>>> {
    let mut handles = Vec::new();
    let ports = &config.ports;

    // Split ports into batches
    let batches = create_static_batches(ports, batch_config.batch_size);

    // Process batches with controlled concurrency
    let batch_semaphore = Arc::new(tokio::sync::Semaphore::new(batch_config.concurrent_batches));

    for (batch_id, batch_ports) in batches.into_iter().enumerate() {
        let batch_sem = batch_semaphore.clone();
        let scan_sem = semaphore.clone();
        let target = config.target;
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        let grab_banner = config.grab_banner;
        let service_detection = config.service_detection;
        let service_detector = service_detector.clone();
        let max_retries = batch_config.max_retries;

        let handle = tokio::spawn(async move {
            let _batch_permit = batch_sem.acquire().await.unwrap();

            tcp_scan_batch_with_pool(
                target,
                batch_ports,
                timeout_duration,
                grab_banner,
                service_detection,
                service_detector,
                scan_sem,
                max_retries,
                batch_id,
            )
            .await
        });

        handles.push(handle);
    }

    handles
}

async fn tcp_scan_batch_with_pool(
    target: IpAddr,
    ports: Vec<u16>,
    timeout_duration: Duration,
    grab_banner: bool,
    service_detection: bool,
    service_detector: Arc<ServiceDetector>,
    semaphore: Arc<tokio::sync::Semaphore>,
    max_retries: u8, // Changed from u32 to u8
    batch_id: usize,
) -> Vec<ScanResult> {
    let batch_start = std::time::Instant::now();

    // Use stream processing for better memory efficiency and controlled concurrency
    let results: Vec<ScanResult> = stream::iter(ports)
        .map(|port| {
            let sem = semaphore.clone();
            let timeout_duration = timeout_duration;
            let grab_banner = grab_banner;
            let service_detection = service_detection;
            let service_detector = service_detector.clone();

            async move {
                let _permit = sem.acquire().await.unwrap();

                // Retry logic for individual ports
                for attempt in 0..=max_retries {
                    match tcp_scan_port_optimized(
                        target,
                        port,
                        timeout_duration,
                        grab_banner,
                        service_detection,
                        service_detector.clone(),
                    )
                    .await
                    {
                        Ok(result) => return result,
                        Err(_) if attempt < max_retries => {
                            // Small delay before retry
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            continue;
                        }
                        Err(_) => {
                            // Return failed result after all retries
                            return ScanResult::new_tcp(
                                port,
                                false,
                                None,
                                None,
                                None,
                                timeout_duration.as_millis() as u64,
                                "TCP",
                            );
                        }
                    }
                }

                // Fallback (should not reach here)
                ScanResult::new_tcp(
                    port,
                    false,
                    None,
                    None,
                    None,
                    timeout_duration.as_millis() as u64,
                    "TCP",
                )
            }
        })
        // Buffer unordered allows processing multiple ports concurrently within the batch
        .buffer_unordered(50) // Tune this based on system capabilities
        .collect()
        .await;

    let batch_duration = batch_start.elapsed();
    println!(
        "🔄 Batch {} completed: {} ports in {:.2}s",
        batch_id,
        results.len(),
        batch_duration.as_secs_f64()
    );

    results
}

async fn tcp_scan_port_optimized(
    target: IpAddr,
    port: u16,
    timeout_duration: Duration,
    grab_banner: bool,
    service_detection: bool,
    service_detector: Arc<ServiceDetector>,
) -> Result<ScanResult, std::io::Error> {
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
        Ok(Err(e)) => return Err(e),
        Err(_) => (false, None), // Timeout
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

    Ok(ScanResult::new_tcp(
        port,
        is_open,
        service,
        service_info,
        banner,
        response_time.as_millis() as u64,
        "TCP",
    ))
}

async fn stealth_batch_scan_optimized(
    config: &ScanConfig,
    semaphore: &Arc<tokio::sync::Semaphore>,
    service_detector: &Arc<ServiceDetector>,
    batch_config: &BatchConfig,
) -> Vec<tokio::task::JoinHandle<Vec<ScanResult>>> {
    let mut handles = Vec::new();

    // Create stealth configuration
    let stealth_config = StealthScanConfig {
        timeout: Duration::from_millis(config.timeout_ms),
        technique: ScanTechnique::StealthSyn,
        retries: batch_config.max_retries, // Now both are u8
        randomize_order: false,
        delay_between_probes: Some(Duration::from_millis(1)), // Minimal delay for batch processing
        source_port_range: None,
    };

    let stealth_scanner = match StealthScanner::new(config.target, stealth_config) {
        Ok(scanner) => Arc::new(scanner),
        Err(e) => {
            eprintln!("Failed to create stealth scanner: {}", e);
            return handles;
        }
    };

    // Split ports into batches
    let batches = create_static_batches(&config.ports, batch_config.batch_size);
    let batch_semaphore = Arc::new(tokio::sync::Semaphore::new(batch_config.concurrent_batches));

    for (batch_id, batch_ports) in batches.into_iter().enumerate() {
        let batch_sem = batch_semaphore.clone();
        let scanner = stealth_scanner.clone();
        let service_detection = config.service_detection;
        let service_detector = service_detector.clone();
        let target = config.target;

        let handle = tokio::spawn(async move {
            let _batch_permit = batch_sem.acquire().await.unwrap();

            stealth_scan_batch(
                scanner,
                batch_ports,
                target,
                service_detection,
                service_detector,
                batch_id,
            )
            .await
        });

        handles.push(handle);
    }

    handles
}

async fn stealth_scan_batch(
    scanner: Arc<StealthScanner>,
    ports: Vec<u16>,
    target: IpAddr,
    service_detection: bool,
    service_detector: Arc<ServiceDetector>,
    batch_id: usize,
) -> Vec<ScanResult> {
    let batch_start = std::time::Instant::now();

    let results: Vec<ScanResult> = stream::iter(ports)
        .map(|port| {
            let scanner = scanner.clone();
            let service_detection = service_detection;
            let service_detector = service_detector.clone();

            async move {
                let stealth_result = scanner.scan_port(port).await;
                convert_stealth_result(stealth_result, target, service_detection, service_detector)
                    .await
            }
        })
        .buffer_unordered(30) // Controlled concurrency for stealth scans
        .collect()
        .await;

    let batch_duration = batch_start.elapsed();
    println!(
        "🔄 Stealth batch {} completed: {} ports in {:.2}s",
        batch_id,
        results.len(),
        batch_duration.as_secs_f64()
    );

    results
}

// Optimized UDP scanning with batch processing
pub async fn start_udp_scans_optimized(
    config: &ScanConfig,
    semaphore: &Arc<tokio::sync::Semaphore>,
    udp_scanner: &Arc<UdpScanner>,
    service_detector: &Arc<ServiceDetector>,
    batch_config: Option<BatchConfig>,
) -> Vec<tokio::task::JoinHandle<Vec<ScanResult>>> {
    let batch_cfg = batch_config.unwrap_or_default();
    let mut handles = Vec::new();

    // Split ports into batches
    let batches = create_static_batches(&config.ports, batch_cfg.batch_size);
    let batch_semaphore = Arc::new(tokio::sync::Semaphore::new(batch_cfg.concurrent_batches));

    for (batch_id, batch_ports) in batches.into_iter().enumerate() {
        let batch_sem = batch_semaphore.clone();
        let udp_scanner = udp_scanner.clone();
        let service_detection = config.service_detection;
        let service_detector = service_detector.clone();
        let target = config.target;

        let handle = tokio::spawn(async move {
            let _batch_permit = batch_sem.acquire().await.unwrap();

            udp_scan_batch(
                udp_scanner,
                batch_ports,
                target,
                service_detection,
                service_detector,
                batch_id,
            )
            .await
        });

        handles.push(handle);
    }

    handles
}

async fn udp_scan_batch(
    udp_scanner: Arc<UdpScanner>,
    ports: Vec<u16>,
    target: IpAddr,
    service_detection: bool,
    service_detector: Arc<ServiceDetector>,
    batch_id: usize,
) -> Vec<ScanResult> {
    let batch_start = std::time::Instant::now();

    let results: Vec<ScanResult> = stream::iter(ports)
        .map(|port| {
            let udp_scanner = udp_scanner.clone();
            let service_detection = service_detection;
            let service_detector = service_detector.clone();

            async move {
                let udp_result = udp_scanner.scan_port(port).await;
                convert_udp_result(udp_result, target, service_detection, service_detector).await
            }
        })
        .buffer_unordered(40) // UDP can handle more concurrent requests
        .collect()
        .await;

    let batch_duration = batch_start.elapsed();
    println!(
        "🔄 UDP batch {} completed: {} ports in {:.2}s",
        batch_id,
        results.len(),
        batch_duration.as_secs_f64()
    );

    results
}

// Legacy compatibility functions for existing codebase
pub async fn start_tcp_scans(
    config: &ScanConfig,
    semaphore: &Arc<tokio::sync::Semaphore>,
    service_detector: &Arc<ServiceDetector>,
) -> Vec<tokio::task::JoinHandle<ScanResult>> {
    let mut handles = Vec::new();

    match config.scan_type {
        ScanType::TcpConnect | ScanType::Mixed => {
            // Use optimized batch processing for better performance
            let batch_handles =
                start_tcp_scans_optimized(config, semaphore, service_detector, None).await;

            // Flatten batch results into individual results for compatibility
            for batch_handle in batch_handles {
                let handle = tokio::spawn(async move {
                    match batch_handle.await {
                        Ok(batch_results) => {
                            // Return all results flattened, but for compatibility return first one
                            batch_results.into_iter().next().unwrap_or_else(|| {
                                ScanResult::new_tcp(0, false, None, None, None, 0, "TCP")
                            })
                        }
                        Err(_) => ScanResult::new_tcp(0, false, None, None, None, 0, "TCP"),
                    }
                });
                handles.push(handle);
            }
        }
        ScanType::StealthSyn => {
            // Create stealth configuration
            let stealth_config = StealthScanConfig {
                timeout: Duration::from_millis(config.timeout_ms),
                technique: ScanTechnique::StealthSyn,
                retries: 2, // Direct u8 value
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

// Original TCP scan function (kept for compatibility)
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

// Conversion functions
async fn convert_stealth_result(
    stealth_result: Result<StealthScanResult, crate::stealth::StealthScanError>,
    target: IpAddr,
    service_detection: bool,
    service_detector: Arc<ServiceDetector>,
) -> ScanResult {
    match stealth_result {
        Ok(result) => {
            let is_open = matches!(result.state, PortState::Open);
            let (service, service_info) = if is_open && service_detection {
                let detected_service = service_detector
                    .detect_service(target, result.port, None)
                    .await;
                (Some(detected_service.name.clone()), Some(detected_service))
            } else {
                (services::detect_basic_service(result.port), None)
            };

            ScanResult::new_tcp(
                result.port,
                is_open,
                service,
                service_info,
                None, // Stealth scans don't grab banners
                result.response_time.as_millis() as u64,
                "SYN",
            )
        }
        Err(_) => {
            ScanResult::new_tcp(
                0, // Port will be set correctly in actual implementation
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

    let service = services::detect_basic_service(udp_result.port);

    let service_info = if is_open && service_detection {
        Some(
            service_detector
                .detect_service(target, udp_result.port, None)
                .await,
        )
    } else {
        None
    };

    let banner = udp_result.response_data.as_ref().map(|data| {
        if data.len() > 100 {
            format!(
                "UDP response ({} bytes): {}...",
                data.len(),
                String::from_utf8_lossy(&data[..100])
            )
        } else {
            format!("UDP response: {}", String::from_utf8_lossy(data))
        }
    });

    ScanResult::new_udp(
        udp_result.port,
        is_open,
        service,
        service_info,
        banner,
        udp_result.response_time, // Already u64, no conversion needed
        udp_state_str,
    )
}

// Helper functions for batch creation
fn create_static_batches(ports: &[u16], batch_size: usize) -> Vec<Vec<u16>> {
    ports
        .chunks(batch_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

// Performance monitoring
pub struct ScanMetrics {
    pub total_ports_scanned: u64,
    pub successful_scans: u64,
    pub failed_scans: u64,
    pub total_scan_time: Duration,
    pub average_response_time: Duration,
    pub scan_rate: f64, // ports per second
}

impl ScanMetrics {
    pub fn new() -> Self {
        Self {
            total_ports_scanned: 0,
            successful_scans: 0,
            failed_scans: 0,
            total_scan_time: Duration::from_secs(0),
            average_response_time: Duration::from_secs(0),
            scan_rate: 0.0,
        }
    }

    pub fn update(&mut self, results: &[ScanResult], scan_time: Duration) {
        self.total_ports_scanned += results.len() as u64;
        self.successful_scans += results.iter().filter(|r| r.is_open).count() as u64;
        self.failed_scans = self.total_ports_scanned - self.successful_scans;
        self.total_scan_time = scan_time;

        let total_response_time: u64 = results.iter().map(|r| r.response_time).sum();

        if !results.is_empty() {
            self.average_response_time =
                Duration::from_millis(total_response_time / results.len() as u64);
        }

        self.scan_rate = self.total_ports_scanned as f64 / scan_time.as_secs_f64();
    }

    pub fn print_summary(&self) {
        println!("\n📊 Scan Performance Summary:");
        println!("   Total ports scanned: {}", self.total_ports_scanned);
        println!("   Successful scans: {}", self.successful_scans);
        println!("   Failed scans: {}", self.failed_scans);
        println!(
            "   Total scan time: {:.2}s",
            self.total_scan_time.as_secs_f64()
        );
        println!(
            "   Average response time: {:.2}ms",
            self.average_response_time.as_millis()
        );
        println!("   Scan rate: {:.1} ports/second", self.scan_rate);
    }
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
        retries: 2, // u8 value
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
    async fn test_batch_creation() {
        let ports = vec![80, 443, 22, 21, 25, 53, 110, 143, 993, 995];
        let batches = create_static_batches(&ports, 3);

        assert_eq!(batches.len(), 4); // 10 ports / 3 batch_size = 4 batches
        assert_eq!(batches[0], vec![80, 443, 22]);
        assert_eq!(batches[1], vec![21, 25, 53]);
        assert_eq!(batches[2], vec![110, 143, 993]);
        assert_eq!(batches[3], vec![995]);
    }

    #[tokio::test]
    async fn test_adaptive_batch_manager() {
        let mut manager = AdaptiveBatchManager::new();
        let initial_size = manager.get_batch_size();

        // Good performance should increase batch size
        manager.update_performance(0.95, 0.3);
        assert!(manager.get_batch_size() >= initial_size);

        // Poor performance should decrease batch size
        manager.update_performance(0.6, 3.0);
        assert!(manager.get_batch_size() <= initial_size);
    }

    #[test]
    fn test_batch_config_default() {
        let config = BatchConfig::default();
        assert_eq!(config.batch_size, DEFAULT_BATCH_SIZE);
        assert_eq!(config.concurrent_batches, DEFAULT_CONCURRENT_BATCHES);
        assert!(config.enable_adaptive_batching);
        assert_eq!(config.max_retries, 2);
    }

    #[test]
    fn test_scan_metrics() {
        let mut metrics = ScanMetrics::new();
        assert_eq!(metrics.total_ports_scanned, 0);
        assert_eq!(metrics.successful_scans, 0);

        // Create some mock results
        let results = vec![
            ScanResult::new_tcp(80, true, Some("http".to_string()), None, None, 100, "TCP"),
            ScanResult::new_tcp(443, true, Some("https".to_string()), None, None, 150, "TCP"),
            ScanResult::new_tcp(22, false, None, None, None, 3000, "TCP"),
        ];

        metrics.update(&results, Duration::from_secs(1));
        assert_eq!(metrics.total_ports_scanned, 3);
        assert_eq!(metrics.successful_scans, 2);
        assert_eq!(metrics.failed_scans, 1);
        assert!(metrics.scan_rate > 0.0);
    }
}
