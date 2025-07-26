mod config;
mod display;
mod risk_assessment;
mod scan_engine;
mod scan_results;
mod services;
mod utils;

pub use config::{Protocol, ScanConfig, ScanType};
pub use risk_assessment::{format_risk_assessment, Priority, RiskAssessment, RiskAssessmentEngine};
pub use scan_results::{CompleteScanResult, ScanResult, ScanSummary};

use crate::html_generator::write_html_report;
use crate::os_fingerprinting::{OSDetector, OSFingerprint};
use crate::service_detection::ServiceDetector;
use crate::ssl::{SslAnalysisResult, SslAnalyzer};
use crate::udp::UdpScanner;
use scan_engine::{AdaptiveBatchManager, BatchConfig, ScanMetrics};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

pub struct PortScanner {
    config: config::ScanConfig,
    service_detector: Arc<ServiceDetector>,
    os_detector: Arc<tokio::sync::Mutex<OSDetector>>,
    udp_scanner: Arc<UdpScanner>,
    ssl_analyzer: Arc<SslAnalyzer>,
    risk_engine: Arc<RiskAssessmentEngine>,
}

impl PortScanner {
    pub fn new(args: crate::Args) -> Result<Self, String> {
        let config = config::ScanConfig::from_args(args)?;

        Ok(Self {
            service_detector: Arc::new(ServiceDetector::new()),
            os_detector: Arc::new(tokio::sync::Mutex::new(OSDetector::new())),
            udp_scanner: Arc::new(UdpScanner::new(config.target, config.timeout_ms)),
            ssl_analyzer: Arc::new(SslAnalyzer::new(config.timeout_ms)),
            risk_engine: Arc::new(RiskAssessmentEngine::new()),
            config,
        })
    }

    pub async fn run(&self) {
        // Delegate to OptimizedPortScanner for better performance
        let optimized_scanner = OptimizedPortScanner {
            service_detector: self.service_detector.clone(),
            os_detector: self.os_detector.clone(),
            udp_scanner: self.udp_scanner.clone(),
            ssl_analyzer: self.ssl_analyzer.clone(),
            risk_engine: self.risk_engine.clone(),
            batch_config: BatchConfig::default(),
            metrics: Arc::new(Mutex::new(ScanMetrics::new())),
            config: self.config.clone(),
        };

        optimized_scanner.run().await;
    }
}

pub struct OptimizedPortScanner {
    config: config::ScanConfig,
    service_detector: Arc<ServiceDetector>,
    os_detector: Arc<tokio::sync::Mutex<OSDetector>>,
    udp_scanner: Arc<UdpScanner>,
    ssl_analyzer: Arc<SslAnalyzer>,
    risk_engine: Arc<RiskAssessmentEngine>,
    batch_config: BatchConfig,
    metrics: Arc<Mutex<ScanMetrics>>,
}

impl OptimizedPortScanner {
    pub fn new(args: crate::Args) -> Result<Self, String> {
        let config = config::ScanConfig::from_args(args)?;

        // Configure batch processing based on scan parameters
        let batch_config = Self::create_batch_config(&config);

        Ok(Self {
            service_detector: Arc::new(ServiceDetector::new()),
            os_detector: Arc::new(tokio::sync::Mutex::new(OSDetector::new())),
            udp_scanner: Arc::new(UdpScanner::new(config.target, config.timeout_ms)),
            ssl_analyzer: Arc::new(SslAnalyzer::new(config.timeout_ms)),
            risk_engine: Arc::new(RiskAssessmentEngine::new()),
            batch_config,
            metrics: Arc::new(Mutex::new(ScanMetrics::new())),
            config,
        })
    }

    fn create_batch_config(config: &ScanConfig) -> BatchConfig {
        let port_count = config.ports.len();
        let concurrency = config.concurrency;

        // Adaptive batch configuration based on scan parameters
        let (batch_size, concurrent_batches) = match (port_count, concurrency) {
            // Small scans: smaller batches, fewer concurrent batches
            (1..=100, _) => (20, 2),
            // Medium scans: balanced approach
            (101..=1000, 1..=100) => (50, 3),
            (101..=1000, 101..=300) => (75, 4),
            (101..=1000, _) => (100, 5),
            // Large scans: bigger batches, more concurrent processing
            (1001..=10000, 1..=100) => (100, 4),
            (1001..=10000, 101..=300) => (150, 6),
            (1001..=10000, _) => (200, 8),
            // Very large scans: maximum optimization
            (_, 1..=100) => (150, 5),
            (_, 101..=300) => (200, 8),
            (_, _) => (250, 10),
        };

        BatchConfig {
            batch_size,
            concurrent_batches,
            enable_adaptive_batching: port_count > 500, // Enable adaptive batching for larger scans
            max_retries: if config.timeout_ms < 2000 { 1 } else { 2 }, // Fewer retries for fast scans
        }
    }

    pub async fn run(&self) {
        let scan_start = std::time::Instant::now();

        display::print_scan_header(&self.config);

        // Print optimization info
        println!("🚀 Optimization Settings:");
        println!("   Batch size: {}", self.batch_config.batch_size);
        println!(
            "   Concurrent batches: {}",
            self.batch_config.concurrent_batches
        );
        println!(
            "   Adaptive batching: {}",
            self.batch_config.enable_adaptive_batching
        );
        println!("   Connection pool: Disabled");
        println!("   Total ports: {}", self.config.ports.len());
        println!();

        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.concurrency));
        let mut all_results = Vec::new();

        // TCP Scanning with batch processing
        if matches!(self.config.protocol, Protocol::Tcp | Protocol::Both) {
            println!("🔍 Starting optimized TCP scan...");
            let tcp_handles = scan_engine::start_tcp_scans_optimized(
                &self.config,
                &semaphore,
                &self.service_detector,
                Some(self.batch_config.clone()),
            )
            .await;

            // Collect TCP results from all batches
            for handle in tcp_handles {
                if let Ok(batch_results) = handle.await {
                    all_results.extend(batch_results);
                }
            }
        }

        // UDP Scanning with batch processing
        if matches!(self.config.protocol, Protocol::Udp | Protocol::Both) {
            println!("🔍 Starting optimized UDP scan...");
            let udp_handles = scan_engine::start_udp_scans_optimized(
                &self.config,
                &semaphore,
                &self.udp_scanner,
                &self.service_detector,
                Some(self.batch_config.clone()),
            )
            .await;

            // Collect UDP results from all batches
            for handle in udp_handles {
                if let Ok(batch_results) = handle.await {
                    all_results.extend(batch_results);
                }
            }
        }

        let scan_time = scan_start.elapsed();

        // Update metrics
        {
            let mut metrics = self.metrics.lock().await;
            metrics.update(&all_results, scan_time);
            metrics.print_summary();
        }

        // Post-processing analysis
        let os_fingerprint = self.perform_os_detection(&all_results).await;
        let ssl_analysis = self.perform_ssl_analysis(&all_results).await;

        // Risk Assessment
        let risk_assessment = self
            .perform_risk_assessment(&all_results, &os_fingerprint, &ssl_analysis)
            .await;

        let summary = scan_results::create_scan_summary(
            &all_results,
            &ssl_analysis,
            scan_time.as_secs_f64(),
            &self.config,
        );

        let complete_result = CompleteScanResult {
            target: self.config.target_hostname.clone(),
            scan_results: all_results,
            os_fingerprint: os_fingerprint.clone(),
            ssl_analysis,
            scan_summary: summary,
            risk_assessment: Some(risk_assessment.clone()),
        };

        self.display_results(complete_result);
    }

    async fn perform_os_detection(&self, results: &[ScanResult]) -> Option<OSFingerprint> {
        if !self.config.os_detection {
            return None;
        }

        let open_tcp_ports: Vec<u16> = results
            .iter()
            .filter(|r| r.is_open && r.protocol == "TCP")
            .map(|r| r.port)
            .collect();

        if !open_tcp_ports.is_empty() {
            let mut os_detector = self.os_detector.lock().await;
            os_detector
                .detect_os(self.config.target, &open_tcp_ports)
                .await
        } else {
            println!("⚠️  No open TCP ports found for OS detection");
            None
        }
    }

    async fn perform_ssl_analysis(&self, results: &[ScanResult]) -> Vec<SslAnalysisResult> {
        if !self.config.ssl_analysis {
            return Vec::new();
        }

        let ssl_ports: Vec<u16> = results
            .iter()
            .filter(|r| r.is_open && self.is_ssl_port(r.port))
            .map(|r| r.port)
            .collect();

        if ssl_ports.is_empty() {
            return Vec::new();
        }

        println!(
            "🔒 Analyzing SSL/TLS services on {} ports...",
            ssl_ports.len()
        );

        // Batch SSL analysis for better performance
        let ssl_semaphore = Arc::new(tokio::sync::Semaphore::new(10)); // Limit SSL connections
        let mut ssl_handles = Vec::new();

        for port in ssl_ports {
            let ssl_analyzer = self.ssl_analyzer.clone();
            let target = self.config.target;
            let sem = ssl_semaphore.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                ssl_analyzer.analyze_ssl(target, port, None).await
            });

            ssl_handles.push(handle);
        }

        let mut ssl_results = Vec::new();
        for handle in ssl_handles {
            match handle.await {
                Ok(ssl_result) => {
                    ssl_results.push(ssl_result);
                }
                Err(_) => {
                    // Handle JoinError - task failed
                    continue;
                }
            }
        }

        ssl_results
    }

    async fn perform_risk_assessment(
        &self,
        results: &[ScanResult],
        os_fingerprint: &Option<OSFingerprint>,
        ssl_analysis: &[SslAnalysisResult],
    ) -> RiskAssessment {
        self.risk_engine.assess_risks(
            results,
            os_fingerprint,
            ssl_analysis,
            &self.config.target.to_string(),
        )
    }

    fn is_ssl_port(&self, port: u16) -> bool {
        matches!(port, 443 | 993 | 995 | 8443 | 465 | 636 | 989 | 990)
    }

    fn display_results(&self, results: CompleteScanResult) {
        display::display_formatted_results(results.clone(), &self.config);

        // Enhanced performance display
        tokio::spawn(async move {
            let metrics = results.scan_summary.clone();
            println!("\n🎯 Scan Efficiency Report:");
            println!(
                "   Open ports found: {}",
                results.scan_results.iter().filter(|r| r.is_open).count()
            );
            println!(
                "   Scan rate: {:.1} ports/second",
                results.scan_results.len() as f64 / metrics.scan_time
            );
            println!(
                "   Average response time: {:.2}ms",
                results
                    .scan_results
                    .iter()
                    .map(|r| r.response_time as f64)
                    .sum::<f64>()
                    / results.scan_results.len() as f64
            );
        });
    }
}

// Enhanced progress tracking for batch operations
pub struct BatchProgressTracker {
    total_batches: usize,
    completed_batches: std::sync::atomic::AtomicUsize,
    total_ports: usize,
    completed_ports: std::sync::atomic::AtomicUsize,
    start_time: std::time::Instant,
}

impl BatchProgressTracker {
    pub fn new(total_batches: usize, total_ports: usize) -> Self {
        Self {
            total_batches,
            completed_batches: std::sync::atomic::AtomicUsize::new(0),
            total_ports,
            completed_ports: std::sync::atomic::AtomicUsize::new(0),
            start_time: std::time::Instant::now(),
        }
    }

    pub fn batch_completed(&self, ports_in_batch: usize) {
        use std::sync::atomic::Ordering;

        self.completed_batches.fetch_add(1, Ordering::Relaxed);
        self.completed_ports
            .fetch_add(ports_in_batch, Ordering::Relaxed);

        let completed_batches = self.completed_batches.load(Ordering::Relaxed);
        let completed_ports = self.completed_ports.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed();

        let batch_progress = (completed_batches as f64 / self.total_batches as f64) * 100.0;
        let port_progress = (completed_ports as f64 / self.total_ports as f64) * 100.0;
        let rate = completed_ports as f64 / elapsed.as_secs_f64();

        println!(
            "📊 Progress: {:.1}% batches ({}/{}) | {:.1}% ports ({}/{}) | {:.1} ports/sec",
            batch_progress,
            completed_batches,
            self.total_batches,
            port_progress,
            completed_ports,
            self.total_ports,
            rate
        );
    }
}

// Adaptive concurrency manager
pub struct AdaptiveConcurrencyManager {
    current_concurrency: usize,
    max_concurrency: usize,
    min_concurrency: usize,
    target_response_time: Duration,
    adjustment_threshold: f64,
}

impl AdaptiveConcurrencyManager {
    pub fn new(initial_concurrency: usize) -> Self {
        Self {
            current_concurrency: initial_concurrency,
            max_concurrency: initial_concurrency * 2,
            min_concurrency: initial_concurrency / 4,
            target_response_time: Duration::from_millis(500),
            adjustment_threshold: 0.2, // 20% change threshold
        }
    }

    pub fn adjust_concurrency(&mut self, avg_response_time: Duration, success_rate: f64) -> usize {
        let response_ratio =
            avg_response_time.as_millis() as f64 / self.target_response_time.as_millis() as f64;

        if success_rate > 0.9 && response_ratio < 1.0 {
            // Performance is good, try increasing concurrency
            let new_concurrency =
                ((self.current_concurrency as f64 * 1.1) as usize).min(self.max_concurrency);
            if new_concurrency != self.current_concurrency {
                println!(
                    "🔧 Increasing concurrency: {} -> {}",
                    self.current_concurrency, new_concurrency
                );
                self.current_concurrency = new_concurrency;
            }
        } else if success_rate < 0.8 || response_ratio > 1.5 {
            // Performance is poor, decrease concurrency
            let new_concurrency =
                ((self.current_concurrency as f64 * 0.8) as usize).max(self.min_concurrency);
            if new_concurrency != self.current_concurrency {
                println!(
                    "🔧 Decreasing concurrency: {} -> {}",
                    self.current_concurrency, new_concurrency
                );
                self.current_concurrency = new_concurrency;
            }
        }

        self.current_concurrency
    }

    pub fn get_current_concurrency(&self) -> usize {
        self.current_concurrency
    }
}

// Memory-efficient result streaming for very large scans
pub struct StreamingResultProcessor {
    batch_size: usize,
    output_writer: Option<std::fs::File>,
}

impl StreamingResultProcessor {
    pub fn new(batch_size: usize, output_file: Option<String>) -> std::io::Result<Self> {
        let output_writer = if let Some(filename) = output_file {
            Some(std::fs::File::create(filename)?)
        } else {
            None
        };

        Ok(Self {
            batch_size,
            output_writer,
        })
    }

    pub async fn process_batch(
        &mut self,
        results: Vec<ScanResult>,
        target: &str,
    ) -> std::io::Result<()> {
        if let Some(ref mut writer) = self.output_writer {
            use std::io::Write;

            for result in &results {
                if result.is_open {
                    writeln!(
                        writer,
                        "{}: {}/{} - {}",
                        target,
                        result.port,
                        result.protocol,
                        result.service.as_deref().unwrap_or("unknown")
                    )?;
                }
            }
            writer.flush()?;
        }

        // Memory management: only keep essential data for final summary
        let open_count = results.iter().filter(|r| r.is_open).count();
        if open_count > 0 {
            println!("✅ Batch completed: {} open ports found", open_count);
        }

        Ok(())
    }
}
