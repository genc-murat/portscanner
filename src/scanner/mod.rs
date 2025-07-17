mod config;
mod display;
mod risk_assessment;
mod scan_engine;
mod scan_results;
mod services;
mod utils; // Yeni eklenen modül

pub use config::{Protocol, ScanConfig, ScanType};
pub use risk_assessment::{format_risk_assessment, Priority, RiskAssessment, RiskAssessmentEngine};
pub use scan_results::{CompleteScanResult, ScanResult, ScanSummary}; // Priority'yi de re-export et

use crate::html_generator::write_html_report;
use crate::os_fingerprinting::{OSDetector, OSFingerprint};
use crate::service_detection::ServiceDetector;
use crate::ssl::{SslAnalysisResult, SslAnalyzer};
use crate::udp::UdpScanner;
use std::sync::Arc;

pub struct PortScanner {
    config: config::ScanConfig,
    service_detector: Arc<ServiceDetector>,
    os_detector: Arc<tokio::sync::Mutex<OSDetector>>,
    udp_scanner: Arc<UdpScanner>,
    ssl_analyzer: Arc<SslAnalyzer>,
    risk_engine: Arc<RiskAssessmentEngine>, // Yeni eklenen risk engine
}

impl PortScanner {
    pub fn new(args: crate::Args) -> Result<Self, String> {
        let config = config::ScanConfig::from_args(args)?;

        Ok(Self {
            service_detector: Arc::new(ServiceDetector::new()),
            os_detector: Arc::new(tokio::sync::Mutex::new(OSDetector::new())),
            udp_scanner: Arc::new(UdpScanner::new(config.target, config.timeout_ms)),
            ssl_analyzer: Arc::new(SslAnalyzer::new(config.timeout_ms)),
            risk_engine: Arc::new(RiskAssessmentEngine::new()), // Risk engine initialization
            config,
        })
    }

    pub async fn run(&self) {
        let scan_start = std::time::Instant::now();

        display::print_scan_header(&self.config);

        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.concurrency));
        let mut handles = Vec::new();

        // TCP Scanning
        if matches!(self.config.protocol, Protocol::Tcp | Protocol::Both) {
            handles.extend(self.start_tcp_scans(&semaphore).await);
        }

        // UDP Scanning
        if matches!(self.config.protocol, Protocol::Udp | Protocol::Both) {
            handles.extend(self.start_udp_scans(&semaphore).await);
        }

        // Collect results
        let mut results = Vec::new();
        for handle in handles {
            if let Ok(result) = handle.await {
                results.push(result);
            }
        }

        // Post-processing analysis
        let os_fingerprint = self.perform_os_detection(&results).await;
        let ssl_analysis = self.perform_ssl_analysis(&results).await;

        // NEW: Risk Assessment
        let risk_assessment = self
            .perform_risk_assessment(&results, &os_fingerprint, &ssl_analysis)
            .await;

        let scan_time = scan_start.elapsed().as_secs_f64();
        let summary =
            scan_results::create_scan_summary(&results, &ssl_analysis, scan_time, &self.config);

        let complete_result = CompleteScanResult {
            target: self.config.target_hostname.clone(),
            scan_results: results,
            os_fingerprint: os_fingerprint.clone(),
            ssl_analysis,
            scan_summary: summary,
            risk_assessment: Some(risk_assessment.clone()), // Risk assessment'i sonuçlara ekle
        };

        self.display_results(complete_result);
    }

    async fn start_tcp_scans(
        &self,
        semaphore: &Arc<tokio::sync::Semaphore>,
    ) -> Vec<tokio::task::JoinHandle<ScanResult>> {
        scan_engine::start_tcp_scans(&self.config, semaphore, &self.service_detector).await
    }

    async fn start_udp_scans(
        &self,
        semaphore: &Arc<tokio::sync::Semaphore>,
    ) -> Vec<tokio::task::JoinHandle<ScanResult>> {
        scan_engine::start_udp_scans(
            &self.config,
            semaphore,
            &self.udp_scanner,
            &self.service_detector,
        )
        .await
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
            .filter(|r| r.is_open && r.protocol == "TCP" && services::is_ssl_port(r.port))
            .map(|r| r.port)
            .collect();

        if ssl_ports.is_empty() {
            println!("⚠️  No SSL/TLS ports found for analysis");
            return Vec::new();
        }

        println!(
            "🔍 Performing SSL/TLS analysis on {} ports",
            ssl_ports.len()
        );

        let mut ssl_results = Vec::new();
        for &port in &ssl_ports {
            let ssl_result = self
                .ssl_analyzer
                .analyze_ssl(self.config.target, port, Some(&self.config.target_hostname))
                .await;
            ssl_results.push(ssl_result);
        }

        ssl_results
    }

    // NEW: Risk Assessment Method
    async fn perform_risk_assessment(
        &self,
        results: &[ScanResult],
        os_fingerprint: &Option<OSFingerprint>,
        ssl_analysis: &[SslAnalysisResult],
    ) -> RiskAssessment {
        println!("🛡️  Performing security risk assessment...");

        self.risk_engine.assess_risks(
            results,
            os_fingerprint,
            ssl_analysis,
            &self.config.target_hostname,
        )
    }

    fn display_results(&self, complete_result: CompleteScanResult) {
        if self.config.json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&complete_result).unwrap()
            );
            return;
        }

        if let Some(filename) = &self.config.html_output {
            match write_html_report(&complete_result, filename) {
                Ok(_) => println!("Successfully saved HTML report to {}", filename),
                Err(e) => eprintln!("Error writing HTML report: {}", e),
            }
            return;
        }

        // Display normal results
        display::display_formatted_results(complete_result.clone(), &self.config);

        // NEW: Display Risk Assessment
        if let Some(risk_assessment) = &complete_result.risk_assessment {
            println!("{}", format_risk_assessment(risk_assessment));
        }
    }
}
