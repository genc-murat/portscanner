//! # Port Scanner
//!
//! A fast, modern port scanner written in Rust with async networking,
//! stealth SYN scan, UDP scanning, advanced service detection, and OS fingerprinting capabilities.
//!
//! ## Features
//!
//! - **Fast Async Scanning**: Built with Tokio for high-performance concurrent scanning
//! - **TCP & UDP Support**: Comprehensive scanning for both TCP and UDP protocols
//! - **Stealth SYN Scan**: Raw socket SYN scanning for speed and stealth (Linux/Unix)
//! - **UDP Service Detection**: Protocol-specific probes for common UDP services
//! - **Advanced Service Detection**: Nmap-style service identification with 150+ signatures
//! - **OS Fingerprinting**: Operating system detection via TCP/IP stack analysis
//! - **Banner Grabbing**: Extract service banners and version information
//! - **JSON Export**: Export results in JSON format for further analysis
//!
//! ## Supported Protocols
//!
//! ### TCP Scanning
//! - TCP Connect scan (default)
//! - Stealth SYN scan (Linux/Unix with root privileges)
//! - Banner grabbing for service identification
//! - Service version detection
//!
//! ### UDP Scanning
//! - UDP probe scanning with service-specific payloads
//! - Support for common UDP services (DNS, NTP, SNMP, DHCP, etc.)
//! - Open|Filtered state detection
//! - Protocol-specific response analysis
//!
//! ## Example
//!
//! ```rust,no_run
//! use portscanner::port_parser::parse_ports;
//! use portscanner::service_detection::ServiceDetector;
//! use portscanner::udp::UdpScanner;
//!
//! // Parse port ranges
//! let ports = parse_ports("22,80,443,8000-9000").unwrap();
//! assert_eq!(ports[0], 22);
//!
//! // Create service detector
//! let detector = ServiceDetector::new();
//! // Use detector for service identification...
//!
//! // Create UDP scanner
//! let target = "127.0.0.1".parse().unwrap();
//! let udp_scanner = UdpScanner::new(target, 3000);
//! // Use UDP scanner for UDP port scanning...
//! ```

pub mod os_fingerprinting;
pub mod port_parser;
pub mod progress;
pub mod service_detection;
pub mod ssl; // Add SSL module
pub mod udp;

// Only include stealth module on Unix systems
#[cfg(unix)]
pub mod stealth;

// Re-export commonly used types
pub use os_fingerprinting::{format_os_info, OSDetector, OSFingerprint};
pub use service_detection::{format_service_info, ServiceDetector, ServiceInfo};
pub use ssl::{format_ssl_analysis, SslAnalysisResult, SslAnalyzer}; // Re-export SSL types
pub use udp::{UdpPortState, UdpScanResult, UdpScanner};

#[cfg(unix)]
pub use stealth::{PortState, StealthScanResult, StealthScanner};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const NAME: &str = env!("CARGO_PKG_NAME");

pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_info() {
        assert!(!VERSION.is_empty());
        assert!(!NAME.is_empty());
        assert!(!DESCRIPTION.is_empty());
    }

    #[test]
    fn test_port_parser() {
        let ports = port_parser::parse_ports("80,443").unwrap();
        assert_eq!(ports, vec![80, 443]);
    }

    #[test]
    fn test_service_detector_creation() {
        let detector = ServiceDetector::new();
        drop(detector);
    }

    #[test]
    fn test_os_detector_creation() {
        let detector = OSDetector::new();
        drop(detector);
    }

    #[test]
    fn test_udp_scanner_creation() {
        let target = "127.0.0.1".parse().unwrap();
        let scanner = UdpScanner::new(target, 3000);
        drop(scanner);
    }

    #[test]
    fn test_udp_common_ports() {
        let ports = UdpScanner::get_common_udp_ports();
        assert!(!ports.is_empty());
        assert!(ports.contains(&53)); // DNS
        assert!(ports.contains(&123)); // NTP
        assert!(ports.contains(&161)); // SNMP
    }

    #[test]
    fn test_ssl_analyzer_creation() {
        let analyzer = SslAnalyzer::new(5000);
        drop(analyzer);
    }

    #[tokio::test]
    async fn test_ssl_analysis_integration() {
        let target = "127.0.0.1".parse().unwrap();
        let analyzer = SslAnalyzer::new(3000);

        // Test SSL analysis on a common HTTPS port
        let result = analyzer.analyze_ssl(target, 443, Some("localhost")).await;

        // Should get some result regardless of SSL availability
        assert_eq!(result.port, 443);
        assert_eq!(result.target, "localhost");
    }
}
