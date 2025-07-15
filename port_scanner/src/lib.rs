//! # Port Scanner
//!
//! A fast, modern port scanner written in Rust with async networking,
//! stealth SYN scan, advanced service detection, and OS fingerprinting capabilities.
//!
//! ## Features
//!
//! - **Fast Async Scanning**: Built with Tokio for high-performance concurrent scanning
//! - **Stealth SYN Scan**: Raw socket SYN scanning for speed and stealth (Linux/Unix)
//! - **Advanced Service Detection**: Nmap-style service identification with 150+ signatures
//! - **OS Fingerprinting**: Operating system detection via TCP/IP stack analysis
//! - **Banner Grabbing**: Extract service banners and version information
//! - **JSON Export**: Export results in JSON format for further analysis
//!
//! ## Example
//!
//! ```rust,no_run
//! use port_scanner::port_parser::parse_ports;
//! use port_scanner::service_detection::ServiceDetector;
//!
//! // Parse port ranges
//! let ports = parse_ports("22,80,443,8000-9000").unwrap();
//! assert_eq!(ports[0], 22);
//!
//! // Create service detector
//! let detector = ServiceDetector::new();
//! // Use detector for service identification...
//! ```

pub mod os_fingerprinting;
pub mod port_parser;
pub mod service_detection;

// Only include stealth module on Unix systems
#[cfg(unix)]
pub mod stealth;

// Re-export commonly used types
pub use os_fingerprinting::{OSDetector, OSFingerprint, format_os_info};
pub use service_detection::{ServiceDetector, ServiceInfo, format_service_info};

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
}
