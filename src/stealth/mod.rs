//! Stealth Scanning Module
//!
//! This module provides a comprehensive, testable, and maintainable implementation
//! of various TCP scanning techniques including stealth SYN scanning, TCP connect
//! scanning, and advanced techniques like FIN, NULL, and Xmas scans.
//!
//! # Architecture
//!
//! The module is organized around several key traits and types:
//!
//! - `ScanEngine`: The main trait for different scanning implementations
//! - `PacketBuilder`: Trait for building different types of TCP packets
//! - `PacketParser`: Trait for parsing responses and determining port states
//! - `NetworkUtils`: Trait for network operations (sending/receiving packets)
//! - `ScanEngineFactory`: Factory for creating appropriate scan engines
//!
//! # Examples
//!
//! ```rust,no_run
//! use portscanner::stealth::{StealthScanner, ScanTechnique, ScanConfig};
//! use std::net::IpAddr;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let target = "127.0.0.1".parse::<IpAddr>()?;
//!     let config = ScanConfig {
//!         timeout: Duration::from_millis(3000),
//!         technique: ScanTechnique::TcpConnect,
//!         ..Default::default()
//!     };
//!     
//!     let scanner = StealthScanner::new(target, config)?;
//!     let result = scanner.scan_port(80).await?;
//!     
//!     println!("Port 80 is {}", result.state);
//!     Ok(())
//! }
//! ```

pub mod factory;
pub mod network;
pub mod packet_builder;
pub mod packet_parser;
pub mod scan_engines;
pub mod traits;
pub mod types;

use factory::DefaultScanEngineFactory;
use traits::ScanEngine;
pub use types::*;

use std::net::IpAddr;
use std::sync::Arc;

/// Main stealth scanner interface that provides a high-level API
/// for performing various types of TCP scans
pub struct StealthScanner {
    target: IpAddr,
    engine: Box<dyn ScanEngine>,
    config: ScanConfig,
}

impl StealthScanner {
    /// Creates a new stealth scanner for the specified target and configuration
    pub fn new(target: IpAddr, config: ScanConfig) -> Result<Self, StealthScanError> {
        let factory = DefaultScanEngineFactory;
        let engine =
            factory.create_engine_for_target(target, config.technique.clone(), config.clone())?;

        Ok(Self {
            target,
            engine,
            config,
        })
    }

    /// Creates a new stealth scanner with a custom scan engine factory
    pub fn with_factory<F>(
        target: IpAddr,
        config: ScanConfig,
        factory: F,
    ) -> Result<Self, StealthScanError>
    where
        F: traits::ScanEngineFactory,
    {
        let engine =
            factory.create_engine_for_target(target, config.technique.clone(), config.clone())?;

        Ok(Self {
            target,
            engine,
            config,
        })
    }

    /// Scans a single port and returns the result
    pub async fn scan_port(&self, port: u16) -> Result<StealthScanResult, StealthScanError> {
        self.engine.scan_port(self.target, port).await
    }

    /// Scans multiple ports and returns a vector of results
    pub async fn scan_ports(
        &self,
        ports: &[u16],
    ) -> Vec<Result<StealthScanResult, StealthScanError>> {
        if self.config.randomize_order {
            let mut randomized_ports = ports.to_vec();
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            randomized_ports.shuffle(&mut rng);
            self.scan_ports_sequential(&randomized_ports).await
        } else {
            self.scan_ports_sequential(ports).await
        }
    }

    /// Scans multiple ports concurrently with controlled concurrency
    pub async fn scan_ports_concurrent(
        &self,
        ports: &[u16],
        max_concurrent: usize,
    ) -> Vec<Result<StealthScanResult, StealthScanError>> {
        use futures::stream::{self, StreamExt};

        let scanner = Arc::new(&self.engine);
        let target = self.target;
        let delay = self.config.delay_between_probes;

        stream::iter(ports)
            .map(|&port| {
                let scanner = Arc::clone(&scanner);
                async move {
                    let result = scanner.scan_port(target, port).await;
                    if let Some(delay) = delay {
                        tokio::time::sleep(delay).await;
                    }
                    result
                }
            })
            .buffer_unordered(max_concurrent)
            .collect()
            .await
    }

    async fn scan_ports_sequential(
        &self,
        ports: &[u16],
    ) -> Vec<Result<StealthScanResult, StealthScanError>> {
        let mut results = Vec::with_capacity(ports.len());

        for &port in ports {
            let result = self.engine.scan_port(self.target, port).await;
            results.push(result);

            if let Some(delay) = self.config.delay_between_probes {
                tokio::time::sleep(delay).await;
            }
        }

        results
    }

    /// Returns the scan technique being used
    pub fn get_technique(&self) -> ScanTechnique {
        self.engine.get_technique()
    }

    /// Returns whether the scanner requires elevated privileges
    pub fn requires_privileges(&self) -> bool {
        self.engine.is_privileged()
    }

    /// Returns the target IP address
    pub fn target(&self) -> IpAddr {
        self.target
    }

    /// Returns a reference to the scan configuration
    pub fn config(&self) -> &ScanConfig {
        &self.config
    }
}

/// Utility functions for common scanning operations
pub mod utils {
    use super::*;
    use factory::DefaultScanEngineFactory;
    use traits::ScanEngineFactory;

    /// Returns the list of scan techniques supported on the current platform
    pub fn supported_techniques() -> Vec<ScanTechnique> {
        let factory = DefaultScanEngineFactory;
        factory.supported_techniques()
    }

    /// Checks if a scan technique requires elevated privileges
    pub fn requires_privileges(technique: &ScanTechnique) -> bool {
        let factory = DefaultScanEngineFactory;
        factory.requires_privileges(technique)
    }

    /// Checks if the current platform supports raw socket operations
    pub fn is_platform_supported() -> bool {
        network::is_platform_supported()
    }

    /// Validates that the current process has the required privileges for raw socket operations
    pub fn validate_privileges() -> Result<(), StealthScanError> {
        network::check_privileges()
    }

    /// Creates a basic scan configuration for the specified technique
    pub fn create_basic_config(technique: ScanTechnique) -> ScanConfig {
        ScanConfig {
            technique,
            ..Default::default()
        }
    }

    /// Creates an aggressive scan configuration with shorter timeouts and more retries
    pub fn create_aggressive_config(technique: ScanTechnique) -> ScanConfig {
        use std::time::Duration;

        ScanConfig {
            technique,
            timeout: Duration::from_millis(1000),
            retries: 3,
            delay_between_probes: Some(Duration::from_millis(10)),
            randomize_order: true,
            ..Default::default()
        }
    }

    /// Creates a stealth scan configuration with longer timeouts and randomization
    pub fn create_stealth_config(technique: ScanTechnique) -> ScanConfig {
        use std::time::Duration;

        ScanConfig {
            technique,
            timeout: Duration::from_millis(5000),
            retries: 1,
            delay_between_probes: Some(Duration::from_millis(100)),
            randomize_order: true,
            ..Default::default()
        }
    }
}

// Re-export commonly used types and traits
pub use traits::{NetworkUtils, PacketBuilder, PacketParser, ScanEngineFactory};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn test_stealth_scanner_creation_tcp_connect() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let config = utils::create_basic_config(ScanTechnique::TcpConnect);

        let scanner = StealthScanner::new(target, config);
        assert!(scanner.is_ok());

        let scanner = scanner.unwrap();
        assert_eq!(scanner.target(), target);
        assert_eq!(scanner.get_technique(), ScanTechnique::TcpConnect);
        assert!(!scanner.requires_privileges());
    }

    #[tokio::test]
    async fn test_single_port_scan() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let config = utils::create_basic_config(ScanTechnique::TcpConnect);

        let scanner = StealthScanner::new(target, config).unwrap();
        let result = scanner.scan_port(12345).await;

        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert_eq!(scan_result.port, 12345);
        assert!(matches!(
            scan_result.state,
            PortState::Closed | PortState::Filtered
        ));
    }

    #[tokio::test]
    async fn test_multiple_port_scan() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let config = utils::create_basic_config(ScanTechnique::TcpConnect);

        let scanner = StealthScanner::new(target, config).unwrap();
        let ports = vec![12345, 12346, 12347];
        let results = scanner.scan_ports(&ports).await;

        assert_eq!(results.len(), 3);
        for (i, result) in results.iter().enumerate() {
            assert!(result.is_ok());
            let scan_result = result.as_ref().unwrap();
            assert_eq!(scan_result.port, ports[i]);
        }
    }

    #[tokio::test]
    async fn test_concurrent_port_scan() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let config = utils::create_basic_config(ScanTechnique::TcpConnect);

        let scanner = StealthScanner::new(target, config).unwrap();
        let ports = vec![12345, 12346, 12347, 12348, 12349];
        let results = scanner.scan_ports_concurrent(&ports, 3).await;

        assert_eq!(results.len(), 5);
        for (i, result) in results.iter().enumerate() {
            assert!(result.is_ok());
            // Note: Due to concurrent execution, the order might not be preserved
            let scan_result = result.as_ref().unwrap();
            assert!(ports.contains(&scan_result.port));
        }
    }

    #[test]
    fn test_utility_functions() {
        let techniques = utils::supported_techniques();
        assert!(!techniques.is_empty());
        assert!(techniques.contains(&ScanTechnique::TcpConnect));

        assert!(!utils::requires_privileges(&ScanTechnique::TcpConnect));
        assert!(utils::requires_privileges(&ScanTechnique::StealthSyn));

        // Platform support varies by OS
        let _supported = utils::is_platform_supported();
    }

    #[test]
    fn test_config_creation() {
        let basic = utils::create_basic_config(ScanTechnique::TcpConnect);
        assert_eq!(basic.technique, ScanTechnique::TcpConnect);
        assert_eq!(basic.timeout, Duration::from_millis(3000));

        let aggressive = utils::create_aggressive_config(ScanTechnique::StealthSyn);
        assert_eq!(aggressive.technique, ScanTechnique::StealthSyn);
        assert_eq!(aggressive.timeout, Duration::from_millis(1000));
        assert_eq!(aggressive.retries, 3);
        assert!(aggressive.randomize_order);

        let stealth = utils::create_stealth_config(ScanTechnique::TcpFin);
        assert_eq!(stealth.technique, ScanTechnique::TcpFin);
        assert_eq!(stealth.timeout, Duration::from_millis(5000));
        assert_eq!(stealth.retries, 1);
        assert!(stealth.randomize_order);
    }

    #[cfg(unix)]
    #[test]
    fn test_privilege_validation() {
        // This test might fail if not running with root privileges
        match utils::validate_privileges() {
            Ok(_) => {
                // Running with root privileges
                assert!(true);
            }
            Err(StealthScanError::PermissionDenied(_)) => {
                // Not running with root privileges (expected in most cases)
                assert!(true);
            }
            Err(e) => {
                panic!("Unexpected error: {:?}", e);
            }
        }
    }

    #[cfg(not(unix))]
    #[test]
    fn test_unsupported_platform_validation() {
        let result = utils::validate_privileges();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StealthScanError::UnsupportedPlatform(_)
        ));
    }
}
