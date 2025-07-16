use crate::stealth::network::{check_privileges, is_platform_supported};
use crate::stealth::scan_engines::{AdvancedScanEngine, StealthSynScanner, TcpConnectScanner};
use crate::stealth::traits::{ScanEngine, ScanEngineFactory};
use crate::stealth::types::*;
use std::net::IpAddr;

pub struct DefaultScanEngineFactory;

impl ScanEngineFactory for DefaultScanEngineFactory {
    fn create_engine(
        &self,
        technique: ScanTechnique,
        config: ScanConfig,
    ) -> Result<Box<dyn ScanEngine>, StealthScanError> {
        match technique {
            ScanTechnique::TcpConnect => Ok(Box::new(TcpConnectScanner::new(config))),
            ScanTechnique::StealthSyn => {
                if !is_platform_supported() {
                    return Err(StealthScanError::UnsupportedPlatform(
                        "Stealth SYN scan requires Unix-like platform".to_string(),
                    ));
                }

                check_privileges()?;

                // We need a target IP to create the scanner
                // This is a limitation of the current design - we might need to refactor
                return Err(StealthScanError::InvalidTarget(
                    "Target IP required for stealth scanner creation".to_string(),
                ));
            }
            _ => {
                if !is_platform_supported() {
                    return Err(StealthScanError::UnsupportedPlatform(
                        "Advanced scan techniques require Unix-like platform".to_string(),
                    ));
                }

                check_privileges()?;

                return Err(StealthScanError::InvalidTarget(
                    "Target IP required for advanced scanner creation".to_string(),
                ));
            }
        }
    }

    fn create_engine_for_target(
        &self,
        target: IpAddr,
        technique: ScanTechnique,
        config: ScanConfig,
    ) -> Result<Box<dyn ScanEngine>, StealthScanError> {
        match technique {
            ScanTechnique::TcpConnect => Ok(Box::new(TcpConnectScanner::new(config))),
            ScanTechnique::StealthSyn => {
                if !is_platform_supported() {
                    return Err(StealthScanError::UnsupportedPlatform(
                        "Stealth SYN scan requires Unix-like platform".to_string(),
                    ));
                }

                check_privileges()?;
                Ok(Box::new(StealthSynScanner::new(target, config)?))
            }
            _ => {
                if !is_platform_supported() {
                    return Err(StealthScanError::UnsupportedPlatform(
                        "Advanced scan techniques require Unix-like platform".to_string(),
                    ));
                }

                check_privileges()?;
                Ok(Box::new(AdvancedScanEngine::new(target, config)?))
            }
        }
    }

    fn supported_techniques(&self) -> Vec<ScanTechnique> {
        let mut techniques = vec![ScanTechnique::TcpConnect];

        if is_platform_supported() {
            techniques.extend_from_slice(&[
                ScanTechnique::StealthSyn,
                ScanTechnique::TcpAck,
                ScanTechnique::TcpFin,
                ScanTechnique::TcpNull,
                ScanTechnique::TcpXmas,
            ]);
        }

        techniques
    }

    fn requires_privileges(&self, technique: &ScanTechnique) -> bool {
        !matches!(technique, ScanTechnique::TcpConnect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn test_factory_supported_techniques() {
        let factory = DefaultScanEngineFactory;
        let techniques = factory.supported_techniques();

        assert!(techniques.contains(&ScanTechnique::TcpConnect));

        #[cfg(unix)]
        {
            assert!(techniques.contains(&ScanTechnique::StealthSyn));
            assert!(techniques.contains(&ScanTechnique::TcpAck));
            assert!(techniques.contains(&ScanTechnique::TcpFin));
            assert!(techniques.contains(&ScanTechnique::TcpNull));
            assert!(techniques.contains(&ScanTechnique::TcpXmas));
        }
    }

    #[test]
    fn test_factory_privilege_requirements() {
        let factory = DefaultScanEngineFactory;

        assert!(!factory.requires_privileges(&ScanTechnique::TcpConnect));
        assert!(factory.requires_privileges(&ScanTechnique::StealthSyn));
        assert!(factory.requires_privileges(&ScanTechnique::TcpAck));
        assert!(factory.requires_privileges(&ScanTechnique::TcpFin));
        assert!(factory.requires_privileges(&ScanTechnique::TcpNull));
        assert!(factory.requires_privileges(&ScanTechnique::TcpXmas));
    }

    #[test]
    fn test_tcp_connect_engine_creation() {
        let factory = DefaultScanEngineFactory;
        let config = ScanConfig {
            timeout: Duration::from_millis(1000),
            technique: ScanTechnique::TcpConnect,
            ..Default::default()
        };

        let result = factory.create_engine(ScanTechnique::TcpConnect, config);
        assert!(result.is_ok());

        let engine = result.unwrap();
        assert_eq!(engine.get_technique(), ScanTechnique::TcpConnect);
        assert!(!engine.is_privileged());
    }

    #[test]
    fn test_target_specific_engine_creation() {
        let factory = DefaultScanEngineFactory;
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let config = ScanConfig {
            timeout: Duration::from_millis(1000),
            technique: ScanTechnique::TcpConnect,
            ..Default::default()
        };

        let result = factory.create_engine_for_target(target, ScanTechnique::TcpConnect, config);
        assert!(result.is_ok());
    }

    #[cfg(not(unix))]
    #[test]
    fn test_unsupported_platform_error() {
        let factory = DefaultScanEngineFactory;
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let config = ScanConfig {
            timeout: Duration::from_millis(1000),
            technique: ScanTechnique::StealthSyn,
            ..Default::default()
        };

        let result = factory.create_engine_for_target(target, ScanTechnique::StealthSyn, config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StealthScanError::UnsupportedPlatform(_)
        ));
    }
}
