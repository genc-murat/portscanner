use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
            PortState::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthScanResult {
    pub port: u16,
    pub state: PortState,
    pub response_time: Duration,
    pub metadata: ScanMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub ttl: Option<u8>,
    pub window_size: Option<u16>,
    pub tcp_flags: Option<u8>,
    pub sequence_number: Option<u32>,
    pub acknowledgment_number: Option<u32>,
    pub scan_technique: ScanTechnique,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScanTechnique {
    TcpConnect,
    StealthSyn,
    TcpAck,
    TcpFin,
    TcpNull,
    TcpXmas,
}

impl fmt::Display for ScanTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanTechnique::TcpConnect => write!(f, "TCP Connect"),
            ScanTechnique::StealthSyn => write!(f, "Stealth SYN"),
            ScanTechnique::TcpAck => write!(f, "TCP ACK"),
            ScanTechnique::TcpFin => write!(f, "TCP FIN"),
            ScanTechnique::TcpNull => write!(f, "TCP NULL"),
            ScanTechnique::TcpXmas => write!(f, "TCP Xmas"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub timeout: Duration,
    pub retries: u8,
    pub source_port_range: Option<(u16, u16)>,
    pub randomize_order: bool,
    pub delay_between_probes: Option<Duration>,
    pub technique: ScanTechnique,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(3000),
            retries: 2,
            source_port_range: Some((1024, 65535)),
            randomize_order: false,
            delay_between_probes: None,
            technique: ScanTechnique::StealthSyn,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StealthScanError {
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Timeout occurred after {0:?}")]
    Timeout(Duration),

    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    #[error("Unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("Raw socket creation failed: {0}")]
    RawSocketError(String),

    #[error("Packet parsing error: {0}")]
    PacketParsingError(String),

    #[error("IP version mismatch: expected {expected}, got {actual}")]
    IpVersionMismatch { expected: String, actual: String },
}

// Add Clone implementation for StealthScanError to make it easier to work with
impl Clone for StealthScanError {
    fn clone(&self) -> Self {
        match self {
            StealthScanError::PermissionDenied(msg) => {
                StealthScanError::PermissionDenied(msg.clone())
            }
            StealthScanError::NetworkError(msg) => StealthScanError::NetworkError(msg.clone()),
            StealthScanError::Timeout(duration) => StealthScanError::Timeout(*duration),
            StealthScanError::InvalidTarget(msg) => StealthScanError::InvalidTarget(msg.clone()),
            StealthScanError::UnsupportedPlatform(msg) => {
                StealthScanError::UnsupportedPlatform(msg.clone())
            }
            StealthScanError::RawSocketError(msg) => StealthScanError::RawSocketError(msg.clone()),
            StealthScanError::PacketParsingError(msg) => {
                StealthScanError::PacketParsingError(msg.clone())
            }
            StealthScanError::IpVersionMismatch { expected, actual } => {
                StealthScanError::IpVersionMismatch {
                    expected: expected.clone(),
                    actual: actual.clone(),
                }
            }
        }
    }
}
