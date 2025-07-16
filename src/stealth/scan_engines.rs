use crate::stealth::network::{RawSocketManager, TcpConnector};
use crate::stealth::packet_builder::{Ipv4PacketBuilder, Ipv6PacketBuilder, TcpPacket};
use crate::stealth::packet_parser::TcpPacketParser;
use crate::stealth::traits::{NetworkUtils, PacketBuilder, PacketParser, ScanEngine};
use crate::stealth::types::*;
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;
use tokio::time::timeout;

pub struct StealthSynScanner {
    config: ScanConfig,
    packet_builder: Box<dyn PacketBuilder<Packet = TcpPacket> + Send + Sync>,
    packet_parser: Box<dyn PacketParser + Send + Sync>,
    network_utils: Arc<dyn NetworkUtils + Send + Sync>,
    target: IpAddr,
}

impl std::fmt::Debug for StealthSynScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StealthSynScanner")
            .field("target", &self.target)
            .field("config", &self.config)
            .finish()
    }
}

impl StealthSynScanner {
    pub fn new(target: IpAddr, config: ScanConfig) -> Result<Self, StealthScanError> {
        let packet_builder: Box<dyn PacketBuilder<Packet = TcpPacket> + Send + Sync> = match target
        {
            IpAddr::V4(dest_ip) => {
                let source_ip = get_local_ipv4(dest_ip)?;
                Box::new(Ipv4PacketBuilder::new(source_ip, dest_ip))
            }
            IpAddr::V6(dest_ip) => {
                let source_ip = get_local_ipv6(dest_ip)?;
                Box::new(Ipv6PacketBuilder::new(source_ip, dest_ip))
            }
        };

        let packet_parser = Box::new(TcpPacketParser::new(target));
        let network_utils = Arc::new(RawSocketManager::new(target)?);

        Ok(Self {
            config,
            packet_builder,
            packet_parser,
            network_utils,
            target,
        })
    }
}

#[async_trait]
impl ScanEngine for StealthSynScanner {
    async fn scan_port(
        &self,
        target: IpAddr,
        port: u16,
    ) -> Result<StealthScanResult, StealthScanError> {
        if target != self.target {
            return Err(StealthScanError::InvalidTarget(
                "Target IP mismatch".to_string(),
            ));
        }

        let start_time = Instant::now();

        // Build SYN packet
        let packet = self.packet_builder.build_syn_packet(port)?;

        // Send packet with retries
        let mut last_error = None;
        for attempt in 0..=self.config.retries {
            match self.send_and_receive_response(target, port, &packet).await {
                Ok(response) => {
                    let elapsed = start_time.elapsed();
                    let parsed = self.packet_parser.parse_response(&response, port)?;

                    return Ok(StealthScanResult {
                        port,
                        state: parsed.port_state,
                        response_time: elapsed,
                        metadata: ScanMetadata {
                            ttl: parsed.ttl,
                            window_size: parsed.window_size,
                            tcp_flags: parsed.tcp_flags,
                            sequence_number: parsed.sequence_number,
                            acknowledgment_number: parsed.acknowledgment_number,
                            scan_technique: ScanTechnique::StealthSyn,
                        },
                    });
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.config.retries {
                        if let Some(delay) = self.config.delay_between_probes {
                            tokio::time::sleep(delay).await;
                        }
                    }
                }
            }
        }

        // All retries failed
        let elapsed = start_time.elapsed();
        Ok(StealthScanResult {
            port,
            state: PortState::Unknown,
            response_time: elapsed,
            metadata: ScanMetadata {
                ttl: None,
                window_size: None,
                tcp_flags: None,
                sequence_number: None,
                acknowledgment_number: None,
                scan_technique: ScanTechnique::StealthSyn,
            },
        })
    }

    fn get_technique(&self) -> ScanTechnique {
        ScanTechnique::StealthSyn
    }

    fn is_privileged(&self) -> bool {
        true
    }
}

impl StealthSynScanner {
    async fn send_and_receive_response(
        &self,
        target: IpAddr,
        port: u16,
        packet: &TcpPacket,
    ) -> Result<Vec<u8>, StealthScanError> {
        // Send packet
        self.network_utils
            .send_packet(&packet.data, target, port)
            .await?;

        // Receive response
        match timeout(
            self.config.timeout,
            self.network_utils.receive_response(self.config.timeout),
        )
        .await
        {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(StealthScanError::Timeout(self.config.timeout)),
        }
    }
}

#[derive(Debug)]
pub struct TcpConnectScanner {
    config: ScanConfig,
    connector: TcpConnector,
}

impl TcpConnectScanner {
    pub fn new(config: ScanConfig) -> Self {
        Self {
            connector: TcpConnector::new(),
            config,
        }
    }
}

#[async_trait]
impl ScanEngine for TcpConnectScanner {
    async fn scan_port(
        &self,
        target: IpAddr,
        port: u16,
    ) -> Result<StealthScanResult, StealthScanError> {
        let start_time = Instant::now();

        let result = self
            .connector
            .connect(target, port, self.config.timeout)
            .await;
        let elapsed = start_time.elapsed();

        let state = match result {
            Ok(_) => PortState::Open,
            Err(e) => match e.kind() {
                std::io::ErrorKind::ConnectionRefused => PortState::Closed,
                std::io::ErrorKind::TimedOut => PortState::Filtered,
                _ => PortState::Unknown,
            },
        };

        Ok(StealthScanResult {
            port,
            state,
            response_time: elapsed,
            metadata: ScanMetadata {
                ttl: None,
                window_size: None,
                tcp_flags: None,
                sequence_number: None,
                acknowledgment_number: None,
                scan_technique: ScanTechnique::TcpConnect,
            },
        })
    }

    fn get_technique(&self) -> ScanTechnique {
        ScanTechnique::TcpConnect
    }

    fn is_privileged(&self) -> bool {
        false
    }
}

pub struct AdvancedScanEngine {
    config: ScanConfig,
    packet_builder: Box<dyn PacketBuilder<Packet = TcpPacket> + Send + Sync>,
    packet_parser: Box<dyn PacketParser + Send + Sync>,
    network_utils: Arc<dyn NetworkUtils + Send + Sync>,
    target: IpAddr,
}

impl std::fmt::Debug for AdvancedScanEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdvancedScanEngine")
            .field("target", &self.target)
            .field("config", &self.config)
            .finish()
    }
}

impl AdvancedScanEngine {
    pub fn new(target: IpAddr, config: ScanConfig) -> Result<Self, StealthScanError> {
        let packet_builder: Box<dyn PacketBuilder<Packet = TcpPacket> + Send + Sync> = match target
        {
            IpAddr::V4(dest_ip) => {
                let source_ip = get_local_ipv4(dest_ip)?;
                Box::new(Ipv4PacketBuilder::new(source_ip, dest_ip))
            }
            IpAddr::V6(dest_ip) => {
                let source_ip = get_local_ipv6(dest_ip)?;
                Box::new(Ipv6PacketBuilder::new(source_ip, dest_ip))
            }
        };

        let packet_parser = Box::new(TcpPacketParser::new(target));
        let network_utils = Arc::new(RawSocketManager::new(target)?);

        Ok(Self {
            config,
            packet_builder,
            packet_parser,
            network_utils,
            target,
        })
    }

    async fn scan_with_technique(
        &self,
        port: u16,
        technique: ScanTechnique,
    ) -> Result<StealthScanResult, StealthScanError> {
        let start_time = Instant::now();

        let packet = match technique {
            ScanTechnique::StealthSyn => self.packet_builder.build_syn_packet(port)?,
            ScanTechnique::TcpAck => self.packet_builder.build_ack_packet(port, 0)?,
            ScanTechnique::TcpFin => self.packet_builder.build_fin_packet(port)?,
            ScanTechnique::TcpNull => self.packet_builder.build_null_packet(port)?,
            ScanTechnique::TcpXmas => self.packet_builder.build_xmas_packet(port)?,
            ScanTechnique::TcpConnect => {
                return Err(StealthScanError::UnsupportedPlatform(
                    "TCP Connect not supported by AdvancedScanEngine".to_string(),
                ));
            }
        };

        // Send packet
        self.network_utils
            .send_packet(&packet.data, self.target, port)
            .await?;

        // Receive response
        let response = match timeout(
            self.config.timeout,
            self.network_utils.receive_response(self.config.timeout),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => return Err(e),
            Err(_) => Vec::new(), // Timeout, treat as no response
        };

        let elapsed = start_time.elapsed();
        let parsed = self.packet_parser.parse_response(&response, port)?;

        Ok(StealthScanResult {
            port,
            state: parsed.port_state,
            response_time: elapsed,
            metadata: ScanMetadata {
                ttl: parsed.ttl,
                window_size: parsed.window_size,
                tcp_flags: parsed.tcp_flags,
                sequence_number: parsed.sequence_number,
                acknowledgment_number: parsed.acknowledgment_number,
                scan_technique: technique,
            },
        })
    }
}

#[async_trait]
impl ScanEngine for AdvancedScanEngine {
    async fn scan_port(
        &self,
        target: IpAddr,
        port: u16,
    ) -> Result<StealthScanResult, StealthScanError> {
        if target != self.target {
            return Err(StealthScanError::InvalidTarget(
                "Target IP mismatch".to_string(),
            ));
        }

        self.scan_with_technique(port, self.config.technique.clone())
            .await
    }

    fn get_technique(&self) -> ScanTechnique {
        self.config.technique.clone()
    }

    fn is_privileged(&self) -> bool {
        !matches!(self.config.technique, ScanTechnique::TcpConnect)
    }
}

// Utility functions for getting local IP addresses
fn get_local_ipv4(dest_ip: Ipv4Addr) -> Result<Ipv4Addr, StealthScanError> {
    use std::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| {
        StealthScanError::NetworkError(format!("Failed to bind IPv4 socket: {}", e))
    })?;

    socket.connect((dest_ip, 80)).map_err(|e| {
        StealthScanError::NetworkError(format!("Failed to connect to IPv4 address: {}", e))
    })?;

    let local_addr = socket.local_addr().map_err(|e| {
        StealthScanError::NetworkError(format!("Failed to get local IPv4 address: {}", e))
    })?;

    match local_addr.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(StealthScanError::IpVersionMismatch {
            expected: "IPv4".to_string(),
            actual: "IPv6".to_string(),
        }),
    }
}

fn get_local_ipv6(dest_ip: Ipv6Addr) -> Result<Ipv6Addr, StealthScanError> {
    use std::net::UdpSocket;

    let socket = UdpSocket::bind("[::]:0").map_err(|e| {
        StealthScanError::NetworkError(format!("Failed to bind IPv6 socket: {}", e))
    })?;

    socket.connect((dest_ip, 80)).map_err(|e| {
        StealthScanError::NetworkError(format!("Failed to connect to IPv6 address: {}", e))
    })?;

    let local_addr = socket.local_addr().map_err(|e| {
        StealthScanError::NetworkError(format!("Failed to get local IPv6 address: {}", e))
    })?;

    match local_addr.ip() {
        IpAddr::V6(ip) => Ok(ip),
        IpAddr::V4(_) => Err(StealthScanError::IpVersionMismatch {
            expected: "IPv6".to_string(),
            actual: "IPv4".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_tcp_connect_scanner_creation() {
        let config = ScanConfig {
            timeout: Duration::from_millis(1000),
            technique: ScanTechnique::TcpConnect,
            ..Default::default()
        };

        let scanner = TcpConnectScanner::new(config);
        assert_eq!(scanner.get_technique(), ScanTechnique::TcpConnect);
        assert!(!scanner.is_privileged());
    }

    #[tokio::test]
    async fn test_tcp_connect_scanner_localhost() {
        let config = ScanConfig {
            timeout: Duration::from_millis(1000),
            technique: ScanTechnique::TcpConnect,
            ..Default::default()
        };

        let scanner = TcpConnectScanner::new(config);
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Test a port that's likely closed
        let result = scanner.scan_port(target, 12345).await.unwrap();
        assert!(matches!(
            result.state,
            PortState::Closed | PortState::Filtered
        ));
    }

    #[test]
    fn test_get_local_ipv4() {
        let dest = Ipv4Addr::new(8, 8, 8, 8);
        let local_ip = get_local_ipv4(dest);
        assert!(local_ip.is_ok());
        assert!(!local_ip.unwrap().is_unspecified());
    }
}
