use crate::stealth::types::*;
use async_trait::async_trait;
use std::net::IpAddr;

/// Trait for different scanning implementations
#[async_trait]
pub trait ScanEngine: Send + Sync + std::fmt::Debug {
    async fn scan_port(
        &self,
        target: IpAddr,
        port: u16,
    ) -> Result<StealthScanResult, StealthScanError>;

    async fn scan_ports(
        &self,
        target: IpAddr,
        ports: &[u16],
    ) -> Vec<Result<StealthScanResult, StealthScanError>> {
        let mut results = Vec::new();
        for &port in ports {
            results.push(self.scan_port(target, port).await);
        }
        results
    }

    fn get_technique(&self) -> ScanTechnique;
    fn is_privileged(&self) -> bool;
}

/// Trait for packet builders
pub trait PacketBuilder: Send + Sync {
    type Packet;

    fn build_syn_packet(&self, dest_port: u16) -> Result<Self::Packet, StealthScanError>;
    fn build_ack_packet(&self, dest_port: u16, seq: u32) -> Result<Self::Packet, StealthScanError>;
    fn build_fin_packet(&self, dest_port: u16) -> Result<Self::Packet, StealthScanError>;
    fn build_null_packet(&self, dest_port: u16) -> Result<Self::Packet, StealthScanError>;
    fn build_xmas_packet(&self, dest_port: u16) -> Result<Self::Packet, StealthScanError>;
}

/// Trait for packet parsers
pub trait PacketParser: Send + Sync {
    fn parse_response(
        &self,
        data: &[u8],
        target_port: u16,
    ) -> Result<ParsedResponse, StealthScanError>;
}

/// Trait for network utilities
#[async_trait]
pub trait NetworkUtils: Send + Sync {
    async fn get_local_ip(&self, target: IpAddr) -> Result<IpAddr, StealthScanError>;
    async fn send_packet(
        &self,
        packet: &[u8],
        target: IpAddr,
        port: u16,
    ) -> Result<(), StealthScanError>;
    async fn receive_response(
        &self,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, StealthScanError>;
}

#[derive(Debug, Clone)]
pub struct ParsedResponse {
    pub port_state: PortState,
    pub tcp_flags: Option<u8>,
    pub ttl: Option<u8>,
    pub window_size: Option<u16>,
    pub sequence_number: Option<u32>,
    pub acknowledgment_number: Option<u32>,
}

/// Factory trait for creating scan engines
pub trait ScanEngineFactory {
    fn create_engine(
        &self,
        technique: ScanTechnique,
        config: ScanConfig,
    ) -> Result<Box<dyn ScanEngine>, StealthScanError>;

    fn create_engine_for_target(
        &self,
        target: IpAddr,
        technique: ScanTechnique,
        config: ScanConfig,
    ) -> Result<Box<dyn ScanEngine>, StealthScanError>;

    fn supported_techniques(&self) -> Vec<ScanTechnique>;
    fn requires_privileges(&self, technique: &ScanTechnique) -> bool;
}
