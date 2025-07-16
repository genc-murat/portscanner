use crate::stealth::traits::PacketBuilder;
use crate::stealth::types::StealthScanError;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct TcpPacket {
    pub data: Vec<u8>,
    pub total_length: usize,
}

pub struct Ipv4PacketBuilder {
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
}

pub struct Ipv6PacketBuilder {
    source_ip: Ipv6Addr,
    dest_ip: Ipv6Addr,
}

impl Ipv4PacketBuilder {
    pub fn new(source_ip: Ipv4Addr, dest_ip: Ipv4Addr) -> Self {
        Self { source_ip, dest_ip }
    }

    fn build_ip_header(&self, tcp_len: u16) -> Vec<u8> {
        let mut header = vec![0u8; 20];

        // Version (4) + IHL (5) = 0x45
        header[0] = 0x45;
        // Type of Service
        header[1] = 0x00;
        // Total Length
        let total_len: u16 = 20 + tcp_len;
        header[2..4].copy_from_slice(&total_len.to_be_bytes());

        // Identification
        let mut rng = rand::thread_rng();
        let id: u16 = rng.gen_range(1..65535);
        header[4..6].copy_from_slice(&id.to_be_bytes());

        // Flags + Fragment Offset (Don't Fragment = 0x4000)
        header[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        // TTL
        header[8] = 64;
        // Protocol (TCP = 6)
        header[9] = 6;
        // Checksum (will be calculated later)
        header[10..12].copy_from_slice(&0u16.to_be_bytes());
        // Source IP
        header[12..16].copy_from_slice(&self.source_ip.octets());
        // Destination IP
        header[16..20].copy_from_slice(&self.dest_ip.octets());

        // Calculate and set checksum
        let checksum = calculate_checksum(&header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());

        header
    }

    fn build_tcp_header(&self, dest_port: u16, flags: u8) -> Result<Vec<u8>, StealthScanError> {
        let mut header = vec![0u8; 20];
        let mut rng = rand::thread_rng();

        // Source Port (random)
        let src_port: u16 = rng.gen_range(1024..65535);
        header[0..2].copy_from_slice(&src_port.to_be_bytes());

        // Destination Port
        header[2..4].copy_from_slice(&dest_port.to_be_bytes());

        // Sequence Number (random)
        let seq_num: u32 = rng.gen_range(1..u32::MAX);
        header[4..8].copy_from_slice(&seq_num.to_be_bytes());

        // Acknowledgment Number (0 for SYN)
        header[8..12].copy_from_slice(&0u32.to_be_bytes());

        // Data Offset (5) + Reserved (0) = 0x50
        header[12] = 0x50;

        // TCP Flags
        header[13] = flags;

        // Window Size
        header[14..16].copy_from_slice(&8192u16.to_be_bytes());

        // Checksum (will be calculated)
        header[16..18].copy_from_slice(&0u16.to_be_bytes());

        // Urgent Pointer
        header[18..20].copy_from_slice(&0u16.to_be_bytes());

        // Calculate TCP checksum
        let checksum = self.calculate_tcp_checksum(&header, src_port, dest_port)?;
        header[16..18].copy_from_slice(&checksum.to_be_bytes());

        Ok(header)
    }

    fn calculate_tcp_checksum(
        &self,
        tcp_header: &[u8],
        _src_port: u16,
        _dest_port: u16,
    ) -> Result<u16, StealthScanError> {
        let mut pseudo_header = Vec::new();

        // Source IP
        pseudo_header.extend_from_slice(&self.source_ip.octets());
        // Destination IP
        pseudo_header.extend_from_slice(&self.dest_ip.octets());
        // Reserved byte
        pseudo_header.push(0);
        // Protocol (TCP = 6)
        pseudo_header.push(6);
        // TCP Length
        pseudo_header.extend_from_slice(&(tcp_header.len() as u16).to_be_bytes());
        // TCP Header
        pseudo_header.extend_from_slice(tcp_header);

        Ok(calculate_checksum(&pseudo_header))
    }
}

impl PacketBuilder for Ipv4PacketBuilder {
    type Packet = TcpPacket;

    fn build_syn_packet(&self, dest_port: u16) -> Result<Self::Packet, StealthScanError> {
        let tcp_header = self.build_tcp_header(dest_port, 0x02)?; // SYN flag
        let ip_header = self.build_ip_header(tcp_header.len() as u16);

        let mut data = Vec::new();
        data.extend_from_slice(&ip_header);
        data.extend_from_slice(&tcp_header);

        Ok(TcpPacket {
            total_length: data.len(),
            data,
        })
    }

    fn build_ack_packet(
        &self,
        dest_port: u16,
        _seq: u32,
    ) -> Result<Self::Packet, StealthScanError> {
        let tcp_header = self.build_tcp_header(dest_port, 0x10)?; // ACK flag
        let ip_header = self.build_ip_header(tcp_header.len() as u16);

        let mut data = Vec::new();
        data.extend_from_slice(&ip_header);
        data.extend_from_slice(&tcp_header);

        Ok(TcpPacket {
            total_length: data.len(),
            data,
        })
    }

    fn build_fin_packet(&self, dest_port: u16) -> Result<Self::Packet, StealthScanError> {
        let tcp_header = self.build_tcp_header(dest_port, 0x01)?; // FIN flag
        let ip_header = self.build_ip_header(tcp_header.len() as u16);

        let mut data = Vec::new();
        data.extend_from_slice(&ip_header);
        data.extend_from_slice(&tcp_header);

        Ok(TcpPacket {
            total_length: data.len(),
            data,
        })
    }

    fn build_null_packet(&self, dest_port: u16) -> Result<Self::Packet, StealthScanError> {
        let tcp_header = self.build_tcp_header(dest_port, 0x00)?; // No flags
        let ip_header = self.build_ip_header(tcp_header.len() as u16);

        let mut data = Vec::new();
        data.extend_from_slice(&ip_header);
        data.extend_from_slice(&tcp_header);

        Ok(TcpPacket {
            total_length: data.len(),
            data,
        })
    }

    fn build_xmas_packet(&self, dest_port: u16) -> Result<Self::Packet, StealthScanError> {
        let tcp_header = self.build_tcp_header(dest_port, 0x29)?; // FIN + PSH + URG flags
        let ip_header = self.build_ip_header(tcp_header.len() as u16);

        let mut data = Vec::new();
        data.extend_from_slice(&ip_header);
        data.extend_from_slice(&tcp_header);

        Ok(TcpPacket {
            total_length: data.len(),
            data,
        })
    }
}

impl Ipv6PacketBuilder {
    pub fn new(source_ip: Ipv6Addr, dest_ip: Ipv6Addr) -> Self {
        Self { source_ip, dest_ip }
    }

    fn build_tcp_header(&self, dest_port: u16, flags: u8) -> Result<Vec<u8>, StealthScanError> {
        let mut header = vec![0u8; 20];
        let mut rng = rand::thread_rng();

        // Source Port (random)
        let src_port: u16 = rng.gen_range(1024..65535);
        header[0..2].copy_from_slice(&src_port.to_be_bytes());

        // Destination Port
        header[2..4].copy_from_slice(&dest_port.to_be_bytes());

        // Sequence Number (random)
        let seq_num: u32 = rng.gen_range(1..u32::MAX);
        header[4..8].copy_from_slice(&seq_num.to_be_bytes());

        // Acknowledgment Number
        header[8..12].copy_from_slice(&0u32.to_be_bytes());

        // Data Offset + Reserved
        header[12] = 0x50;

        // TCP Flags
        header[13] = flags;

        // Window Size
        header[14..16].copy_from_slice(&8192u16.to_be_bytes());

        // Checksum (will be calculated)
        header[16..18].copy_from_slice(&0u16.to_be_bytes());

        // Urgent Pointer
        header[18..20].copy_from_slice(&0u16.to_be_bytes());

        // Calculate IPv6 TCP checksum
        let checksum = self.calculate_tcp_checksum(&header)?;
        header[16..18].copy_from_slice(&checksum.to_be_bytes());

        Ok(header)
    }

    fn calculate_tcp_checksum(&self, tcp_header: &[u8]) -> Result<u16, StealthScanError> {
        let mut pseudo_header = Vec::new();

        // Source IPv6 Address (16 bytes)
        pseudo_header.extend_from_slice(&self.source_ip.octets());
        // Destination IPv6 Address (16 bytes)
        pseudo_header.extend_from_slice(&self.dest_ip.octets());
        // TCP Length (4 bytes)
        let tcp_len = tcp_header.len() as u32;
        pseudo_header.extend_from_slice(&tcp_len.to_be_bytes());
        // Zeros (3 bytes) + Next Header (1 byte = TCP = 6)
        pseudo_header.extend_from_slice(&[0, 0, 0, 6]);
        // TCP Header
        pseudo_header.extend_from_slice(tcp_header);

        Ok(calculate_checksum(&pseudo_header))
    }
}

impl PacketBuilder for Ipv6PacketBuilder {
    type Packet = TcpPacket;

    fn build_syn_packet(&self, dest_port: u16) -> Result<Self::Packet, StealthScanError> {
        let tcp_header = self.build_tcp_header(dest_port, 0x02)?; // SYN flag

        Ok(TcpPacket {
            total_length: tcp_header.len(),
            data: tcp_header,
        })
    }

    fn build_ack_packet(
        &self,
        dest_port: u16,
        _seq: u32,
    ) -> Result<Self::Packet, StealthScanError> {
        let tcp_header = self.build_tcp_header(dest_port, 0x10)?; // ACK flag

        Ok(TcpPacket {
            total_length: tcp_header.len(),
            data: tcp_header,
        })
    }

    fn build_fin_packet(&self, dest_port: u16) -> Result<Self::Packet, StealthScanError> {
        let tcp_header = self.build_tcp_header(dest_port, 0x01)?; // FIN flag

        Ok(TcpPacket {
            total_length: tcp_header.len(),
            data: tcp_header,
        })
    }

    fn build_null_packet(&self, dest_port: u16) -> Result<Self::Packet, StealthScanError> {
        let tcp_header = self.build_tcp_header(dest_port, 0x00)?; // No flags

        Ok(TcpPacket {
            total_length: tcp_header.len(),
            data: tcp_header,
        })
    }

    fn build_xmas_packet(&self, dest_port: u16) -> Result<Self::Packet, StealthScanError> {
        let tcp_header = self.build_tcp_header(dest_port, 0x29)?; // FIN + PSH + URG flags

        Ok(TcpPacket {
            total_length: tcp_header.len(),
            data: tcp_header,
        })
    }
}

// Utility function for checksum calculation
pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i < data.len() - 1 {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }

    // Add any remaining byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold carry bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}
