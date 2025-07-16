use crate::stealth::traits::{PacketParser, ParsedResponse};
use crate::stealth::types::{PortState, StealthScanError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct TcpPacketParser {
    target_ip: IpAddr,
}

impl TcpPacketParser {
    pub fn new(target_ip: IpAddr) -> Self {
        Self { target_ip }
    }

    fn parse_ipv4_packet(
        &self,
        data: &[u8],
        target_port: u16,
    ) -> Result<ParsedResponse, StealthScanError> {
        if data.len() < 40 {
            return Err(StealthScanError::PacketParsingError(
                "Packet too short for IPv4 + TCP".to_string(),
            ));
        }

        // Parse IP header
        let ip_header_len = ((data[0] & 0x0F) * 4) as usize;
        if data.len() < ip_header_len + 20 {
            return Err(StealthScanError::PacketParsingError(
                "Packet too short for TCP header".to_string(),
            ));
        }

        let tcp_start = ip_header_len;
        let ttl = Some(data[8]);

        self.parse_tcp_header(&data[tcp_start..], target_port, ttl)
    }

    fn parse_ipv6_packet(
        &self,
        data: &[u8],
        target_port: u16,
    ) -> Result<ParsedResponse, StealthScanError> {
        if data.len() < 60 {
            return Err(StealthScanError::PacketParsingError(
                "Packet too short for IPv6 + TCP".to_string(),
            ));
        }

        // IPv6 header is fixed 40 bytes
        let ipv6_header_len = 40;

        // Check if it's a TCP packet (Next Header = 6)
        let next_header = data[6];
        if next_header != 6 {
            return Err(StealthScanError::PacketParsingError(
                "Not a TCP packet".to_string(),
            ));
        }

        // IPv6 doesn't have TTL, it has Hop Limit
        let hop_limit = Some(data[7]);

        self.parse_tcp_header(&data[ipv6_header_len..], target_port, hop_limit)
    }

    fn parse_tcp_header(
        &self,
        tcp_data: &[u8],
        target_port: u16,
        ttl: Option<u8>,
    ) -> Result<ParsedResponse, StealthScanError> {
        if tcp_data.len() < 20 {
            return Err(StealthScanError::PacketParsingError(
                "TCP header too short".to_string(),
            ));
        }

        let src_port = u16::from_be_bytes([tcp_data[0], tcp_data[1]]);

        // Verify this response is for our target port
        if src_port != target_port {
            return Err(StealthScanError::PacketParsingError(format!(
                "Port mismatch: expected {}, got {}",
                target_port, src_port
            )));
        }

        let sequence_number = Some(u32::from_be_bytes([
            tcp_data[4],
            tcp_data[5],
            tcp_data[6],
            tcp_data[7],
        ]));

        let acknowledgment_number = Some(u32::from_be_bytes([
            tcp_data[8],
            tcp_data[9],
            tcp_data[10],
            tcp_data[11],
        ]));

        let tcp_flags = Some(tcp_data[13]);
        let window_size = Some(u16::from_be_bytes([tcp_data[14], tcp_data[15]]));

        let port_state = self.determine_port_state(tcp_flags.unwrap());

        Ok(ParsedResponse {
            port_state,
            tcp_flags,
            ttl,
            window_size,
            sequence_number,
            acknowledgment_number,
        })
    }

    fn determine_port_state(&self, flags: u8) -> PortState {
        // TCP flags: CWR ECE URG ACK PSH RST SYN FIN
        //           128  64  32  16   8   4   2   1

        if flags & 0x12 == 0x12 {
            // SYN + ACK = Open port
            PortState::Open
        } else if flags & 0x04 == 0x04 {
            // RST flag = Closed port
            PortState::Closed
        } else if flags & 0x14 == 0x14 {
            // RST + ACK = Closed port (response to ACK scan)
            PortState::Closed
        } else if flags & 0x10 == 0x10 {
            // ACK only (for ACK scan) = Unfiltered
            PortState::Unknown
        } else {
            // No response or unexpected flags = Filtered
            PortState::Filtered
        }
    }
}

impl PacketParser for TcpPacketParser {
    fn parse_response(
        &self,
        data: &[u8],
        target_port: u16,
    ) -> Result<ParsedResponse, StealthScanError> {
        if data.is_empty() {
            return Ok(ParsedResponse {
                port_state: PortState::Filtered,
                tcp_flags: None,
                ttl: None,
                window_size: None,
                sequence_number: None,
                acknowledgment_number: None,
            });
        }

        // Determine IP version from the first nibble
        let version = (data[0] & 0xF0) >> 4;

        match version {
            4 => self.parse_ipv4_packet(data, target_port),
            6 => self.parse_ipv6_packet(data, target_port),
            _ => Err(StealthScanError::PacketParsingError(format!(
                "Unsupported IP version: {}",
                version
            ))),
        }
    }
}

pub struct IcmpPacketParser {
    target_ip: IpAddr,
}

impl IcmpPacketParser {
    pub fn new(target_ip: IpAddr) -> Self {
        Self { target_ip }
    }

    fn parse_icmp_unreachable(
        &self,
        data: &[u8],
        target_port: u16,
    ) -> Result<ParsedResponse, StealthScanError> {
        // ICMP Destination Unreachable parsing
        if data.len() < 28 {
            return Err(StealthScanError::PacketParsingError(
                "ICMP packet too short".to_string(),
            ));
        }

        let icmp_type = data[20]; // After IP header
        let icmp_code = data[21];

        match icmp_type {
            3 => {
                // Destination Unreachable
                match icmp_code {
                    3 => {
                        // Port Unreachable
                        Ok(ParsedResponse {
                            port_state: PortState::Closed,
                            tcp_flags: None,
                            ttl: Some(data[8]),
                            window_size: None,
                            sequence_number: None,
                            acknowledgment_number: None,
                        })
                    }
                    1 | 2 | 9 | 10 | 13 => {
                        // Host/Network/Communication Administratively Prohibited
                        Ok(ParsedResponse {
                            port_state: PortState::Filtered,
                            tcp_flags: None,
                            ttl: Some(data[8]),
                            window_size: None,
                            sequence_number: None,
                            acknowledgment_number: None,
                        })
                    }
                    _ => {
                        // Other unreachable codes
                        Ok(ParsedResponse {
                            port_state: PortState::Unknown,
                            tcp_flags: None,
                            ttl: Some(data[8]),
                            window_size: None,
                            sequence_number: None,
                            acknowledgment_number: None,
                        })
                    }
                }
            }
            _ => Err(StealthScanError::PacketParsingError(format!(
                "Unsupported ICMP type: {}",
                icmp_type
            ))),
        }
    }
}

impl PacketParser for IcmpPacketParser {
    fn parse_response(
        &self,
        data: &[u8],
        target_port: u16,
    ) -> Result<ParsedResponse, StealthScanError> {
        self.parse_icmp_unreachable(data, target_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_tcp_parser_syn_ack_response() {
        let parser = TcpPacketParser::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        // Mock TCP packet with SYN+ACK flags (0x12)
        let mut packet = vec![0u8; 40];

        // IP header
        packet[0] = 0x45; // Version + IHL
        packet[8] = 64; // TTL

        // TCP header starts at offset 20
        packet[20..22].copy_from_slice(&80u16.to_be_bytes()); // Source port
        packet[33] = 0x12; // SYN + ACK flags
        packet[34..36].copy_from_slice(&8192u16.to_be_bytes()); // Window size

        let result = parser.parse_response(&packet, 80).unwrap();

        assert_eq!(result.port_state, PortState::Open);
        assert_eq!(result.tcp_flags, Some(0x12));
        assert_eq!(result.ttl, Some(64));
        assert_eq!(result.window_size, Some(8192));
    }

    #[test]
    fn test_tcp_parser_rst_response() {
        let parser = TcpPacketParser::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        // Mock TCP packet with RST flag (0x04)
        let mut packet = vec![0u8; 40];

        // IP header
        packet[0] = 0x45; // Version + IHL
        packet[8] = 64; // TTL

        // TCP header starts at offset 20
        packet[20..22].copy_from_slice(&80u16.to_be_bytes()); // Source port
        packet[33] = 0x04; // RST flag

        let result = parser.parse_response(&packet, 80).unwrap();

        assert_eq!(result.port_state, PortState::Closed);
        assert_eq!(result.tcp_flags, Some(0x04));
        assert_eq!(result.ttl, Some(64));
    }

    #[test]
    fn test_tcp_parser_empty_response() {
        let parser = TcpPacketParser::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        let result = parser.parse_response(&[], 80).unwrap();

        assert_eq!(result.port_state, PortState::Filtered);
        assert_eq!(result.tcp_flags, None);
        assert_eq!(result.ttl, None);
    }

    #[test]
    fn test_icmp_parser_port_unreachable() {
        let parser = IcmpPacketParser::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        // Mock ICMP Destination Unreachable - Port Unreachable packet
        let mut packet = vec![0u8; 28];

        // IP header
        packet[0] = 0x45; // Version + IHL
        packet[8] = 64; // TTL

        // ICMP header starts at offset 20
        packet[20] = 3; // Type: Destination Unreachable
        packet[21] = 3; // Code: Port Unreachable

        let result = parser.parse_response(&packet, 80).unwrap();

        assert_eq!(result.port_state, PortState::Closed);
        assert_eq!(result.ttl, Some(64));
    }
}
