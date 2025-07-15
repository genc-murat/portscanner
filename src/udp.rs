use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone, PartialEq)]
pub enum UdpPortState {
    Open,
    OpenFiltered, // UDP port responds or no ICMP unreachable
    #[allow(dead_code)] // This variant might be used for ICMP unreachable detection
    Closed, // ICMP port unreachable received
    Filtered,     // ICMP filtered or timeout
}

#[derive(Debug, Clone)]
pub struct UdpScanResult {
    pub port: u16,
    pub state: UdpPortState,
    pub response_time: u64,
    pub response_data: Option<Vec<u8>>,
    pub service_response: Option<String>,
}

pub struct UdpScanner {
    target: IpAddr,
    timeout_ms: u64,
    max_retries: u8,
}

impl UdpScanner {
    pub fn new(target: IpAddr, timeout_ms: u64) -> Self {
        Self {
            target,
            timeout_ms,
            max_retries: 2,
        }
    }

    pub async fn scan_port(&self, port: u16) -> UdpScanResult {
        let start_time = Instant::now();

        // Try service-specific probes first
        if let Some(result) = self.service_specific_scan(port).await {
            return result;
        }

        // Fallback to generic UDP scan
        self.generic_udp_scan(port, start_time).await
    }

    async fn service_specific_scan(&self, port: u16) -> Option<UdpScanResult> {
        let probe_data = match port {
            53 => self.create_dns_probe(),
            123 => self.create_ntp_probe(),
            161 => self.create_snmp_probe(),
            69 => self.create_tftp_probe(),
            137 => self.create_netbios_probe(),
            5353 => self.create_mdns_probe(),
            1900 => self.create_upnp_probe(),
            _ => return None,
        };

        let start_time = Instant::now();
        match self.send_udp_probe(port, &probe_data).await {
            Ok(Some(response)) => Some(UdpScanResult {
                port,
                state: UdpPortState::Open,
                response_time: start_time.elapsed().as_millis() as u64,
                response_data: Some(response.clone()),
                service_response: Some(self.format_service_response(port, &response)),
            }),
            Ok(None) => Some(UdpScanResult {
                port,
                state: UdpPortState::OpenFiltered,
                response_time: start_time.elapsed().as_millis() as u64,
                response_data: None,
                service_response: None,
            }),
            Err(_) => None,
        }
    }

    async fn generic_udp_scan(&self, port: u16, start_time: Instant) -> UdpScanResult {
        // Send empty UDP packet or common payload
        let probe_data = vec![0x00]; // Simple probe

        for attempt in 0..=self.max_retries {
            match self.send_udp_probe(port, &probe_data).await {
                Ok(Some(response)) => {
                    return UdpScanResult {
                        port,
                        state: UdpPortState::Open,
                        response_time: start_time.elapsed().as_millis() as u64,
                        response_data: Some(response),
                        service_response: None,
                    };
                }
                Ok(None) => {
                    if attempt == self.max_retries {
                        return UdpScanResult {
                            port,
                            state: UdpPortState::OpenFiltered,
                            response_time: start_time.elapsed().as_millis() as u64,
                            response_data: None,
                            service_response: None,
                        };
                    }
                }
                Err(_) => {
                    if attempt == self.max_retries {
                        return UdpScanResult {
                            port,
                            state: UdpPortState::Filtered,
                            response_time: start_time.elapsed().as_millis() as u64,
                            response_data: None,
                            service_response: None,
                        };
                    }
                }
            }

            // Small delay between retries
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        UdpScanResult {
            port,
            state: UdpPortState::Filtered,
            response_time: start_time.elapsed().as_millis() as u64,
            response_data: None,
            service_response: None,
        }
    }

    async fn send_udp_probe(
        &self,
        port: u16,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>, std::io::Error> {
        let socket_addr = SocketAddr::new(self.target, port);
        let socket = TokioUdpSocket::bind("0.0.0.0:0").await?;

        // Send probe
        socket.send_to(data, socket_addr).await?;

        // Wait for response
        let mut buffer = vec![0u8; 4096];
        match timeout(
            Duration::from_millis(self.timeout_ms),
            socket.recv_from(&mut buffer),
        )
        .await
        {
            Ok(Ok((len, _))) => {
                buffer.truncate(len);
                Ok(Some(buffer))
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(None), // Timeout, but not an error
        }
    }

    // DNS probe (port 53)
    fn create_dns_probe(&self) -> Vec<u8> {
        vec![
            // DNS Header
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer, Authority, Additional: 0
            // Query for version.bind CHAOS TXT
            0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
            0x04, 0x62, 0x69, 0x6e, 0x64, // "bind"
            0x00, // End of name
            0x00, 0x10, // Type: TXT
            0x00, 0x03, // Class: CHAOS
        ]
    }

    // NTP probe (port 123)
    fn create_ntp_probe(&self) -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x1B; // LI=0, VN=3, Mode=3 (client)
        packet
    }

    // SNMP probe (port 161)
    fn create_snmp_probe(&self) -> Vec<u8> {
        // SNMPv1 GetRequest for system.sysDescr.0
        vec![
            0x30, 0x26, // SEQUENCE, length 38
            0x02, 0x01, 0x00, // INTEGER version (0 = SNMPv1)
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // OCTET STRING "public"
            0xa0, 0x19, // GetRequest PDU
            0x02, 0x01, 0x01, // Request ID
            0x02, 0x01, 0x00, // Error status
            0x02, 0x01, 0x00, // Error index
            0x30, 0x0e, // VarBindList
            0x30, 0x0c, // VarBind
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01,
            0x00, // OID 1.3.6.1.2.1.1.1.0
            0x05, 0x00, // NULL value
        ]
    }

    // TFTP probe (port 69)
    fn create_tftp_probe(&self) -> Vec<u8> {
        // TFTP Read Request for "nonexistent"
        let mut packet = Vec::new();
        packet.extend(&[0x00, 0x01]); // Opcode: RRQ
        packet.extend(b"nonexistent\0"); // Filename
        packet.extend(b"octet\0"); // Mode
        packet
    }

    // NetBIOS Name Service probe (port 137)
    fn create_netbios_probe(&self) -> Vec<u8> {
        vec![
            // NetBIOS Name Query
            0x12, 0x34, // Transaction ID
            0x01, 0x10, // Flags: Query, Recursion Desired
            0x00, 0x01, // Questions: 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer, Authority, Additional: 0
            // Query for "*" (broadcast name)
            0x20, // Name length (32 encoded bytes)
            // Encoded "*SMBSERVER      " (16 chars, each encoded as 2 nibbles + 'A')
            0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x00, // End of name
            0x00, 0x21, // Type: NB (NetBIOS)
            0x00, 0x01, // Class: IN
        ]
    }

    // mDNS probe (port 5353)
    fn create_mdns_probe(&self) -> Vec<u8> {
        vec![
            // mDNS Query
            0x00, 0x00, // Transaction ID (0 for mDNS)
            0x00, 0x00, // Standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer, Authority, Additional: 0
            // Query for "_services._dns-sd._udp.local"
            0x09, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, // "_services"
            0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64, // "_dns-sd"
            0x04, 0x5f, 0x75, 0x64, 0x70, // "_udp"
            0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, // "local"
            0x00, // End of name
            0x00, 0x0c, // Type: PTR
            0x00, 0x01, // Class: IN
        ]
    }

    // UPnP SSDP probe (port 1900)
    fn create_upnp_probe(&self) -> Vec<u8> {
        let ssdp_discover = "M-SEARCH * HTTP/1.1\r\n\
             HOST: 239.255.255.250:1900\r\n\
             MAN: \"ssdp:discover\"\r\n\
             ST: upnp:rootdevice\r\n\
             MX: 3\r\n\r\n";
        ssdp_discover.as_bytes().to_vec()
    }

    fn format_service_response(&self, port: u16, response: &[u8]) -> String {
        match port {
            53 => self.format_dns_response(response),
            123 => self.format_ntp_response(response),
            161 => self.format_snmp_response(response),
            69 => self.format_tftp_response(response),
            137 => self.format_netbios_response(response),
            5353 => self.format_mdns_response(response),
            1900 => self.format_upnp_response(response),
            _ => format!("UDP response ({} bytes)", response.len()),
        }
    }

    fn format_dns_response(&self, response: &[u8]) -> String {
        if response.len() >= 12 {
            let flags = u16::from_be_bytes([response[2], response[3]]);
            if flags & 0x8000 != 0 {
                // Response bit set
                return "DNS Server".to_string();
            }
        }
        "DNS-like response".to_string()
    }

    fn format_ntp_response(&self, response: &[u8]) -> String {
        if response.len() >= 48 {
            let li_vn_mode = response[0];
            let version = (li_vn_mode >> 3) & 0x07;
            format!("NTP Server (v{})", version)
        } else {
            "NTP-like response".to_string()
        }
    }

    fn format_snmp_response(&self, response: &[u8]) -> String {
        if response.len() > 2 && response[0] == 0x30 {
            "SNMP Agent".to_string()
        } else {
            "SNMP-like response".to_string()
        }
    }

    fn format_tftp_response(&self, response: &[u8]) -> String {
        if response.len() >= 4 {
            let opcode = u16::from_be_bytes([response[0], response[1]]);
            match opcode {
                1 => "TFTP Read Request".to_string(),
                2 => "TFTP Write Request".to_string(),
                3 => "TFTP Data".to_string(),
                4 => "TFTP Acknowledgment".to_string(),
                5 => "TFTP Error".to_string(),
                _ => "TFTP Server".to_string(),
            }
        } else {
            "TFTP-like response".to_string()
        }
    }

    fn format_netbios_response(&self, response: &[u8]) -> String {
        if response.len() >= 12 {
            "NetBIOS Name Service".to_string()
        } else {
            "NetBIOS-like response".to_string()
        }
    }

    fn format_mdns_response(&self, response: &[u8]) -> String {
        if response.len() >= 12 {
            "mDNS/Bonjour Service".to_string()
        } else {
            "mDNS-like response".to_string()
        }
    }

    fn format_upnp_response(&self, response: &[u8]) -> String {
        if let Ok(text) = std::str::from_utf8(response) {
            if text.contains("HTTP/1.1") && text.contains("USN:") {
                if let Some(server_line) = text
                    .lines()
                    .find(|line| line.to_lowercase().starts_with("server:"))
                {
                    return format!(
                        "UPnP Device: {}",
                        server_line.trim_start_matches("Server:").trim()
                    );
                }
                return "UPnP Device".to_string();
            }
        }
        "UPnP-like response".to_string()
    }

    pub fn get_common_udp_ports() -> Vec<u16> {
        vec![
            53,    // DNS
            67,    // DHCP server
            68,    // DHCP client
            69,    // TFTP
            123,   // NTP
            137,   // NetBIOS Name Service
            138,   // NetBIOS Datagram Service
            161,   // SNMP
            162,   // SNMP Trap
            500,   // IKE (IPSec)
            514,   // Syslog
            520,   // RIP
            1194,  // OpenVPN
            1701,  // L2TP
            1900,  // UPnP SSDP
            4500,  // IPSec NAT-T
            5353,  // mDNS
            5060,  // SIP
            6881,  // BitTorrent
            27015, // Steam
            27017, // MongoDB
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_scanner_creation() {
        let target = "127.0.0.1".parse().unwrap();
        let scanner = UdpScanner::new(target, 3000);
        assert_eq!(scanner.target, target);
        assert_eq!(scanner.timeout_ms, 3000);
    }

    #[test]
    fn test_dns_probe_creation() {
        let target = "127.0.0.1".parse().unwrap();
        let scanner = UdpScanner::new(target, 3000);
        let probe = scanner.create_dns_probe();
        assert!(!probe.is_empty());
        assert_eq!(probe[0], 0x12); // Transaction ID
        assert_eq!(probe[1], 0x34);
    }

    #[test]
    fn test_ntp_probe_creation() {
        let target = "127.0.0.1".parse().unwrap();
        let scanner = UdpScanner::new(target, 3000);
        let probe = scanner.create_ntp_probe();
        assert_eq!(probe.len(), 48);
        assert_eq!(probe[0], 0x1B); // LI=0, VN=3, Mode=3
    }

    #[test]
    fn test_common_udp_ports() {
        let ports = UdpScanner::get_common_udp_ports();
        assert!(ports.contains(&53)); // DNS
        assert!(ports.contains(&123)); // NTP
        assert!(ports.contains(&161)); // SNMP
    }

    #[tokio::test]
    async fn test_udp_scan_localhost_dns() {
        let target = "127.0.0.1".parse().unwrap();
        let scanner = UdpScanner::new(target, 1000);
        let result = scanner.scan_port(53).await;

        // Result should be either Open, OpenFiltered, or Filtered
        assert!(matches!(
            result.state,
            UdpPortState::Open | UdpPortState::OpenFiltered | UdpPortState::Filtered
        ));
    }
}
