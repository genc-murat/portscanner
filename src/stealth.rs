use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct StealthScanResult {
    pub port: u16,
    pub state: PortState,
    pub response_time: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

pub struct StealthScanner {
    target: IpAddr,
    source_ip: IpAddr,
    timeout_ms: u64,
}

impl StealthScanner {
    pub fn new(target: IpAddr, timeout_ms: u64) -> Result<Self, String> {
        let source_ip = get_local_ip(target.is_ipv6())?;

        // IPv6 ve IPv4 uyumluluğunu kontrol et
        match (target.is_ipv4(), source_ip.is_ipv4()) {
            (true, false) | (false, true) => {
                return Err("Target and source IP version mismatch".to_string());
            }
            _ => {}
        }

        Ok(Self {
            target,
            source_ip,
            timeout_ms,
        })
    }

    pub async fn syn_scan(&self, port: u16) -> StealthScanResult {
        match self.perform_syn_scan(port).await {
            Ok(result) => result,
            Err(_) => StealthScanResult {
                port,
                state: PortState::Unknown,
                response_time: self.timeout_ms,
            },
        }
    }

    #[cfg(target_os = "linux")]
    async fn perform_syn_scan(
        &self,
        port: u16,
    ) -> Result<StealthScanResult, Box<dyn std::error::Error>> {
        match self.target {
            IpAddr::V4(_) => self.perform_ipv4_syn_scan(port).await,
            IpAddr::V6(_) => self.perform_ipv6_syn_scan(port).await,
        }
    }

    #[cfg(target_os = "linux")]
    async fn perform_ipv4_syn_scan(
        &self,
        port: u16,
    ) -> Result<StealthScanResult, Box<dyn std::error::Error>> {
        use libc::{sendto, sockaddr, sockaddr_in, socket, AF_INET, IPPROTO_TCP, SOCK_RAW};
        use std::mem;

        let start_time = Instant::now();

        let sock_fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_TCP) };
        if sock_fd < 0 {
            return Err("Failed to create raw socket. Run with sudo privileges.".into());
        }

        // Enable IP_HDRINCL
        let one: i32 = 1;
        unsafe {
            libc::setsockopt(
                sock_fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &one as *const i32 as *const libc::c_void,
                mem::size_of::<i32>() as libc::socklen_t,
            );
        }

        let mut target_addr: sockaddr_in = unsafe { mem::zeroed() };
        target_addr.sin_family = AF_INET as u16;
        target_addr.sin_port = port.to_be();

        if let IpAddr::V4(ipv4) = self.target {
            target_addr.sin_addr.s_addr = u32::from(ipv4).to_be();
        } else {
            return Err("IPv4 address expected".into());
        }

        let packet = self.build_ipv4_syn_packet(port)?;

        let sent = unsafe {
            sendto(
                sock_fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &target_addr as *const sockaddr_in as *const sockaddr,
                mem::size_of::<sockaddr_in>() as libc::socklen_t,
            )
        };

        if sent < 0 {
            unsafe {
                libc::close(sock_fd);
            }
            return Err("Failed to send SYN packet".into());
        }

        let response_result = timeout(
            Duration::from_millis(self.timeout_ms),
            self.listen_for_ipv4_response(sock_fd, port),
        )
        .await;

        unsafe {
            libc::close(sock_fd);
        }

        let response_time = start_time.elapsed().as_millis() as u64;

        let state = match response_result {
            Ok(Ok(received_state)) => received_state,
            Ok(Err(_)) => PortState::Unknown,
            Err(_) => PortState::Filtered, // Timeout
        };

        Ok(StealthScanResult {
            port,
            state,
            response_time,
        })
    }

    #[cfg(target_os = "linux")]
    async fn perform_ipv6_syn_scan(
        &self,
        port: u16,
    ) -> Result<StealthScanResult, Box<dyn std::error::Error>> {
        use libc::{sendto, sockaddr, sockaddr_in6, socket, AF_INET6, IPPROTO_TCP, SOCK_RAW};
        use std::mem;

        let start_time = Instant::now();

        let sock_fd = unsafe { socket(AF_INET6, SOCK_RAW, IPPROTO_TCP) };
        if sock_fd < 0 {
            return Err("Failed to create IPv6 raw socket. Run with sudo privileges.".into());
        }

        // IPv6 için IP header'ı kernel tarafından oluşturulur, IP_HDRINCL gerekli değil

        let mut target_addr: sockaddr_in6 = unsafe { mem::zeroed() };
        target_addr.sin6_family = AF_INET6 as u16;
        target_addr.sin6_port = port.to_be();

        if let IpAddr::V6(ipv6) = self.target {
            target_addr.sin6_addr.s6_addr = ipv6.octets();
        } else {
            return Err("IPv6 address expected".into());
        }

        // IPv6 için sadece TCP header gönder (IP header kernel tarafından eklenir)
        let tcp_header = self.build_ipv6_tcp_header(port)?;

        let sent = unsafe {
            sendto(
                sock_fd,
                tcp_header.as_ptr() as *const libc::c_void,
                tcp_header.len(),
                0,
                &target_addr as *const sockaddr_in6 as *const sockaddr,
                mem::size_of::<sockaddr_in6>() as libc::socklen_t,
            )
        };

        if sent < 0 {
            unsafe {
                libc::close(sock_fd);
            }
            return Err("Failed to send IPv6 SYN packet".into());
        }

        let response_result = timeout(
            Duration::from_millis(self.timeout_ms),
            self.listen_for_ipv6_response(sock_fd, port),
        )
        .await;

        unsafe {
            libc::close(sock_fd);
        }

        let response_time = start_time.elapsed().as_millis() as u64;

        let state = match response_result {
            Ok(Ok(received_state)) => received_state,
            Ok(Err(_)) => PortState::Unknown,
            Err(_) => PortState::Filtered, // Timeout
        };

        Ok(StealthScanResult {
            port,
            state,
            response_time,
        })
    }

    #[cfg(not(target_os = "linux"))]
    async fn perform_syn_scan(
        &self,
        port: u16,
    ) -> Result<StealthScanResult, Box<dyn std::error::Error>> {
        // Fallback to TCP connect scan for non-Linux systems
        let start_time = Instant::now();

        let socket_addr = std::net::SocketAddr::new(self.target, port);
        let connect_result = timeout(
            Duration::from_millis(self.timeout_ms),
            tokio::net::TcpStream::connect(socket_addr),
        )
        .await;

        let response_time = start_time.elapsed().as_millis() as u64;

        let state = match connect_result {
            Ok(Ok(_)) => PortState::Open,
            Ok(Err(_)) => PortState::Closed,
            Err(_) => PortState::Filtered,
        };

        Ok(StealthScanResult {
            port,
            state,
            response_time,
        })
    }

    fn build_ipv4_syn_packet(&self, dest_port: u16) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut packet = Vec::with_capacity(40); // IP header (20) + TCP header (20)

        // IP Header
        packet.extend(&self.build_ipv4_header(20)?); // TCP header length = 20

        // TCP Header
        packet.extend(&self.build_ipv4_tcp_header(dest_port)?);

        Ok(packet)
    }

    fn build_ipv4_header(&self, tcp_len: u16) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut header = vec![0u8; 20];

        // Version (4) + IHL (5) = 0x45
        header[0] = 0x45;

        // Type of Service
        header[1] = 0x00;

        // Total Length
        let total_len: u16 = 20 + tcp_len;
        header[2..4].copy_from_slice(&total_len.to_be_bytes());

        let mut rng = rand::thread_rng();
        let id: u16 = rng.gen_range(1..65535);
        header[4..6].copy_from_slice(&id.to_be_bytes());

        // Flags + Fragment Offset (Don't Fragment = 0x4000)
        header[6..8].copy_from_slice(&0x4000u16.to_be_bytes());

        // TTL
        header[8] = 64;

        // Protocol (TCP = 6)
        header[9] = 6;

        // Checksum
        header[10..12].copy_from_slice(&0u16.to_be_bytes());

        // Source IP
        if let IpAddr::V4(src_ip) = self.source_ip {
            header[12..16].copy_from_slice(&src_ip.octets());
        }

        // Destination IP
        if let IpAddr::V4(dest_ip) = self.target {
            header[16..20].copy_from_slice(&dest_ip.octets());
        }

        // Calculate checksum
        let checksum = calculate_checksum(&header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());

        Ok(header)
    }

    fn build_ipv4_tcp_header(&self, dest_port: u16) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut header = vec![0u8; 20];

        // Source Port (random)
        let mut rng = rand::thread_rng();
        let src_port: u16 = rng.gen_range(1024..65535);
        header[0..2].copy_from_slice(&src_port.to_be_bytes());

        // Destination Port
        header[2..4].copy_from_slice(&dest_port.to_be_bytes());

        // Sequence Number (random)
        let seq_num: u32 = rng.gen_range(1..u32::MAX);
        header[4..8].copy_from_slice(&seq_num.to_be_bytes());

        // Acknowledgment Number (0 for SYN)
        header[8..12].copy_from_slice(&0u32.to_be_bytes());

        // Data Offset (5) + Reserved (0) + Flags
        // Data Offset = 5 (20 bytes / 4) = 0x50
        header[12] = 0x50;

        // TCP Flags (SYN = 0x02)
        header[13] = 0x02;

        // Window Size
        header[14..16].copy_from_slice(&8192u16.to_be_bytes());

        // Checksum
        header[16..18].copy_from_slice(&0u16.to_be_bytes());

        // Urgent Pointer
        header[18..20].copy_from_slice(&0u16.to_be_bytes());

        // Calculate TCP checksum
        let checksum = self.calculate_ipv4_tcp_checksum(&header, src_port, dest_port)?;
        header[16..18].copy_from_slice(&checksum.to_be_bytes());

        Ok(header)
    }

    fn build_ipv6_tcp_header(&self, dest_port: u16) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut header = vec![0u8; 20];

        // Source Port (random)
        let mut rng = rand::thread_rng();
        let src_port: u16 = rng.gen_range(1024..65535);
        header[0..2].copy_from_slice(&src_port.to_be_bytes());

        // Destination Port
        header[2..4].copy_from_slice(&dest_port.to_be_bytes());

        // Sequence Number (random)
        let seq_num: u32 = rng.gen_range(1..u32::MAX);
        header[4..8].copy_from_slice(&seq_num.to_be_bytes());

        // Acknowledgment Number (0 for SYN)
        header[8..12].copy_from_slice(&0u32.to_be_bytes());

        // Data Offset (5) + Reserved (0) + Flags
        header[12] = 0x50;

        // TCP Flags (SYN = 0x02)
        header[13] = 0x02;

        // Window Size
        header[14..16].copy_from_slice(&8192u16.to_be_bytes());

        // Checksum (will be calculated)
        header[16..18].copy_from_slice(&0u16.to_be_bytes());

        // Urgent Pointer
        header[18..20].copy_from_slice(&0u16.to_be_bytes());

        // Calculate IPv6 TCP checksum
        let checksum = self.calculate_ipv6_tcp_checksum(&header, src_port, dest_port)?;
        header[16..18].copy_from_slice(&checksum.to_be_bytes());

        Ok(header)
    }

    fn calculate_ipv4_tcp_checksum(
        &self,
        tcp_header: &[u8],
        _src_port: u16,
        _dest_port: u16,
    ) -> Result<u16, Box<dyn std::error::Error>> {
        let mut pseudo_header = Vec::new();

        // Source IP
        if let IpAddr::V4(src_ip) = self.source_ip {
            pseudo_header.extend_from_slice(&src_ip.octets());
        }

        // Destination IP
        if let IpAddr::V4(dest_ip) = self.target {
            pseudo_header.extend_from_slice(&dest_ip.octets());
        }

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

    fn calculate_ipv6_tcp_checksum(
        &self,
        tcp_header: &[u8],
        _src_port: u16,
        _dest_port: u16,
    ) -> Result<u16, Box<dyn std::error::Error>> {
        let mut pseudo_header = Vec::new();

        // Source IPv6 Address (16 bytes)
        if let IpAddr::V6(src_ip) = self.source_ip {
            pseudo_header.extend_from_slice(&src_ip.octets());
        }

        // Destination IPv6 Address (16 bytes)
        if let IpAddr::V6(dest_ip) = self.target {
            pseudo_header.extend_from_slice(&dest_ip.octets());
        }

        // TCP Length (4 bytes)
        let tcp_len = tcp_header.len() as u32;
        pseudo_header.extend_from_slice(&tcp_len.to_be_bytes());

        // Zeros (3 bytes) + Next Header (1 byte = TCP = 6)
        pseudo_header.extend_from_slice(&[0, 0, 0, 6]);

        // TCP Header
        pseudo_header.extend_from_slice(tcp_header);

        Ok(calculate_checksum(&pseudo_header))
    }

    #[cfg(target_os = "linux")]
    async fn listen_for_ipv4_response(
        &self,
        sock_fd: i32,
        target_port: u16,
    ) -> Result<PortState, Box<dyn std::error::Error>> {
        use libc::{recvfrom, sockaddr, sockaddr_in};
        use std::mem;

        let mut buffer = [0u8; 1024];
        let mut addr: sockaddr_in = unsafe { mem::zeroed() };
        let mut addr_len = mem::size_of::<sockaddr_in>() as libc::socklen_t;

        loop {
            let received = unsafe {
                recvfrom(
                    sock_fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                    &mut addr as *mut sockaddr_in as *mut sockaddr,
                    &mut addr_len,
                )
            };

            if received < 0 {
                return Err("Failed to receive packet".into());
            }

            if let Some(state) =
                self.parse_ipv4_response(&buffer[..received as usize], target_port)?
            {
                return Ok(state);
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn listen_for_ipv6_response(
        &self,
        sock_fd: i32,
        target_port: u16,
    ) -> Result<PortState, Box<dyn std::error::Error>> {
        use libc::{recvfrom, sockaddr, sockaddr_in6};
        use std::mem;

        let mut buffer = [0u8; 1024];
        let mut addr: sockaddr_in6 = unsafe { mem::zeroed() };
        let mut addr_len = mem::size_of::<sockaddr_in6>() as libc::socklen_t;

        loop {
            let received = unsafe {
                recvfrom(
                    sock_fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                    &mut addr as *mut sockaddr_in6 as *mut sockaddr,
                    &mut addr_len,
                )
            };

            if received < 0 {
                return Err("Failed to receive packet".into());
            }

            if let Some(state) =
                self.parse_ipv6_response(&buffer[..received as usize], target_port)?
            {
                return Ok(state);
            }
        }
    }

    fn parse_ipv4_response(
        &self,
        packet: &[u8],
        target_port: u16,
    ) -> Result<Option<PortState>, Box<dyn std::error::Error>> {
        if packet.len() < 40 {
            // Minimum IP + TCP header size
            return Ok(None);
        }

        // Skip IP header (typically 20 bytes, but check IHL)
        let ip_header_len = ((packet[0] & 0x0F) * 4) as usize;

        if packet.len() < ip_header_len + 20 {
            return Ok(None);
        }

        let tcp_start = ip_header_len;

        let src_port = u16::from_be_bytes([packet[tcp_start], packet[tcp_start + 1]]);

        if src_port != target_port {
            return Ok(None);
        }

        let flags = packet[tcp_start + 13];

        if flags & 0x12 == 0x12 {
            // SYN + ACK
            Ok(Some(PortState::Open))
        } else if flags & 0x04 == 0x04 {
            // RST
            Ok(Some(PortState::Closed))
        } else {
            Ok(None) // Continue listening
        }
    }

    fn parse_ipv6_response(
        &self,
        packet: &[u8],
        target_port: u16,
    ) -> Result<Option<PortState>, Box<dyn std::error::Error>> {
        if packet.len() < 60 {
            // Minimum IPv6 + TCP header size (40 + 20)
            return Ok(None);
        }

        // IPv6 header is fixed 40 bytes
        let ipv6_header_len = 40;

        // Check if it's a TCP packet (Next Header = 6)
        let next_header = packet[6];
        if next_header != 6 {
            return Ok(None);
        }

        if packet.len() < ipv6_header_len + 20 {
            return Ok(None);
        }

        let tcp_start = ipv6_header_len;

        let src_port = u16::from_be_bytes([packet[tcp_start], packet[tcp_start + 1]]);

        if src_port != target_port {
            return Ok(None);
        }

        let flags = packet[tcp_start + 13];

        if flags & 0x12 == 0x12 {
            // SYN + ACK
            Ok(Some(PortState::Open))
        } else if flags & 0x04 == 0x04 {
            // RST
            Ok(Some(PortState::Closed))
        } else {
            Ok(None) // Continue listening
        }
    }
}

fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i < data.len() - 1 {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }

    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

fn get_local_ip(is_ipv6: bool) -> Result<IpAddr, String> {
    use std::net::UdpSocket;

    let bind_addr = if is_ipv6 { "[::]:0" } else { "0.0.0.0:0" };
    let connect_addr = if is_ipv6 {
        "[2001:4860:4860::8888]:80" // Google DNS IPv6
    } else {
        "8.8.8.8:80" // Google DNS IPv4
    };

    let socket = UdpSocket::bind(bind_addr).map_err(|e| format!("Failed to bind socket: {}", e))?;

    socket
        .connect(connect_addr)
        .map_err(|e| format!("Failed to connect: {}", e))?;

    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("Failed to get local address: {}", e))?;

    Ok(local_addr.ip())
}

// IPv6 address utilities
pub fn is_ipv6_address(addr: &str) -> bool {
    addr.parse::<Ipv6Addr>().is_ok()
}

pub fn normalize_ipv6_address(addr: &str) -> Result<String, String> {
    let ipv6: Ipv6Addr = addr
        .parse()
        .map_err(|e| format!("Invalid IPv6 address: {}", e))?;
    Ok(ipv6.to_string())
}

pub fn expand_ipv6_address(addr: &str) -> Result<String, String> {
    let ipv6: Ipv6Addr = addr
        .parse()
        .map_err(|e| format!("Invalid IPv6 address: {}", e))?;

    // IPv6 adresini tam formatında göster (sıkıştırılmamış)
    let segments = ipv6.segments();
    Ok(format!(
        "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ipv4_stealth_scanner_creation() {
        let target = "127.0.0.1".parse().unwrap();
        let scanner = StealthScanner::new(target, 3000);
        assert!(scanner.is_ok());
    }

    #[tokio::test]
    async fn test_ipv6_stealth_scanner_creation() {
        let target = "::1".parse().unwrap();
        let scanner = StealthScanner::new(target, 3000);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_ipv6_address_validation() {
        assert!(is_ipv6_address("2001:db8::1"));
        assert!(is_ipv6_address("::1"));
        assert!(is_ipv6_address("fe80::1%eth0"));
        assert!(!is_ipv6_address("192.168.1.1"));
        assert!(!is_ipv6_address("invalid"));
    }

    #[test]
    fn test_ipv6_address_normalization() {
        assert_eq!(
            normalize_ipv6_address("2001:0db8:0000:0000:0000:0000:0000:0001").unwrap(),
            "2001:db8::1"
        );
        assert_eq!(normalize_ipv6_address("::1").unwrap(), "::1");
    }

    #[test]
    fn test_ipv6_address_expansion() {
        assert_eq!(
            expand_ipv6_address("2001:db8::1").unwrap(),
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        );
        assert_eq!(
            expand_ipv6_address("::1").unwrap(),
            "0000:0000:0000:0000:0000:0000:0000:0001"
        );
    }

    #[test]
    fn test_checksum_calculation() {
        let data = vec![
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        ];
        let checksum = calculate_checksum(&data);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_ipv4_ipv6_version_mismatch() {
        let ipv4_target = "192.168.1.1".parse().unwrap();
        let ipv6_target = "2001:db8::1".parse().unwrap();

        // Bu test local IP'nin belirlenmesi sırasında hata vermeli
        // çünkü target IPv6 ama sistem IPv4 kullanıyor olabilir
        let scanner_v4 = StealthScanner::new(ipv4_target, 3000);
        let scanner_v6 = StealthScanner::new(ipv6_target, 3000);

        // En azından birinin çalışması gerekiyor
        assert!(scanner_v4.is_ok() || scanner_v6.is_ok());
    }
}
