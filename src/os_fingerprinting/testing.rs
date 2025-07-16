use super::NetworkCharacteristics;
use rand::Rng;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct NetworkTester {
    tcp_timeout: Duration,
    probe_timeout: Duration,
}

impl NetworkTester {
    pub fn new() -> Self {
        Self {
            tcp_timeout: Duration::from_secs(3),
            probe_timeout: Duration::from_millis(300),
        }
    }

    pub async fn tcp_connect_probe(
        &self,
        target: IpAddr,
        port: u16,
    ) -> Option<NetworkCharacteristics> {
        let socket_addr = SocketAddr::new(target, port);

        match timeout(self.tcp_timeout, TcpStream::connect(socket_addr)).await {
            Ok(Ok(_)) => {
                // Basic characteristics from successful connection
                Some(NetworkCharacteristics::from_tcp_connection(
                    Some(65535), // Default assumption
                    Vec::new(),
                    true, // Most modern systems support timestamps
                    true, // Most modern systems support window scaling
                    true, // Most modern systems support SACK
                ))
            }
            _ => None,
        }
    }

    pub async fn tcp_syn_closed_port(&self, target: IpAddr, port: u16) -> Option<String> {
        let socket_addr = SocketAddr::new(target, port);

        match timeout(self.probe_timeout, TcpStream::connect(socket_addr)).await {
            Ok(Err(_)) => Some("RST".to_string()),
            Err(_) => Some("TIMEOUT".to_string()),
            Ok(Ok(_)) => Some("OPEN".to_string()), // Unexpected
        }
    }

    pub async fn find_closed_port(&self, target: IpAddr) -> Option<u16> {
        // Try common ports that are usually closed
        if let Some(port) = self.try_common_closed_ports(target).await {
            return Some(port);
        }

        // Try random ports
        if let Some(port) = self.try_random_ports(target).await {
            return Some(port);
        }

        // Last resort: assume port 1 is closed (very likely)
        Some(1)
    }

    async fn try_common_closed_ports(&self, target: IpAddr) -> Option<u16> {
        let test_ports = [
            1, 3, 4, 6, 7, 9, 13, 17, 19, 20, // Uncommon low ports
            65534, 65533, 65532, 65531, 65530, // High ports
            1234, 5678, 9876, 12345, 54321, // Random mid-range
            666, 1337, 31337, 8192, 16384, // Rarely used ports
        ];

        for &port in &test_ports {
            if self.is_port_closed(target, port).await {
                return Some(port);
            }
        }

        None
    }

    async fn try_random_ports(&self, target: IpAddr) -> Option<u16> {
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let random_port = rng.gen_range(49152..65535); // Dynamic/private port range
            if self.is_port_closed(target, random_port).await {
                return Some(random_port);
            }
        }

        None
    }

    async fn is_port_closed(&self, target: IpAddr, port: u16) -> bool {
        let socket_addr = SocketAddr::new(target, port);

        match timeout(self.probe_timeout, TcpStream::connect(socket_addr)).await {
            Ok(Err(e)) => {
                // Check for connection refused specifically
                if let Some(os_error) = e.raw_os_error() {
                    #[cfg(unix)]
                    if os_error == libc::ECONNREFUSED {
                        return true;
                    }

                    #[cfg(windows)]
                    if os_error == 10061 {
                        // WSAECONNREFUSED
                        return true;
                    }
                }

                // Generic connection error, likely closed port
                matches!(e.kind(), std::io::ErrorKind::ConnectionRefused)
            }
            Err(_) | Ok(Ok(_)) => false, // Timeout or successful connection
        }
    }

    pub async fn estimate_ttl(&self, target: IpAddr, open_ports: &[u16]) -> Option<u8> {
        // Simple TTL estimation based on common values
        // This is a simplified approach - real TTL detection would require raw sockets

        if let Some(&port) = open_ports.first() {
            let socket_addr = SocketAddr::new(target, port);
            let start = Instant::now();

            match timeout(Duration::from_millis(100), TcpStream::connect(socket_addr)).await {
                Ok(Ok(_)) => {
                    let rtt = start.elapsed().as_millis();
                    self.estimate_ttl_from_rtt(rtt)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn estimate_ttl_from_rtt(&self, rtt: u128) -> Option<u8> {
        // Estimate TTL based on RTT (very rough approximation)
        match rtt {
            0..=10 => Some(64),   // Local network, likely Linux/Unix
            11..=50 => Some(128), // Nearby, possibly Windows
            51..=200 => Some(64), // Internet, likely Linux server
            _ => Some(255),       // Far away or router/embedded device
        }
    }
}
