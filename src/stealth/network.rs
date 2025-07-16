use crate::stealth::traits::NetworkUtils;
use crate::stealth::types::StealthScanError;
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

pub struct RawSocketManager {
    target: IpAddr,
    #[cfg(unix)]
    socket_fd: Option<RawFd>,
    #[cfg(not(unix))]
    _phantom: std::marker::PhantomData<()>,
}

impl std::fmt::Debug for RawSocketManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawSocketManager")
            .field("target", &self.target)
            .field("has_socket", &self.socket_fd.is_some())
            .finish()
    }
}

impl RawSocketManager {
    pub fn new(target: IpAddr) -> Result<Self, StealthScanError> {
        #[cfg(unix)]
        {
            let socket_fd = Self::create_raw_socket(target)?;
            Ok(Self {
                target,
                socket_fd: Some(socket_fd),
            })
        }

        #[cfg(not(unix))]
        {
            Ok(Self {
                target,
                _phantom: std::marker::PhantomData,
            })
        }
    }

    #[cfg(unix)]
    fn create_raw_socket(target: IpAddr) -> Result<RawFd, StealthScanError> {
        use libc::{socket, AF_INET, AF_INET6, IPPROTO_TCP, SOCK_RAW};
        use std::mem;

        let (family, protocol) = match target {
            IpAddr::V4(_) => (AF_INET, IPPROTO_TCP),
            IpAddr::V6(_) => (AF_INET6, IPPROTO_TCP),
        };

        let sock_fd = unsafe { socket(family, SOCK_RAW, protocol) };
        if sock_fd < 0 {
            return Err(StealthScanError::RawSocketError(
                "Failed to create raw socket. Run with sudo privileges.".to_string(),
            ));
        }

        // Enable IP_HDRINCL for IPv4
        if matches!(target, IpAddr::V4(_)) {
            let one: i32 = 1;
            unsafe {
                if libc::setsockopt(
                    sock_fd,
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    &one as *const i32 as *const libc::c_void,
                    mem::size_of::<i32>() as libc::socklen_t,
                ) < 0
                {
                    libc::close(sock_fd);
                    return Err(StealthScanError::RawSocketError(
                        "Failed to set IP_HDRINCL".to_string(),
                    ));
                }
            }
        }

        Ok(sock_fd)
    }

    #[cfg(unix)]
    fn build_sockaddr(
        &self,
        target: IpAddr,
        port: u16,
    ) -> Result<(libc::sockaddr_storage, libc::socklen_t), StealthScanError> {
        use libc::{sockaddr_in, sockaddr_in6, sockaddr_storage, AF_INET, AF_INET6};
        use std::mem;

        match target {
            IpAddr::V4(ipv4) => {
                let mut addr: sockaddr_in = unsafe { mem::zeroed() };
                addr.sin_family = AF_INET as libc::sa_family_t;
                addr.sin_port = port.to_be();
                addr.sin_addr.s_addr = u32::from(ipv4).to_be();

                let mut storage: sockaddr_storage = unsafe { mem::zeroed() };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &addr as *const sockaddr_in as *const u8,
                        &mut storage as *mut sockaddr_storage as *mut u8,
                        mem::size_of::<sockaddr_in>(),
                    );
                }

                Ok((storage, mem::size_of::<sockaddr_in>() as libc::socklen_t))
            }
            IpAddr::V6(ipv6) => {
                let mut addr: sockaddr_in6 = unsafe { mem::zeroed() };
                addr.sin6_family = AF_INET6 as libc::sa_family_t;
                addr.sin6_port = port.to_be();
                addr.sin6_addr.s6_addr = ipv6.octets();

                let mut storage: sockaddr_storage = unsafe { mem::zeroed() };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &addr as *const sockaddr_in6 as *const u8,
                        &mut storage as *mut sockaddr_storage as *mut u8,
                        mem::size_of::<sockaddr_in6>(),
                    );
                }

                Ok((storage, mem::size_of::<sockaddr_in6>() as libc::socklen_t))
            }
        }
    }
}

#[async_trait]
impl NetworkUtils for RawSocketManager {
    async fn get_local_ip(&self, target: IpAddr) -> Result<IpAddr, StealthScanError> {
        use std::net::UdpSocket;

        let bind_addr = match target {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(bind_addr)
            .map_err(|e| StealthScanError::NetworkError(format!("Failed to bind socket: {}", e)))?;

        socket
            .connect((target, 80))
            .map_err(|e| StealthScanError::NetworkError(format!("Failed to connect: {}", e)))?;

        let local_addr = socket.local_addr().map_err(|e| {
            StealthScanError::NetworkError(format!("Failed to get local address: {}", e))
        })?;

        Ok(local_addr.ip())
    }

    #[cfg(unix)]
    async fn send_packet(
        &self,
        packet: &[u8],
        target: IpAddr,
        port: u16,
    ) -> Result<(), StealthScanError> {
        use libc::{sendto, sockaddr};

        let sock_fd = self.socket_fd.ok_or_else(|| {
            StealthScanError::RawSocketError("Raw socket not initialized".to_string())
        })?;

        let (sockaddr_storage, addr_len) = self.build_sockaddr(target, port)?;

        let sent = unsafe {
            sendto(
                sock_fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &sockaddr_storage as *const libc::sockaddr_storage as *const sockaddr,
                addr_len,
            )
        };

        if sent < 0 {
            return Err(StealthScanError::NetworkError(
                "Failed to send packet".to_string(),
            ));
        }

        Ok(())
    }

    #[cfg(not(unix))]
    async fn send_packet(
        &self,
        _packet: &[u8],
        _target: IpAddr,
        _port: u16,
    ) -> Result<(), StealthScanError> {
        Err(StealthScanError::UnsupportedPlatform(
            "Raw sockets not supported on this platform".to_string(),
        ))
    }

    #[cfg(unix)]
    async fn receive_response(
        &self,
        timeout_duration: Duration,
    ) -> Result<Vec<u8>, StealthScanError> {
        use libc::{recvfrom, sockaddr, sockaddr_storage};
        use std::mem;
        use tokio::task;

        let sock_fd = self.socket_fd.ok_or_else(|| {
            StealthScanError::RawSocketError("Raw socket not initialized".to_string())
        })?;

        let result = task::spawn_blocking(move || {
            let mut buffer = vec![0u8; 4096];
            let mut addr: sockaddr_storage = unsafe { mem::zeroed() };
            let mut addr_len = mem::size_of::<sockaddr_storage>() as libc::socklen_t;

            // Set socket timeout
            let timeout_sec = timeout_duration.as_secs() as libc::time_t;
            let timeout_usec = (timeout_duration.subsec_micros()) as libc::suseconds_t;
            let timeout_val = libc::timeval {
                tv_sec: timeout_sec,
                tv_usec: timeout_usec,
            };

            unsafe {
                libc::setsockopt(
                    sock_fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &timeout_val as *const libc::timeval as *const libc::c_void,
                    mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }

            let received = unsafe {
                recvfrom(
                    sock_fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                    &mut addr as *mut sockaddr_storage as *mut sockaddr,
                    &mut addr_len,
                )
            };

            if received < 0 {
                Err(StealthScanError::NetworkError(
                    "Failed to receive packet".to_string(),
                ))
            } else {
                buffer.truncate(received as usize);
                Ok(buffer)
            }
        })
        .await;

        result.map_err(|e| StealthScanError::NetworkError(format!("Task join error: {}", e)))?
    }

    #[cfg(not(unix))]
    async fn receive_response(
        &self,
        _timeout_duration: Duration,
    ) -> Result<Vec<u8>, StealthScanError> {
        Err(StealthScanError::UnsupportedPlatform(
            "Raw sockets not supported on this platform".to_string(),
        ))
    }
}

impl Drop for RawSocketManager {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            if let Some(fd) = self.socket_fd {
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct TcpConnector {
    // Connection pool or configuration could be added here
}

impl TcpConnector {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn connect(
        &self,
        target: IpAddr,
        port: u16,
        timeout_duration: Duration,
    ) -> Result<TcpStream, std::io::Error> {
        let socket_addr = SocketAddr::new(target, port);
        timeout(timeout_duration, TcpStream::connect(socket_addr))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Connection timeout"))?
    }
}

#[async_trait]
impl NetworkUtils for TcpConnector {
    async fn get_local_ip(&self, target: IpAddr) -> Result<IpAddr, StealthScanError> {
        use std::net::UdpSocket;

        let bind_addr = match target {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(bind_addr)
            .map_err(|e| StealthScanError::NetworkError(format!("Failed to bind socket: {}", e)))?;

        socket
            .connect((target, 80))
            .map_err(|e| StealthScanError::NetworkError(format!("Failed to connect: {}", e)))?;

        let local_addr = socket.local_addr().map_err(|e| {
            StealthScanError::NetworkError(format!("Failed to get local address: {}", e))
        })?;

        Ok(local_addr.ip())
    }

    async fn send_packet(
        &self,
        _packet: &[u8],
        _target: IpAddr,
        _port: u16,
    ) -> Result<(), StealthScanError> {
        Err(StealthScanError::UnsupportedPlatform(
            "Raw packet sending not supported by TcpConnector".to_string(),
        ))
    }

    async fn receive_response(&self, _timeout: Duration) -> Result<Vec<u8>, StealthScanError> {
        Err(StealthScanError::UnsupportedPlatform(
            "Raw packet receiving not supported by TcpConnector".to_string(),
        ))
    }
}

// Mock network utilities for testing
#[cfg(test)]
pub struct MockNetworkUtils {
    pub responses: std::collections::VecDeque<Vec<u8>>,
    pub send_error: Option<StealthScanError>,
    pub receive_error: Option<StealthScanError>,
}

#[cfg(test)]
impl MockNetworkUtils {
    pub fn new() -> Self {
        Self {
            responses: std::collections::VecDeque::new(),
            send_error: None,
            receive_error: None,
        }
    }

    pub fn add_response(&mut self, response: Vec<u8>) {
        self.responses.push_back(response);
    }

    pub fn set_send_error(&mut self, error: StealthScanError) {
        self.send_error = Some(error);
    }

    pub fn set_receive_error(&mut self, error: StealthScanError) {
        self.receive_error = Some(error);
    }
}

#[cfg(test)]
#[async_trait]
impl NetworkUtils for MockNetworkUtils {
    async fn get_local_ip(&self, target: IpAddr) -> Result<IpAddr, StealthScanError> {
        match target {
            IpAddr::V4(_) => Ok(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100))),
            IpAddr::V6(_) => Ok(IpAddr::V6(std::net::Ipv6Addr::new(
                0xfe80, 0, 0, 0, 0, 0, 0, 1,
            ))),
        }
    }

    async fn send_packet(
        &self,
        _packet: &[u8],
        _target: IpAddr,
        _port: u16,
    ) -> Result<(), StealthScanError> {
        if let Some(ref error) = self.send_error {
            return Err(error.clone());
        }
        Ok(())
    }

    async fn receive_response(&self, _timeout: Duration) -> Result<Vec<u8>, StealthScanError> {
        if let Some(ref error) = self.receive_error {
            return Err(error.clone());
        }

        // For testing, we can't modify self, so we'll return a default response
        // In real tests, you'd use Arc<Mutex<MockNetworkUtils>> to modify state
        Ok(vec![])
    }
}

// Utility functions for platform detection and privilege checking
pub fn is_platform_supported() -> bool {
    cfg!(unix)
}

pub fn requires_privileges() -> bool {
    cfg!(unix)
}

#[cfg(unix)]
pub fn check_privileges() -> Result<(), StealthScanError> {
    if unsafe { libc::getuid() } != 0 {
        return Err(StealthScanError::PermissionDenied(
            "Root privileges required for raw socket operations".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn check_privileges() -> Result<(), StealthScanError> {
    Err(StealthScanError::UnsupportedPlatform(
        "Raw socket operations not supported on this platform".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_tcp_connector_creation() {
        let connector = TcpConnector::new();
        // Basic creation test
        assert!(true);
    }

    #[tokio::test]
    async fn test_tcp_connector_get_local_ip() {
        let connector = TcpConnector::new();
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        let result = connector.get_local_ip(target).await;
        assert!(result.is_ok());

        let local_ip = result.unwrap();
        assert!(local_ip.is_ipv4());
        assert!(!local_ip.is_unspecified());
    }

    #[test]
    fn test_platform_detection() {
        // Test that platform detection functions work
        let supported = is_platform_supported();
        let requires_priv = requires_privileges();

        #[cfg(unix)]
        {
            assert!(supported);
            assert!(requires_priv);
        }

        #[cfg(not(unix))]
        {
            assert!(!supported);
        }
    }

    #[test]
    fn test_mock_network_utils() {
        let mut mock = MockNetworkUtils::new();
        mock.add_response(vec![1, 2, 3, 4]);
        mock.set_send_error(StealthScanError::NetworkError("Test error".to_string()));

        assert_eq!(mock.responses.len(), 1);
        assert!(mock.send_error.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn test_raw_socket_creation_ipv4() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // This test might fail if not run with sufficient privileges
        match RawSocketManager::new(target) {
            Ok(_) => {
                // Socket created successfully
                assert!(true);
            }
            Err(StealthScanError::RawSocketError(_)) => {
                // Expected if not running with root privileges
                println!("Raw socket creation failed (expected without root privileges)");
                assert!(true);
            }
            Err(e) => {
                panic!("Unexpected error: {:?}", e);
            }
        }
    }

    #[cfg(not(unix))]
    #[test]
    fn test_unsupported_platform() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let manager = RawSocketManager::new(target);

        // Should work on non-Unix platforms, but sending/receiving should fail
        assert!(manager.is_ok());
    }
}
