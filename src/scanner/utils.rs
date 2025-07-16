use std::net::{IpAddr, ToSocketAddrs};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

pub fn resolve_hostname(hostname: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(ip);
    }

    let socket_addrs = format!("{}:80", hostname)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve hostname: {}", e))?;

    for addr in socket_addrs {
        return Ok(addr.ip());
    }

    Err("Failed to resolve hostname".to_string())
}

pub async fn grab_banner_from_stream(
    stream: &mut TcpStream,
    port: u16,
    timeout_duration: Duration,
) -> Option<String> {
    match port {
        21 | 22 | 23 | 25 | 110 | 143 | 993 | 995 => read_banner(stream, timeout_duration).await,
        80 | 8080 | 8081 | 8000 | 3000 => grab_http_banner(stream, timeout_duration).await,
        443 | 8443 => read_banner(stream, timeout_duration).await,
        53 => Some("DNS Server".to_string()),
        3306 => read_banner(stream, timeout_duration).await,
        5432 => read_banner(stream, timeout_duration).await,
        1433 => read_banner(stream, timeout_duration).await,
        1521 => read_banner(stream, timeout_duration).await,
        27017 => read_banner(stream, timeout_duration).await,
        6379 => read_banner(stream, timeout_duration).await,
        _ => read_banner(stream, timeout_duration).await,
    }
}

async fn read_banner(stream: &mut TcpStream, timeout_duration: Duration) -> Option<String> {
    use tokio::io::AsyncReadExt;
    let mut buffer = [0; 1024];
    match timeout(timeout_duration, stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let banner = String::from_utf8_lossy(&buffer[..n]);
            let clean_banner = banner
                .trim()
                .lines()
                .next()
                .unwrap_or("")
                .trim_end_matches('\r')
                .trim_end_matches('\n')
                .to_string();
            if clean_banner.is_empty() {
                None
            } else {
                Some(clean_banner)
            }
        }
        _ => None,
    }
}

async fn grab_http_banner(stream: &mut TcpStream, timeout_duration: Duration) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let http_request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(http_request).await.is_err() {
        return None;
    }
    let mut buffer = [0; 2048];
    match timeout(timeout_duration, stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buffer[..n]);
            for line in response.lines() {
                if line.to_lowercase().starts_with("server:") {
                    return Some(line.trim().to_string());
                }
            }
            if let Some(first_line) = response.lines().next() {
                if first_line.contains("HTTP/") {
                    return Some(format!("HTTP Server ({})", first_line.trim()));
                }
            }
            Some("HTTP Server".to_string())
        }
        _ => None,
    }
}

#[cfg(unix)]
pub fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}
