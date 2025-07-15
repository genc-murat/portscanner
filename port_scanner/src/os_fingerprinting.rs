use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSFingerprint {
    pub os_family: String,
    pub os_name: String,
    pub os_version: Option<String>,
    pub device_type: Option<String>,
    pub confidence: u8, // 0-100
    pub cpe: Option<String>,
    pub vendor: Option<String>,
    pub architecture: Option<String>,
    pub details: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NetworkCharacteristics {
    pub ttl: Option<u8>,
    pub window_size: Option<u16>,
    pub mss: Option<u16>,
    pub tcp_options: Vec<u8>,
    pub tcp_flags_response: u8,
    pub icmp_response: bool,
    pub closed_port_response: Option<String>,
    pub sequence_predictability: Option<f64>,
    pub timestamps: bool,
    pub window_scaling: bool,
    pub sack_permitted: bool,
}

#[derive(Debug, Clone)]
pub struct OSSignature {
    pub os_family: String,
    pub os_name: String,
    pub ttl_range: (u8, u8),
    pub window_sizes: Vec<u16>,
    pub mss_values: Vec<u16>,
    pub tcp_options_patterns: Vec<Vec<u8>>,
    pub sequence_predictability_range: (f64, f64),
    pub common_flags: Vec<u8>,
    pub supports_timestamps: bool,
    pub supports_window_scaling: bool,
    pub supports_sack: bool,
    pub closed_port_behavior: String,
    pub confidence_weight: f64,
}

pub struct OSDetector {
    signatures: Vec<OSSignature>,
    #[allow(dead_code)]
    ping_cache: HashMap<IpAddr, NetworkCharacteristics>,
}

impl OSDetector {
    pub fn new() -> Self {
        let mut detector = Self {
            signatures: Vec::new(),
            ping_cache: HashMap::new(),
        };

        detector.load_os_signatures();
        detector
    }

    pub async fn detect_os(&mut self, target: IpAddr, open_ports: &[u16]) -> Option<OSFingerprint> {
        println!("🔍 Performing OS detection for {}", target);

        let characteristics = self.gather_characteristics(target, open_ports).await?;

        let matches = self.match_signatures(&characteristics);

        if matches.is_empty() {
            return None;
        }

        self.calculate_best_match(matches, &characteristics)
    }

    async fn gather_characteristics(
        &mut self,
        target: IpAddr,
        open_ports: &[u16],
    ) -> Option<NetworkCharacteristics> {
        let mut characteristics = NetworkCharacteristics {
            ttl: None,
            window_size: None,
            mss: None,
            tcp_options: Vec::new(),
            tcp_flags_response: 0,
            icmp_response: false,
            closed_port_response: None,
            sequence_predictability: None,
            timestamps: false,
            window_scaling: false,
            sack_permitted: false,
        };

        // Test 1: TCP connect to open port for basic characteristics
        if let Some(&open_port) = open_ports.first() {
            if let Some(tcp_info) = self.tcp_connect_probe(target, open_port).await {
                characteristics.window_size = tcp_info.window_size;
                characteristics.tcp_options = tcp_info.tcp_options;
                characteristics.timestamps = tcp_info.timestamps;
                characteristics.window_scaling = tcp_info.window_scaling;
                characteristics.sack_permitted = tcp_info.sack_permitted;
            }
        }

        // Test 2: TCP SYN to closed port
        let closed_port = self.find_closed_port(target).await;
        if let Some(closed_port) = closed_port {
            characteristics.closed_port_response =
                self.tcp_syn_closed_port(target, closed_port).await;
        }

        // Test 3: Simple TTL estimation
        characteristics.ttl = self.estimate_ttl(target, open_ports).await;

        Some(characteristics)
    }

    async fn tcp_connect_probe(&self, target: IpAddr, port: u16) -> Option<NetworkCharacteristics> {
        let socket_addr = std::net::SocketAddr::new(target, port);

        match timeout(Duration::from_secs(3), TcpStream::connect(socket_addr)).await {
            Ok(Ok(_)) => {
                // Basic characteristics from successful connection
                Some(NetworkCharacteristics {
                    ttl: None,
                    window_size: Some(65535), // Default assumption
                    mss: Some(1460),          // Common MSS value
                    tcp_options: Vec::new(),
                    tcp_flags_response: 0x12, // SYN+ACK
                    icmp_response: false,
                    closed_port_response: None,
                    sequence_predictability: None,
                    timestamps: true,     // Most modern systems support this
                    window_scaling: true, // Most modern systems support this
                    sack_permitted: true, // Most modern systems support this
                })
            }
            _ => None,
        }
    }

    async fn tcp_syn_closed_port(&self, target: IpAddr, port: u16) -> Option<String> {
        let socket_addr = std::net::SocketAddr::new(target, port);

        match timeout(Duration::from_secs(1), TcpStream::connect(socket_addr)).await {
            Ok(Err(_)) => Some("RST".to_string()),
            Err(_) => Some("TIMEOUT".to_string()),
            Ok(Ok(_)) => Some("OPEN".to_string()), // Unexpected
        }
    }

    async fn find_closed_port(&self, target: IpAddr) -> Option<u16> {
        let test_ports = [
            1, 3, 4, 6, 7, 9, 13, 17, 19, 20, // Uncommon high ports
            65534, 65533, 65532, 65531, 65530, // Random ports in different ranges
            1234, 5678, 9876, 12345, 54321, // Ports that are rarely used
            666, 1337, 31337, 8192, 16384,
        ];

        for &port in &test_ports {
            let socket_addr = std::net::SocketAddr::new(target, port);

            match timeout(Duration::from_millis(300), TcpStream::connect(socket_addr)).await {
                Ok(Err(e)) => {
                    // Check if it's actually a connection refused (port closed)
                    if let Some(os_error) = e.raw_os_error() {
                        #[cfg(unix)]
                        if os_error == libc::ECONNREFUSED {
                            return Some(port);
                        }

                        #[cfg(windows)]
                        if os_error == 10061 {
                            // WSAECONNREFUSED
                            return Some(port);
                        }
                    }

                    // Generic connection error, likely closed port
                    if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        return Some(port);
                    }

                    continue; // Other error types, try next port
                }
                Err(_) => {
                    // Timeout - could be filtered, try next
                    continue;
                }
                Ok(Ok(_)) => {
                    // Port is open, try next
                    continue;
                }
            }
        }

        // If we can't find a closed port, generate a random high port
        // This is less reliable but better than nothing
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let random_port = rng.gen_range(49152..65535); // Dynamic/private port range
            let socket_addr = std::net::SocketAddr::new(target, random_port);

            match timeout(Duration::from_millis(200), TcpStream::connect(socket_addr)).await {
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    return Some(random_port);
                }
                _ => continue,
            }
        }

        // Last resort: assume port 1 is closed (very likely)
        Some(1)
    }

    async fn estimate_ttl(&self, target: IpAddr, open_ports: &[u16]) -> Option<u8> {
        // Simple TTL estimation based on common values
        // This is a simplified approach - real TTL detection would require raw sockets

        if let Some(&port) = open_ports.first() {
            let socket_addr = std::net::SocketAddr::new(target, port);
            let start = Instant::now();

            match timeout(Duration::from_millis(100), TcpStream::connect(socket_addr)).await {
                Ok(Ok(_)) => {
                    let rtt = start.elapsed().as_millis();

                    // Estimate TTL based on RTT (very rough approximation)
                    if rtt < 10 {
                        Some(64) // Local network, likely Linux/Unix
                    } else if rtt < 50 {
                        Some(128) // Nearby, possibly Windows
                    } else if rtt < 200 {
                        Some(64) // Internet, likely Linux server
                    } else {
                        Some(255) // Far away or router/embedded device
                    }
                }
                _ => None,
            }
        } else {
            None
        }
    }

    /// Match network characteristics against known OS signatures
    ///
    /// # Note
    /// This method is primarily intended for internal use and testing.
    #[doc(hidden)]
    pub fn match_signatures(
        &self,
        characteristics: &NetworkCharacteristics,
    ) -> Vec<(f64, &OSSignature)> {
        let mut matches = Vec::new();

        for signature in &self.signatures {
            let mut score = 0.0;
            let mut total_weight = 0.0;

            // TTL matching
            if let Some(ttl) = characteristics.ttl {
                total_weight += 0.3;
                if ttl >= signature.ttl_range.0 && ttl <= signature.ttl_range.1 {
                    score += 0.3;
                }
            }

            // Window size matching
            if let Some(window_size) = characteristics.window_size {
                total_weight += 0.2;
                if signature.window_sizes.contains(&window_size) {
                    score += 0.2;
                } else {
                    // Partial match for similar window sizes
                    for &sig_window in &signature.window_sizes {
                        let diff = (window_size as i32 - sig_window as i32).abs();
                        if diff < 8192 {
                            // Allow some variance
                            score += 0.1;
                            break;
                        }
                    }
                }
            }

            // MSS matching
            if let Some(mss) = characteristics.mss {
                total_weight += 0.15;
                if signature.mss_values.contains(&mss) {
                    score += 0.15;
                }
            }

            // Feature flags matching
            total_weight += 0.2;
            let mut feature_score = 0.0;
            if characteristics.timestamps == signature.supports_timestamps {
                feature_score += 0.07;
            }
            if characteristics.window_scaling == signature.supports_window_scaling {
                feature_score += 0.07;
            }
            if characteristics.sack_permitted == signature.supports_sack {
                feature_score += 0.06;
            }
            score += feature_score;

            // Closed port behavior
            if let Some(ref behavior) = characteristics.closed_port_response {
                total_weight += 0.15;
                if behavior == &signature.closed_port_behavior {
                    score += 0.15;
                }
            }

            if total_weight > 0.0 {
                let normalized_score = (score / total_weight) * signature.confidence_weight;
                if normalized_score > 0.2 {
                    // Lower threshold for simpler detection
                    matches.push((normalized_score, signature));
                }
            }
        }

        matches.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
        matches
    }

    fn calculate_best_match(
        &self,
        matches: Vec<(f64, &OSSignature)>,
        characteristics: &NetworkCharacteristics,
    ) -> Option<OSFingerprint> {
        if matches.is_empty() {
            return None;
        }

        let (score, best_match) = &matches[0];
        let confidence = (*score * 100.0) as u8;

        let mut details = Vec::new();

        if let Some(ttl) = characteristics.ttl {
            details.push(format!("TTL: {}", ttl));
        }
        if let Some(window_size) = characteristics.window_size {
            details.push(format!("Window Size: {}", window_size));
        }
        if let Some(mss) = characteristics.mss {
            details.push(format!("MSS: {}", mss));
        }
        if characteristics.timestamps {
            details.push("TCP Timestamps: Enabled".to_string());
        }
        if characteristics.window_scaling {
            details.push("Window Scaling: Enabled".to_string());
        }
        if characteristics.sack_permitted {
            details.push("SACK: Enabled".to_string());
        }
        if let Some(ref behavior) = characteristics.closed_port_response {
            details.push(format!("Closed Port Response: {}", behavior));
        }

        Some(OSFingerprint {
            os_family: best_match.os_family.clone(),
            os_name: best_match.os_name.clone(),
            os_version: None,
            device_type: None,
            confidence,
            cpe: None,
            vendor: None,
            architecture: None,
            details,
        })
    }

    fn load_os_signatures(&mut self) {
        // Linux signatures
        self.signatures.push(OSSignature {
            os_family: "Linux".to_string(),
            os_name: "Linux".to_string(),
            ttl_range: (64, 64),
            window_sizes: vec![5840, 14600, 29200, 65535],
            mss_values: vec![1460, 1440],
            tcp_options_patterns: vec![],
            sequence_predictability_range: (1000000.0, f64::INFINITY),
            common_flags: vec![0x12],
            supports_timestamps: true,
            supports_window_scaling: true,
            supports_sack: true,
            closed_port_behavior: "RST".to_string(),
            confidence_weight: 1.0,
        });

        // Windows signatures
        self.signatures.push(OSSignature {
            os_family: "Windows".to_string(),
            os_name: "Microsoft Windows".to_string(),
            ttl_range: (128, 128),
            window_sizes: vec![65535, 8192, 16384, 32768],
            mss_values: vec![1460, 1440, 1380],
            tcp_options_patterns: vec![],
            sequence_predictability_range: (0.0, 1000000.0),
            common_flags: vec![0x12],
            supports_timestamps: true,
            supports_window_scaling: true,
            supports_sack: true,
            closed_port_behavior: "RST".to_string(),
            confidence_weight: 1.0,
        });

        // macOS signatures
        self.signatures.push(OSSignature {
            os_family: "macOS".to_string(),
            os_name: "Apple macOS".to_string(),
            ttl_range: (64, 64),
            window_sizes: vec![65535, 32768, 16384],
            mss_values: vec![1460, 1440],
            tcp_options_patterns: vec![],
            sequence_predictability_range: (1000000.0, f64::INFINITY),
            common_flags: vec![0x12],
            supports_timestamps: false,
            supports_window_scaling: true,
            supports_sack: true,
            closed_port_behavior: "RST".to_string(),
            confidence_weight: 0.9,
        });

        // FreeBSD signatures
        self.signatures.push(OSSignature {
            os_family: "FreeBSD".to_string(),
            os_name: "FreeBSD".to_string(),
            ttl_range: (64, 64),
            window_sizes: vec![65535, 32768],
            mss_values: vec![1460],
            tcp_options_patterns: vec![],
            sequence_predictability_range: (1000000.0, f64::INFINITY),
            common_flags: vec![0x12],
            supports_timestamps: true,
            supports_window_scaling: true,
            supports_sack: true,
            closed_port_behavior: "RST".to_string(),
            confidence_weight: 0.8,
        });

        // Cisco IOS signatures
        self.signatures.push(OSSignature {
            os_family: "Cisco IOS".to_string(),
            os_name: "Cisco IOS".to_string(),
            ttl_range: (255, 255),
            window_sizes: vec![4128, 8192],
            mss_values: vec![1460, 536],
            tcp_options_patterns: vec![],
            sequence_predictability_range: (0.0, 100000.0),
            common_flags: vec![0x12],
            supports_timestamps: false,
            supports_window_scaling: false,
            supports_sack: false,
            closed_port_behavior: "RST".to_string(),
            confidence_weight: 0.9,
        });

        // Android signatures (Linux-based but different characteristics)
        self.signatures.push(OSSignature {
            os_family: "Android".to_string(),
            os_name: "Google Android".to_string(),
            ttl_range: (64, 64),
            window_sizes: vec![14600, 29200],
            mss_values: vec![1460],
            tcp_options_patterns: vec![],
            sequence_predictability_range: (1000000.0, f64::INFINITY),
            common_flags: vec![0x12],
            supports_timestamps: true,
            supports_window_scaling: true,
            supports_sack: true,
            closed_port_behavior: "RST".to_string(),
            confidence_weight: 0.85,
        });
    }
}

pub fn format_os_info(os_info: &OSFingerprint) -> String {
    let mut parts = vec![os_info.os_name.clone()];

    if let Some(version) = &os_info.os_version {
        parts.push(format!("({})", version));
    }

    if let Some(device_type) = &os_info.device_type {
        parts.push(format!("[{}]", device_type));
    }

    if os_info.confidence < 70 {
        parts.push(format!("({}% confidence)", os_info.confidence));
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_detector_creation() {
        let detector = OSDetector::new();
        assert!(!detector.signatures.is_empty());
    }

    #[test]
    fn test_signature_matching() {
        let detector = OSDetector::new();

        let characteristics = NetworkCharacteristics {
            ttl: Some(64),
            window_size: Some(65535),
            mss: Some(1460),
            tcp_options: vec![],
            tcp_flags_response: 0x12,
            icmp_response: false,
            closed_port_response: Some("RST".to_string()),
            sequence_predictability: Some(1000000.0),
            timestamps: true,
            window_scaling: true,
            sack_permitted: true,
        };

        let matches = detector.match_signatures(&characteristics);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_os_info_formatting() {
        let os_info = OSFingerprint {
            os_family: "Linux".to_string(),
            os_name: "Ubuntu Linux".to_string(),
            os_version: Some("20.04".to_string()),
            device_type: Some("Server".to_string()),
            confidence: 95,
            cpe: Some("cpe:/o:canonical:ubuntu_linux:20.04".to_string()),
            vendor: Some("Canonical".to_string()),
            architecture: Some("x86_64".to_string()),
            details: vec!["TTL: 64".to_string(), "Window Size: 29200".to_string()],
        };

        let formatted = format_os_info(&os_info);
        assert!(formatted.contains("Ubuntu Linux"));
        assert!(formatted.contains("20.04"));
        assert!(formatted.contains("Server"));
    }
}
