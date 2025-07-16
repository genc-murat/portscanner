use super::signatures::OSSignatureDatabase;
use super::testing::NetworkTester;
use super::{NetworkCharacteristics, OSFingerprint, OSSignature};
use std::collections::HashMap;
use std::net::IpAddr;

pub struct OSDetector {
    signature_db: OSSignatureDatabase,
    network_tester: NetworkTester,
    #[allow(dead_code)]
    ping_cache: HashMap<IpAddr, NetworkCharacteristics>,
}

impl OSDetector {
    pub fn new() -> Self {
        Self {
            signature_db: OSSignatureDatabase::new(),
            network_tester: NetworkTester::new(),
            ping_cache: HashMap::new(),
        }
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
        let mut characteristics = NetworkCharacteristics::new();

        // Test 1: TCP connect to open port for basic characteristics
        if let Some(&open_port) = open_ports.first() {
            if let Some(tcp_info) = self
                .network_tester
                .tcp_connect_probe(target, open_port)
                .await
            {
                characteristics.window_size = tcp_info.window_size;
                characteristics.tcp_options = tcp_info.tcp_options;
                characteristics.timestamps = tcp_info.timestamps;
                characteristics.window_scaling = tcp_info.window_scaling;
                characteristics.sack_permitted = tcp_info.sack_permitted;
            }
        }

        // Test 2: TCP SYN to closed port
        let closed_port = self.network_tester.find_closed_port(target).await;
        if let Some(closed_port) = closed_port {
            if let Some(response) = self
                .network_tester
                .tcp_syn_closed_port(target, closed_port)
                .await
            {
                characteristics.set_closed_port_response(response);
            }
        }

        // Test 3: Simple TTL estimation
        if let Some(ttl) = self.network_tester.estimate_ttl(target, open_ports).await {
            characteristics.set_ttl(ttl);
        }

        Some(characteristics)
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

        for signature in self.signature_db.get_signatures() {
            let score = self.calculate_signature_score(characteristics, signature);

            if score > 0.2 {
                // Lower threshold for simpler detection
                matches.push((score, signature));
            }
        }

        matches.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
        matches
    }

    fn calculate_signature_score(
        &self,
        characteristics: &NetworkCharacteristics,
        signature: &OSSignature,
    ) -> f64 {
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
            (score / total_weight) * signature.confidence_weight
        } else {
            0.0
        }
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

        // Use the builder pattern with the new methods
        let mut fingerprint = OSFingerprint::new(
            best_match.os_family.clone(),
            best_match.os_name.clone(),
            confidence,
        )
        .with_details(characteristics.to_details());

        // Determine device type based on OS characteristics
        if fingerprint.is_server() {
            fingerprint = fingerprint.with_device_type("Server".to_string());
        } else if fingerprint.is_mobile() {
            fingerprint = fingerprint.with_device_type("Mobile Device".to_string());
        } else if fingerprint.is_network_device() {
            fingerprint = fingerprint.with_device_type("Network Device".to_string());
        } else {
            fingerprint = fingerprint.with_device_type("Desktop/Workstation".to_string());
        }

        // Add vendor information
        let vendor = match best_match.os_family.as_str() {
            "Windows" => "Microsoft".to_string(),
            "macOS" | "iOS" => "Apple".to_string(),
            "Android" => "Google".to_string(),
            "Cisco IOS" => "Cisco".to_string(),
            "JunOS" => "Juniper".to_string(),
            "FreeBSD" | "OpenBSD" | "NetBSD" => "BSD Community".to_string(),
            _ => "Open Source Community".to_string(),
        };
        fingerprint = fingerprint.with_vendor(vendor);

        // Add architecture guess based on characteristics
        if let Some(window_size) = characteristics.window_size {
            let arch = if window_size >= 65535 {
                "x86_64".to_string()
            } else {
                "x86".to_string()
            };
            fingerprint = fingerprint.with_architecture(arch);
        }

        // Generate CPE if possible
        let cpe = self.generate_cpe(&fingerprint);
        if let Some(cpe) = cpe {
            fingerprint = fingerprint.with_cpe(cpe);
        }

        Some(fingerprint)
    }

    fn generate_cpe(&self, fingerprint: &OSFingerprint) -> Option<String> {
        // Generate Common Platform Enumeration identifier
        match fingerprint.os_family.as_str() {
            "Linux" => {
                if fingerprint.os_name.contains("Ubuntu") {
                    Some("cpe:/o:canonical:ubuntu_linux".to_string())
                } else if fingerprint.os_name.contains("CentOS") {
                    Some("cpe:/o:centos:centos".to_string())
                } else {
                    Some("cpe:/o:linux:linux_kernel".to_string())
                }
            }
            "Windows" => {
                if fingerprint.os_name.contains("10") {
                    Some("cpe:/o:microsoft:windows_10".to_string())
                } else if fingerprint.os_name.contains("11") {
                    Some("cpe:/o:microsoft:windows_11".to_string())
                } else if fingerprint.os_name.contains("Server") {
                    Some("cpe:/o:microsoft:windows_server".to_string())
                } else {
                    Some("cpe:/o:microsoft:windows".to_string())
                }
            }
            "macOS" => Some("cpe:/o:apple:macos".to_string()),
            "iOS" => Some("cpe:/o:apple:iphone_os".to_string()),
            "Android" => Some("cpe:/o:google:android".to_string()),
            "FreeBSD" => Some("cpe:/o:freebsd:freebsd".to_string()),
            "OpenBSD" => Some("cpe:/o:openbsd:openbsd".to_string()),
            "NetBSD" => Some("cpe:/o:netbsd:netbsd".to_string()),
            _ => None,
        }
    }
}
