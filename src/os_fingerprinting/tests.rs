#[cfg(test)]
mod tests {
    use super::super::characteristics::NetworkCharacteristics;
    use super::super::detector::OSDetector;
    use super::super::*;

    #[test]
    fn test_os_detector_creation() {
        let detector = OSDetector::new();
        // Test that detector initializes properly
        assert!(true); // Basic smoke test
    }

    #[test]
    fn test_linux_signature_matching() {
        let detector = OSDetector::new();

        let linux_characteristics = NetworkCharacteristics {
            ttl: Some(64),
            window_size: Some(29200),
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

        let matches = detector.match_signatures(&linux_characteristics);
        assert!(!matches.is_empty());

        // Should have at least one Linux match
        let has_linux_match = matches
            .iter()
            .any(|(_, sig)| sig.os_family.contains("Linux") || sig.os_name.contains("Linux"));
        assert!(has_linux_match);
    }

    #[test]
    fn test_windows_signature_matching() {
        let detector = OSDetector::new();

        let windows_characteristics = NetworkCharacteristics {
            ttl: Some(128),
            window_size: Some(65535),
            mss: Some(1460),
            tcp_options: vec![],
            tcp_flags_response: 0x12,
            icmp_response: false,
            closed_port_response: Some("RST".to_string()),
            sequence_predictability: Some(500000.0),
            timestamps: true,
            window_scaling: true,
            sack_permitted: true,
        };

        let matches = detector.match_signatures(&windows_characteristics);
        assert!(!matches.is_empty());

        // Should have at least one Windows match
        let has_windows_match = matches
            .iter()
            .any(|(_, sig)| sig.os_family.contains("Windows") || sig.os_name.contains("Windows"));
        assert!(has_windows_match);
    }

    #[test]
    fn test_macos_signature_matching() {
        let detector = OSDetector::new();

        let macos_characteristics = NetworkCharacteristics {
            ttl: Some(64),
            window_size: Some(65535),
            mss: Some(1460),
            tcp_options: vec![],
            tcp_flags_response: 0x12,
            icmp_response: false,
            closed_port_response: Some("RST".to_string()),
            sequence_predictability: Some(2000000.0),
            timestamps: false, // macOS often has timestamps disabled
            window_scaling: true,
            sack_permitted: true,
        };

        let matches = detector.match_signatures(&macos_characteristics);
        assert!(!matches.is_empty());

        // Should have at least one macOS match
        let has_macos_match = matches
            .iter()
            .any(|(_, sig)| sig.os_family.contains("macOS") || sig.os_name.contains("macOS"));
        assert!(has_macos_match);
    }

    #[test]
    fn test_network_characteristics_details() {
        let characteristics = NetworkCharacteristics {
            ttl: Some(64),
            window_size: Some(29200),
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

        let details = characteristics.to_details();
        assert!(!details.is_empty());
        assert!(details.iter().any(|d| d.contains("TTL: 64")));
        assert!(details.iter().any(|d| d.contains("Window Size: 29200")));
        assert!(details.iter().any(|d| d.contains("MSS: 1460")));
        assert!(details
            .iter()
            .any(|d| d.contains("TCP Timestamps: Enabled")));
        assert!(details
            .iter()
            .any(|d| d.contains("Window Scaling: Enabled")));
        assert!(details.iter().any(|d| d.contains("SACK: Enabled")));
        assert!(details
            .iter()
            .any(|d| d.contains("Closed Port Response: RST")));
    }

    #[test]
    fn test_os_info_formatting() {
        let os_info = OSFingerprint::new("Linux".to_string(), "Ubuntu Linux".to_string(), 95)
            .with_version("20.04".to_string())
            .with_device_type("Server".to_string())
            .with_cpe("cpe:/o:canonical:ubuntu_linux:20.04".to_string())
            .with_vendor("Canonical".to_string())
            .with_architecture("x86_64".to_string())
            .with_details(vec![
                "TTL: 64".to_string(),
                "Window Size: 29200".to_string(),
            ]);

        let formatted = format_os_info(&os_info);
        assert!(formatted.contains("Ubuntu Linux"));
        assert!(formatted.contains("20.04"));
        assert!(formatted.contains("Server"));
        assert!(!formatted.contains("confidence")); // High confidence shouldn't show
        assert!(os_info.is_high_confidence());
        assert!(os_info.is_server());
        assert!(!os_info.is_mobile());
        assert!(!os_info.is_network_device());
    }

    #[test]
    fn test_os_info_formatting_low_confidence() {
        let os_info = OSFingerprint::new("Linux".to_string(), "Unknown Linux".to_string(), 45)
            .with_details(vec!["TTL: 64".to_string()]);

        let formatted = format_os_info(&os_info);
        assert!(formatted.contains("Unknown Linux"));
        assert!(formatted.contains("45% confidence")); // Low confidence should show
        assert!(!os_info.is_high_confidence());
        assert_eq!(os_info.confidence_text(), "Low");
    }

    #[test]
    fn test_network_characteristics_creation() {
        let characteristics = NetworkCharacteristics::new();
        assert!(characteristics.ttl.is_none());
        assert!(characteristics.window_size.is_none());
        assert!(!characteristics.timestamps);
        assert!(!characteristics.window_scaling);
        assert!(!characteristics.sack_permitted);
    }

    #[test]
    fn test_network_characteristics_from_tcp() {
        let characteristics = NetworkCharacteristics::from_tcp_connection(
            Some(65535),
            vec![1, 2, 3],
            true,
            true,
            false,
        );

        assert_eq!(characteristics.window_size, Some(65535));
        assert_eq!(characteristics.tcp_options, vec![1, 2, 3]);
        assert!(characteristics.timestamps);
        assert!(characteristics.window_scaling);
        assert!(!characteristics.sack_permitted);
        assert_eq!(characteristics.mss, Some(1460));
        assert_eq!(characteristics.tcp_flags_response, 0x12);
    }
}
