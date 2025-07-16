use super::OSFingerprint;

/// Utility functions for OS detection

pub fn merge_os_fingerprints(fingerprints: &[OSFingerprint]) -> Option<OSFingerprint> {
    if fingerprints.is_empty() {
        return None;
    }

    if fingerprints.len() == 1 {
        return Some(fingerprints[0].clone());
    }

    // Find the fingerprint with highest confidence
    let best = fingerprints.iter().max_by_key(|fp| fp.confidence)?;

    // Merge details from all fingerprints
    let mut all_details = Vec::new();
    for fp in fingerprints {
        all_details.extend(fp.details.clone());
    }

    // Remove duplicates while preserving order
    all_details.dedup();

    // Use builder pattern to create merged fingerprint
    let mut merged = OSFingerprint::new(
        best.os_family.clone(),
        best.os_name.clone(),
        best.confidence,
    )
    .with_details(all_details);

    // Add optional fields from the best match
    if let Some(ref version) = best.os_version {
        merged = merged.with_version(version.clone());
    }

    if let Some(ref device_type) = best.device_type {
        merged = merged.with_device_type(device_type.clone());
    }

    if let Some(ref cpe) = best.cpe {
        merged = merged.with_cpe(cpe.clone());
    }

    if let Some(ref vendor) = best.vendor {
        merged = merged.with_vendor(vendor.clone());
    }

    if let Some(ref architecture) = best.architecture {
        merged = merged.with_architecture(architecture.clone());
    }

    Some(merged)
}

pub(crate) fn confidence_to_text(confidence: u8) -> &'static str {
    match confidence {
        90..=100 => "Very High",
        75..=89 => "High",
        60..=74 => "Medium",
        40..=59 => "Low",
        _ => "Very Low",
    }
}

pub fn is_mobile_os(os_family: &str) -> bool {
    matches!(os_family, "Android" | "iOS" | "Windows Mobile")
}

pub fn is_server_os(os_name: &str) -> bool {
    let server_indicators = [
        "Server",
        "server",
        "RHEL",
        "CentOS",
        "Ubuntu Server",
        "Windows Server",
        "FreeBSD",
        "OpenBSD",
        "NetBSD",
    ];

    server_indicators
        .iter()
        .any(|&indicator| os_name.contains(indicator))
}

pub fn is_network_device(os_family: &str) -> bool {
    matches!(os_family, "Cisco IOS" | "JunOS" | "Embedded")
}

pub(crate) fn normalize_os_name(os_name: &str) -> String {
    // Remove version numbers and normalize common variations
    let normalized = os_name
        .replace("Microsoft ", "")
        .replace("Apple ", "")
        .replace("Google ", "");

    // Handle common variations
    if normalized.starts_with("Windows") {
        if normalized.contains("10") {
            "Windows 10".to_string()
        } else if normalized.contains("11") {
            "Windows 11".to_string()
        } else if normalized.contains("Server") {
            "Windows Server".to_string()
        } else {
            "Windows".to_string()
        }
    } else if normalized.starts_with("macOS") || normalized.starts_with("Mac OS") {
        "macOS".to_string()
    } else if normalized.starts_with("Ubuntu") {
        "Ubuntu Linux".to_string()
    } else if normalized.starts_with("CentOS") || normalized.starts_with("RHEL") {
        "CentOS/RHEL".to_string()
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_to_text() {
        assert_eq!(confidence_to_text(95), "Very High");
        assert_eq!(confidence_to_text(80), "High");
        assert_eq!(confidence_to_text(65), "Medium");
        assert_eq!(confidence_to_text(45), "Low");
        assert_eq!(confidence_to_text(25), "Very Low");
    }

    #[test]
    fn test_is_mobile_os() {
        assert!(is_mobile_os("Android"));
        assert!(is_mobile_os("iOS"));
        assert!(!is_mobile_os("Linux"));
        assert!(!is_mobile_os("Windows"));
    }

    #[test]
    fn test_is_server_os() {
        assert!(is_server_os("Ubuntu Server"));
        assert!(is_server_os("Windows Server"));
        assert!(is_server_os("CentOS"));
        assert!(is_server_os("FreeBSD"));
        assert!(!is_server_os("Windows 10"));
        assert!(!is_server_os("macOS"));
    }

    #[test]
    fn test_is_network_device() {
        assert!(is_network_device("Cisco IOS"));
        assert!(is_network_device("JunOS"));
        assert!(is_network_device("Embedded"));
        assert!(!is_network_device("Linux"));
        assert!(!is_network_device("Windows"));
    }

    #[test]
    fn test_normalize_os_name() {
        assert_eq!(normalize_os_name("Microsoft Windows 10"), "Windows 10");
        assert_eq!(normalize_os_name("Apple macOS"), "macOS");
        assert_eq!(normalize_os_name("Google Android"), "Android");
        assert_eq!(normalize_os_name("Ubuntu 20.04"), "Ubuntu Linux");
        assert_eq!(normalize_os_name("CentOS 8"), "CentOS/RHEL");
    }

    #[test]
    fn test_merge_os_fingerprints() {
        let fp1 = OSFingerprint::new("Linux".to_string(), "Ubuntu Linux".to_string(), 80)
            .with_version("20.04".to_string())
            .with_details(vec!["TTL: 64".to_string()]);

        let fp2 = OSFingerprint::new("Linux".to_string(), "Linux".to_string(), 90)
            .with_details(vec!["Window Size: 29200".to_string()]);

        let merged = merge_os_fingerprints(&[fp1, fp2]).unwrap();
        assert_eq!(merged.confidence, 90);
        assert_eq!(merged.details.len(), 2);
        assert!(merged.details.contains(&"TTL: 64".to_string()));
        assert!(merged.details.contains(&"Window Size: 29200".to_string()));
        assert!(merged.is_high_confidence());
    }
}
