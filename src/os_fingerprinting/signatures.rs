use super::OSSignature;

pub struct OSSignatureDatabase {
    signatures: Vec<OSSignature>,
}

impl OSSignatureDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            signatures: Vec::new(),
        };

        db.load_default_signatures();
        db
    }

    pub fn get_signatures(&self) -> &[OSSignature] {
        &self.signatures
    }

    pub fn add_signature(&mut self, signature: OSSignature) {
        self.signatures.push(signature);
    }

    fn load_default_signatures(&mut self) {
        self.load_linux_signatures();
        self.load_windows_signatures();
        self.load_macos_signatures();
        self.load_bsd_signatures();
        self.load_network_device_signatures();
        self.load_mobile_signatures();
    }

    fn load_linux_signatures(&mut self) {
        let linux = OSSignature::new("Linux", "Linux", 64, "RST", 1.0)
            .with_window_sizes(vec![5840, 14600, 29200, 65535])
            .with_mss_values(vec![1460, 1440])
            .with_tcp_features(true, true, true)
            .with_sequence_predictability((1000000.0, f64::INFINITY));

        self.signatures.push(linux);

        // Ubuntu specific
        let ubuntu = OSSignature::new("Linux", "Ubuntu Linux", 64, "RST", 0.95)
            .with_window_sizes(vec![29200, 14600])
            .with_mss_values(vec![1460])
            .with_tcp_features(true, true, true)
            .with_sequence_predictability((1000000.0, f64::INFINITY));

        self.signatures.push(ubuntu);

        // CentOS/RHEL specific
        let centos = OSSignature::new("Linux", "CentOS/RHEL", 64, "RST", 0.9)
            .with_window_sizes(vec![14600, 5840])
            .with_mss_values(vec![1460, 1440])
            .with_tcp_features(true, true, true)
            .with_sequence_predictability((1000000.0, f64::INFINITY));

        self.signatures.push(centos);
    }

    fn load_windows_signatures(&mut self) {
        // Modern Windows (10/11/Server 2016+)
        let windows_modern = OSSignature::new("Windows", "Microsoft Windows", 128, "RST", 1.0)
            .with_window_sizes(vec![65535, 8192, 16384, 32768])
            .with_mss_values(vec![1460, 1440, 1380])
            .with_tcp_features(true, true, true)
            .with_sequence_predictability((0.0, 1000000.0));

        self.signatures.push(windows_modern);

        // Windows 10 specific
        let windows10 = OSSignature::new("Windows", "Microsoft Windows 10", 128, "RST", 0.95)
            .with_window_sizes(vec![65535, 32768])
            .with_mss_values(vec![1460])
            .with_tcp_features(true, true, true)
            .with_sequence_predictability((0.0, 1000000.0));

        self.signatures.push(windows10);

        // Windows Server
        let windows_server =
            OSSignature::new("Windows", "Microsoft Windows Server", 128, "RST", 0.9)
                .with_window_sizes(vec![65535, 16384])
                .with_mss_values(vec![1460, 1440])
                .with_tcp_features(true, true, true)
                .with_sequence_predictability((0.0, 1000000.0));

        self.signatures.push(windows_server);
    }

    fn load_macos_signatures(&mut self) {
        let macos = OSSignature::new("macOS", "Apple macOS", 64, "RST", 0.9)
            .with_window_sizes(vec![65535, 32768, 16384])
            .with_mss_values(vec![1460, 1440])
            .with_tcp_features(false, true, true)
            .with_sequence_predictability((1000000.0, f64::INFINITY));

        self.signatures.push(macos);

        // macOS Big Sur/Monterey specific
        let macos_modern = OSSignature::new("macOS", "Apple macOS (Big Sur+)", 64, "RST", 0.85)
            .with_window_sizes(vec![65535, 32768])
            .with_mss_values(vec![1460])
            .with_tcp_features(true, true, true)
            .with_sequence_predictability((1000000.0, f64::INFINITY));

        self.signatures.push(macos_modern);
    }

    fn load_bsd_signatures(&mut self) {
        // FreeBSD
        let freebsd = OSSignature::new("FreeBSD", "FreeBSD", 64, "RST", 0.8)
            .with_window_sizes(vec![65535, 32768])
            .with_mss_values(vec![1460])
            .with_tcp_features(true, true, true)
            .with_sequence_predictability((1000000.0, f64::INFINITY));

        self.signatures.push(freebsd);

        // OpenBSD
        let openbsd = OSSignature::new("OpenBSD", "OpenBSD", 64, "RST", 0.8)
            .with_window_sizes(vec![16384, 32768])
            .with_mss_values(vec![1460])
            .with_tcp_features(true, true, false)
            .with_sequence_predictability((1000000.0, f64::INFINITY));

        self.signatures.push(openbsd);

        // NetBSD
        let netbsd = OSSignature::new("NetBSD", "NetBSD", 64, "RST", 0.75)
            .with_window_sizes(vec![32768, 65535])
            .with_mss_values(vec![1460])
            .with_tcp_features(true, true, true)
            .with_sequence_predictability((1000000.0, f64::INFINITY));

        self.signatures.push(netbsd);
    }

    fn load_network_device_signatures(&mut self) {
        // Cisco IOS
        let cisco_ios = OSSignature::new("Cisco IOS", "Cisco IOS", 255, "RST", 0.9)
            .with_window_sizes(vec![4128, 8192])
            .with_mss_values(vec![1460, 536])
            .with_tcp_features(false, false, false)
            .with_sequence_predictability((0.0, 100000.0));

        self.signatures.push(cisco_ios);

        // Juniper JunOS
        let junos = OSSignature::new("JunOS", "Juniper JunOS", 64, "RST", 0.85)
            .with_window_sizes(vec![16384, 32768])
            .with_mss_values(vec![1460])
            .with_tcp_features(true, true, true)
            .with_sequence_predictability((1000000.0, f64::INFINITY));

        self.signatures.push(junos);

        // Generic embedded/router
        let embedded = OSSignature::new("Embedded", "Embedded/Router Device", 255, "RST", 0.6)
            .with_window_sizes(vec![4096, 8192, 16384])
            .with_mss_values(vec![1460, 1024, 536])
            .with_tcp_features(false, false, false)
            .with_sequence_predictability((0.0, 1000000.0));

        self.signatures.push(embedded);
    }

    fn load_mobile_signatures(&mut self) {
        // Android (Linux-based but different characteristics)
        let android = OSSignature::new("Android", "Google Android", 64, "RST", 0.85)
            .with_window_sizes(vec![14600, 29200])
            .with_mss_values(vec![1460])
            .with_tcp_features(true, true, true)
            .with_sequence_predictability((1000000.0, f64::INFINITY));

        self.signatures.push(android);

        // iOS
        let ios = OSSignature::new("iOS", "Apple iOS", 64, "RST", 0.8)
            .with_window_sizes(vec![65535, 32768])
            .with_mss_values(vec![1460])
            .with_tcp_features(true, true, true)
            .with_sequence_predictability((1000000.0, f64::INFINITY));

        self.signatures.push(ios);
    }
}
