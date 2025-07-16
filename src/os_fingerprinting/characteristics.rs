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

impl NetworkCharacteristics {
    pub fn new() -> Self {
        Self {
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
        }
    }

    pub fn from_tcp_connection(
        window_size: Option<u16>,
        tcp_options: Vec<u8>,
        timestamps: bool,
        window_scaling: bool,
        sack_permitted: bool,
    ) -> Self {
        Self {
            ttl: None,
            window_size,
            mss: Some(1460), // Common MSS value
            tcp_options,
            tcp_flags_response: 0x12, // SYN+ACK
            icmp_response: false,
            closed_port_response: None,
            sequence_predictability: None,
            timestamps,
            window_scaling,
            sack_permitted,
        }
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.ttl = Some(ttl);
    }

    pub fn set_closed_port_response(&mut self, response: String) {
        self.closed_port_response = Some(response);
    }

    pub fn to_details(&self) -> Vec<String> {
        let mut details = Vec::new();

        if let Some(ttl) = self.ttl {
            details.push(format!("TTL: {}", ttl));
        }
        if let Some(window_size) = self.window_size {
            details.push(format!("Window Size: {}", window_size));
        }
        if let Some(mss) = self.mss {
            details.push(format!("MSS: {}", mss));
        }
        if self.timestamps {
            details.push("TCP Timestamps: Enabled".to_string());
        }
        if self.window_scaling {
            details.push("Window Scaling: Enabled".to_string());
        }
        if self.sack_permitted {
            details.push("SACK: Enabled".to_string());
        }
        if let Some(ref behavior) = self.closed_port_response {
            details.push(format!("Closed Port Response: {}", behavior));
        }

        details
    }
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

impl OSSignature {
    pub fn new(
        os_family: &str,
        os_name: &str,
        ttl: u8,
        closed_port_behavior: &str,
        confidence_weight: f64,
    ) -> Self {
        Self {
            os_family: os_family.to_string(),
            os_name: os_name.to_string(),
            ttl_range: (ttl, ttl),
            window_sizes: Vec::new(),
            mss_values: Vec::new(),
            tcp_options_patterns: Vec::new(),
            sequence_predictability_range: (0.0, f64::INFINITY),
            common_flags: vec![0x12],
            supports_timestamps: true,
            supports_window_scaling: true,
            supports_sack: true,
            closed_port_behavior: closed_port_behavior.to_string(),
            confidence_weight,
        }
    }

    pub fn with_window_sizes(mut self, window_sizes: Vec<u16>) -> Self {
        self.window_sizes = window_sizes;
        self
    }

    pub fn with_mss_values(mut self, mss_values: Vec<u16>) -> Self {
        self.mss_values = mss_values;
        self
    }

    pub fn with_tcp_features(mut self, timestamps: bool, window_scaling: bool, sack: bool) -> Self {
        self.supports_timestamps = timestamps;
        self.supports_window_scaling = window_scaling;
        self.supports_sack = sack;
        self
    }

    pub fn with_sequence_predictability(mut self, range: (f64, f64)) -> Self {
        self.sequence_predictability_range = range;
        self
    }
}
