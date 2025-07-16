use serde::{Deserialize, Serialize};

mod characteristics;
mod detector;
mod signatures;
mod testing;
mod utils;

#[cfg(test)]
mod tests;

pub use characteristics::{NetworkCharacteristics, OSSignature};
pub use detector::OSDetector;
pub use utils::{is_mobile_os, is_network_device, is_server_os, merge_os_fingerprints};

// Internal imports for use within this module
use utils::confidence_to_text;

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

impl OSFingerprint {
    pub fn new(os_family: String, os_name: String, confidence: u8) -> Self {
        Self {
            os_family,
            os_name,
            os_version: None,
            device_type: None,
            confidence,
            cpe: None,
            vendor: None,
            architecture: None,
            details: Vec::new(),
        }
    }

    pub fn with_version(mut self, version: String) -> Self {
        self.os_version = Some(version);
        self
    }

    pub fn with_device_type(mut self, device_type: String) -> Self {
        self.device_type = Some(device_type);
        self
    }

    pub fn with_cpe(mut self, cpe: String) -> Self {
        self.cpe = Some(cpe);
        self
    }

    pub fn with_vendor(mut self, vendor: String) -> Self {
        self.vendor = Some(vendor);
        self
    }

    pub fn with_architecture(mut self, architecture: String) -> Self {
        self.architecture = Some(architecture);
        self
    }

    pub fn with_details(mut self, details: Vec<String>) -> Self {
        self.details = details;
        self
    }

    pub fn add_detail(&mut self, detail: String) {
        self.details.push(detail);
    }

    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }

    pub fn is_mobile(&self) -> bool {
        is_mobile_os(&self.os_family)
    }

    pub fn is_server(&self) -> bool {
        is_server_os(&self.os_name)
    }

    pub fn is_network_device(&self) -> bool {
        is_network_device(&self.os_family)
    }

    pub fn confidence_text(&self) -> &'static str {
        confidence_to_text(self.confidence)
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
