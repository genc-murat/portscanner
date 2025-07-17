use crate::os_fingerprinting::OSFingerprint;
use crate::scanner::scan_results::ScanResult;
use crate::service_detection::ServiceInfo;
use crate::ssl::SslAnalysisResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub overall_risk_score: u8, // 0-100
    pub security_posture: SecurityPosture,
    pub risk_categories: Vec<RiskCategory>,
    pub critical_findings: Vec<CriticalFinding>,
    pub vulnerabilities: Vec<VulnerabilityFinding>,
    pub recommendations: Vec<SecurityRecommendation>,
    pub compliance_status: ComplianceStatus,
    pub attack_surface: AttackSurface,
    pub threat_model: ThreatModel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityPosture {
    Critical,  // 0-30
    Poor,      // 31-50
    Fair,      // 51-70
    Good,      // 71-85
    Excellent, // 86-100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskCategory {
    pub category: RiskCategoryType,
    pub score: u8,
    pub weight: f64,
    pub findings: Vec<String>,
    pub mitigation_priority: Priority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskCategoryType {
    ExposedServices,
    InsecureProtocols,
    WeakAuthentication,
    UnencryptedTraffic,
    OutdatedSoftware,
    MisconfiguredServices,
    DatabaseExposure,
    RemoteAccess,
    NetworkDevices,
    WebApplications,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalFinding {
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub affected_ports: Vec<u16>,
    pub cve_references: Vec<String>,
    pub exploit_likelihood: ExploitLikelihood,
    pub business_impact: BusinessImpact,
    pub remediation: String,
    pub cvss_score: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub port: u16,
    pub service: String,
    pub description: String,
    pub remediation: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRecommendation {
    pub priority: Priority,
    pub category: String,
    pub title: String,
    pub description: String,
    pub implementation_effort: ImplementationEffort,
    pub cost_impact: CostImpact,
    pub security_benefit: SecurityBenefit,
    pub timeline: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    pub frameworks: HashMap<String, ComplianceResult>,
    pub gaps: Vec<ComplianceGap>,
    pub overall_compliance_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub framework: String,
    pub compliance_percentage: u8,
    pub passing_controls: u32,
    pub failing_controls: u32,
    pub not_applicable: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceGap {
    pub control_id: String,
    pub framework: String,
    pub requirement: String,
    pub current_status: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurface {
    pub total_exposed_ports: u32,
    pub high_risk_services: Vec<String>,
    pub entry_points: Vec<EntryPoint>,
    pub lateral_movement_risks: Vec<String>,
    pub data_exfiltration_risks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPoint {
    pub port: u16,
    pub service: String,
    pub risk_level: Severity,
    pub attack_vectors: Vec<String>,
    pub mitigation_status: MitigationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModel {
    pub threat_actors: Vec<ThreatActor>,
    pub attack_scenarios: Vec<AttackScenario>,
    pub asset_criticality: AssetCriticality,
    pub data_sensitivity: DataSensitivity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub actor_type: String,
    pub capability_level: CapabilityLevel,
    pub motivation: String,
    pub likely_attack_methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackScenario {
    pub name: String,
    pub probability: f32,
    pub impact: BusinessImpact,
    pub attack_path: Vec<String>,
    pub detection_difficulty: DetectionDifficulty,
    pub prevention_measures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Priority {
    Immediate,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExploitLikelihood {
    VeryHigh,
    High,
    Medium,
    Low,
    VeryLow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BusinessImpact {
    Critical,
    High,
    Medium,
    Low,
    Negligible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImplementationEffort {
    Low,
    Medium,
    High,
    VeryHigh,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CostImpact {
    Free,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityBenefit {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MitigationStatus {
    Implemented,
    Partial,
    Missing,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CapabilityLevel {
    NationState,
    Advanced,
    Intermediate,
    Basic,
    Script,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssetCriticality {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataSensitivity {
    TopSecret,
    Secret,
    Confidential,
    Internal,
    Public,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionDifficulty {
    VeryHard,
    Hard,
    Medium,
    Easy,
    VeryEasy,
}

pub struct RiskAssessmentEngine {
    port_risk_database: HashMap<u16, PortRiskProfile>,
    vulnerability_database: HashMap<String, VulnerabilityProfile>,
    compliance_frameworks: HashMap<String, ComplianceFramework>,
}

#[derive(Debug, Clone)]
struct PortRiskProfile {
    base_risk_score: u8,
    common_vulnerabilities: Vec<String>,
    attack_vectors: Vec<String>,
    mitigation_difficulty: ImplementationEffort,
}

#[derive(Debug, Clone)]
struct VulnerabilityProfile {
    cvss_score: f32,
    exploit_complexity: String,
    common_exploits: Vec<String>,
    detection_signatures: Vec<String>,
}

#[derive(Debug, Clone)]
struct ComplianceFramework {
    name: String,
    controls: Vec<ComplianceControl>,
    criticality_weights: HashMap<String, f64>,
}

#[derive(Debug, Clone)]
struct ComplianceControl {
    control_id: String,
    requirement: String,
    validation_rules: Vec<String>,
    severity_if_failed: Severity,
}

impl RiskAssessmentEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            port_risk_database: HashMap::new(),
            vulnerability_database: HashMap::new(),
            compliance_frameworks: HashMap::new(),
        };

        engine.initialize_risk_database();
        engine.initialize_compliance_frameworks();
        engine
    }

    pub fn assess_risks(
        &self,
        scan_results: &[ScanResult],
        os_fingerprint: &Option<OSFingerprint>,
        ssl_analysis: &[SslAnalysisResult],
        target: &str,
    ) -> RiskAssessment {
        let critical_findings = self.identify_critical_findings(scan_results, ssl_analysis);
        let vulnerabilities = self.identify_vulnerabilities(scan_results, os_fingerprint);
        let risk_categories = self.calculate_risk_categories(scan_results, ssl_analysis);
        let overall_risk_score = self.calculate_overall_risk_score(&risk_categories);
        let security_posture = self.determine_security_posture(overall_risk_score);
        let recommendations = self.generate_recommendations(&risk_categories, &critical_findings);
        let compliance_status = self.assess_compliance(scan_results, ssl_analysis);
        let attack_surface = self.analyze_attack_surface(scan_results);
        let threat_model = self.build_threat_model(scan_results, os_fingerprint, target);

        RiskAssessment {
            overall_risk_score,
            security_posture,
            risk_categories,
            critical_findings,
            vulnerabilities,
            recommendations,
            compliance_status,
            attack_surface,
            threat_model,
        }
    }

    fn initialize_risk_database(&mut self) {
        // High-risk services
        self.port_risk_database.insert(
            23,
            PortRiskProfile {
                base_risk_score: 95,
                common_vulnerabilities: vec![
                    "CVE-2018-6789".to_string(),
                    "Plaintext authentication".to_string(),
                ],
                attack_vectors: vec![
                    "Credential interception".to_string(),
                    "Session hijacking".to_string(),
                ],
                mitigation_difficulty: ImplementationEffort::Low,
            },
        );

        self.port_risk_database.insert(
            21,
            PortRiskProfile {
                base_risk_score: 80,
                common_vulnerabilities: vec![
                    "Anonymous access".to_string(),
                    "Weak authentication".to_string(),
                ],
                attack_vectors: vec!["Brute force".to_string(), "Directory traversal".to_string()],
                mitigation_difficulty: ImplementationEffort::Low,
            },
        );

        self.port_risk_database.insert(
            445,
            PortRiskProfile {
                base_risk_score: 85,
                common_vulnerabilities: vec!["EternalBlue".to_string(), "SMB relay".to_string()],
                attack_vectors: vec![
                    "Lateral movement".to_string(),
                    "Remote code execution".to_string(),
                ],
                mitigation_difficulty: ImplementationEffort::Medium,
            },
        );

        self.port_risk_database.insert(
            3389,
            PortRiskProfile {
                base_risk_score: 75,
                common_vulnerabilities: vec!["BlueKeep".to_string(), "Weak passwords".to_string()],
                attack_vectors: vec!["Brute force".to_string(), "Credential stuffing".to_string()],
                mitigation_difficulty: ImplementationEffort::Medium,
            },
        );

        // Database services
        self.port_risk_database.insert(
            3306,
            PortRiskProfile {
                base_risk_score: 70,
                common_vulnerabilities: vec![
                    "Weak passwords".to_string(),
                    "Privilege escalation".to_string(),
                ],
                attack_vectors: vec!["SQL injection".to_string(), "Data exfiltration".to_string()],
                mitigation_difficulty: ImplementationEffort::Medium,
            },
        );

        self.port_risk_database.insert(
            5432,
            PortRiskProfile {
                base_risk_score: 70,
                common_vulnerabilities: vec![
                    "Default credentials".to_string(),
                    "Privilege escalation".to_string(),
                ],
                attack_vectors: vec![
                    "Data manipulation".to_string(),
                    "Information disclosure".to_string(),
                ],
                mitigation_difficulty: ImplementationEffort::Medium,
            },
        );

        self.port_risk_database.insert(
            1433,
            PortRiskProfile {
                base_risk_score: 75,
                common_vulnerabilities: vec![
                    "SQL injection".to_string(),
                    "Buffer overflow".to_string(),
                ],
                attack_vectors: vec![
                    "Database compromise".to_string(),
                    "Lateral movement".to_string(),
                ],
                mitigation_difficulty: ImplementationEffort::Medium,
            },
        );

        // Network services
        self.port_risk_database.insert(
            161,
            PortRiskProfile {
                base_risk_score: 60,
                common_vulnerabilities: vec![
                    "Default community strings".to_string(),
                    "Information disclosure".to_string(),
                ],
                attack_vectors: vec![
                    "Network reconnaissance".to_string(),
                    "Configuration extraction".to_string(),
                ],
                mitigation_difficulty: ImplementationEffort::Low,
            },
        );

        // Web services (medium risk by default, but can be high based on configuration)
        self.port_risk_database.insert(
            80,
            PortRiskProfile {
                base_risk_score: 40,
                common_vulnerabilities: vec!["Web application vulnerabilities".to_string()],
                attack_vectors: vec![
                    "XSS".to_string(),
                    "CSRF".to_string(),
                    "Injection attacks".to_string(),
                ],
                mitigation_difficulty: ImplementationEffort::High,
            },
        );

        self.port_risk_database.insert(
            443,
            PortRiskProfile {
                base_risk_score: 30,
                common_vulnerabilities: vec!["SSL/TLS misconfigurations".to_string()],
                attack_vectors: vec![
                    "Man-in-the-middle".to_string(),
                    "Certificate attacks".to_string(),
                ],
                mitigation_difficulty: ImplementationEffort::Medium,
            },
        );
    }

    fn initialize_compliance_frameworks(&mut self) {
        // PCI DSS Framework
        let pci_dss = ComplianceFramework {
            name: "PCI DSS".to_string(),
            controls: vec![
                ComplianceControl {
                    control_id: "2.2.1".to_string(),
                    requirement: "Remove unnecessary services and protocols".to_string(),
                    validation_rules: vec![
                        "No Telnet".to_string(),
                        "No unencrypted FTP".to_string(),
                    ],
                    severity_if_failed: Severity::High,
                },
                ComplianceControl {
                    control_id: "4.1".to_string(),
                    requirement: "Use strong cryptography for data transmission".to_string(),
                    validation_rules: vec![
                        "TLS 1.2+".to_string(),
                        "Strong cipher suites".to_string(),
                    ],
                    severity_if_failed: Severity::Critical,
                },
            ],
            criticality_weights: {
                let mut weights = HashMap::new();
                weights.insert("encryption".to_string(), 0.3);
                weights.insert("access_control".to_string(), 0.25);
                weights.insert("monitoring".to_string(), 0.2);
                weights
            },
        };

        // NIST Framework
        let nist = ComplianceFramework {
            name: "NIST Cybersecurity Framework".to_string(),
            controls: vec![
                ComplianceControl {
                    control_id: "PR.AC-1".to_string(),
                    requirement:
                        "Identities and credentials are managed for authorized devices and users"
                            .to_string(),
                    validation_rules: vec![
                        "No default credentials".to_string(),
                        "Strong authentication".to_string(),
                    ],
                    severity_if_failed: Severity::High,
                },
                ComplianceControl {
                    control_id: "PR.DS-2".to_string(),
                    requirement: "Data-in-transit is protected".to_string(),
                    validation_rules: vec![
                        "Encryption in transit".to_string(),
                        "Certificate validation".to_string(),
                    ],
                    severity_if_failed: Severity::High,
                },
            ],
            criticality_weights: {
                let mut weights = HashMap::new();
                weights.insert("identify".to_string(), 0.2);
                weights.insert("protect".to_string(), 0.3);
                weights.insert("detect".to_string(), 0.2);
                weights.insert("respond".to_string(), 0.15);
                weights.insert("recover".to_string(), 0.15);
                weights
            },
        };

        self.compliance_frameworks
            .insert("PCI_DSS".to_string(), pci_dss);
        self.compliance_frameworks.insert("NIST".to_string(), nist);
    }

    fn identify_critical_findings(
        &self,
        scan_results: &[ScanResult],
        ssl_analysis: &[SslAnalysisResult],
    ) -> Vec<CriticalFinding> {
        let mut findings = Vec::new();

        // Check for critical service exposures
        for result in scan_results.iter().filter(|r| r.is_open) {
            if let Some(profile) = self.port_risk_database.get(&result.port) {
                if profile.base_risk_score >= 80 {
                    findings.push(CriticalFinding {
                        severity: Severity::Critical,
                        title: format!("High-Risk Service Exposed: Port {}", result.port),
                        description: format!(
                            "Critical service '{}' is exposed on port {}. This service has known security risks and should be secured or removed.",
                            result.service.as_deref().unwrap_or("Unknown"),
                            result.port
                        ),
                        affected_ports: vec![result.port],
                        cve_references: profile.common_vulnerabilities.clone(),
                        exploit_likelihood: ExploitLikelihood::High,
                        business_impact: BusinessImpact::Critical,
                        remediation: self.get_port_remediation(result.port),
                        cvss_score: Some(8.5),
                    });
                }
            }
        }

        // Check SSL/TLS vulnerabilities
        for ssl_result in ssl_analysis {
            if ssl_result.security_score < 50 {
                findings.push(CriticalFinding {
                    severity: Severity::High,
                    title: format!("Critical SSL/TLS Vulnerabilities: Port {}", ssl_result.port),
                    description: "SSL/TLS service has critical security vulnerabilities that could lead to data interception.".to_string(),
                    affected_ports: vec![ssl_result.port],
                    cve_references: ssl_result.vulnerabilities.iter()
                        .filter_map(|v| v.cve_id.clone())
                        .collect(),
                    exploit_likelihood: ExploitLikelihood::High,
                    business_impact: BusinessImpact::High,
                    remediation: "Update SSL/TLS configuration, disable weak protocols and ciphers, update certificates.".to_string(),
                    cvss_score: Some(7.5),
                });
            }
        }

        findings
    }

    fn identify_vulnerabilities(
        &self,
        scan_results: &[ScanResult],
        os_fingerprint: &Option<OSFingerprint>,
    ) -> Vec<VulnerabilityFinding> {
        let mut vulnerabilities = Vec::new();

        // Port-specific vulnerabilities
        for result in scan_results.iter().filter(|r| r.is_open) {
            vulnerabilities.extend(self.get_port_vulnerabilities(result));
        }

        // OS-specific vulnerabilities
        if let Some(os) = os_fingerprint {
            vulnerabilities.extend(self.get_os_vulnerabilities(os));
        }

        vulnerabilities
    }

    fn get_port_vulnerabilities(&self, result: &ScanResult) -> Vec<VulnerabilityFinding> {
        let mut vulnerabilities = Vec::new();

        match result.port {
            23 => {
                vulnerabilities.push(VulnerabilityFinding {
                    id: "TELNET-001".to_string(),
                    title: "Unencrypted Telnet Service".to_string(),
                    severity: Severity::Critical,
                    port: result.port,
                    service: "Telnet".to_string(),
                    description: "Telnet transmits all data including passwords in plaintext."
                        .to_string(),
                    remediation: "Disable Telnet and use SSH instead.".to_string(),
                    references: vec!["CWE-319".to_string()],
                });
            }
            21 => {
                vulnerabilities.push(VulnerabilityFinding {
                    id: "FTP-001".to_string(),
                    title: "Unencrypted FTP Service".to_string(),
                    severity: Severity::High,
                    port: result.port,
                    service: "FTP".to_string(),
                    description: "FTP transmits credentials and data in plaintext.".to_string(),
                    remediation: "Use SFTP or FTPS instead of plain FTP.".to_string(),
                    references: vec!["CWE-319".to_string()],
                });
            }
            445 => {
                vulnerabilities.push(VulnerabilityFinding {
                    id: "SMB-001".to_string(),
                    title: "SMB Service Exposure".to_string(),
                    severity: Severity::High,
                    port: result.port,
                    service: "SMB".to_string(),
                    description: "SMB service exposed to network, potential for lateral movement."
                        .to_string(),
                    remediation: "Restrict SMB access, enable SMB signing, apply latest patches."
                        .to_string(),
                    references: vec!["CVE-2017-0144".to_string()],
                });
            }
            161 => {
                vulnerabilities.push(VulnerabilityFinding {
                    id: "SNMP-001".to_string(),
                    title: "SNMP Information Disclosure".to_string(),
                    severity: Severity::Medium,
                    port: result.port,
                    service: "SNMP".to_string(),
                    description:
                        "SNMP service may expose system information with default community strings."
                            .to_string(),
                    remediation: "Change default community strings, use SNMPv3, restrict access."
                        .to_string(),
                    references: vec!["CWE-200".to_string()],
                });
            }
            _ => {}
        }

        vulnerabilities
    }

    fn get_os_vulnerabilities(&self, os: &OSFingerprint) -> Vec<VulnerabilityFinding> {
        let mut vulnerabilities = Vec::new();

        if os.os_family.contains("Windows") && os.confidence > 70 {
            vulnerabilities.push(VulnerabilityFinding {
                id: "OS-WIN-001".to_string(),
                title: "Windows OS Detected".to_string(),
                severity: Severity::Info,
                port: 0,
                service: "Operating System".to_string(),
                description:
                    "Windows operating system detected. Ensure latest security updates are applied."
                        .to_string(),
                remediation: "Enable automatic updates, apply security patches regularly."
                    .to_string(),
                references: vec!["https://support.microsoft.com/".to_string()],
            });
        }

        vulnerabilities
    }

    fn calculate_risk_categories(
        &self,
        scan_results: &[ScanResult],
        ssl_analysis: &[SslAnalysisResult],
    ) -> Vec<RiskCategory> {
        let mut categories = Vec::new();

        // Exposed Services Risk
        categories.push(self.assess_exposed_services_risk(scan_results));

        // Insecure Protocols Risk
        categories.push(self.assess_insecure_protocols_risk(scan_results));

        // Unencrypted Traffic Risk
        categories.push(self.assess_unencrypted_traffic_risk(scan_results, ssl_analysis));

        // Database Exposure Risk
        categories.push(self.assess_database_exposure_risk(scan_results));

        // Remote Access Risk
        categories.push(self.assess_remote_access_risk(scan_results));

        categories
    }

    fn assess_exposed_services_risk(&self, scan_results: &[ScanResult]) -> RiskCategory {
        let open_ports = scan_results.iter().filter(|r| r.is_open).count();
        let high_risk_ports = scan_results
            .iter()
            .filter(|r| {
                r.is_open
                    && self
                        .port_risk_database
                        .get(&r.port)
                        .map_or(false, |p| p.base_risk_score > 70)
            })
            .count();

        let score = if high_risk_ports > 0 {
            100 - (high_risk_ports * 20).min(80) as u8
        } else {
            90 - (open_ports * 5).min(40) as u8
        };

        let findings = scan_results
            .iter()
            .filter(|r| r.is_open)
            .map(|r| {
                format!(
                    "Port {} ({}) is exposed",
                    r.port,
                    r.service.as_deref().unwrap_or("unknown")
                )
            })
            .collect();

        RiskCategory {
            category: RiskCategoryType::ExposedServices,
            score,
            weight: 0.25,
            findings,
            mitigation_priority: if high_risk_ports > 0 {
                Priority::Immediate
            } else {
                Priority::Medium
            },
        }
    }

    fn assess_insecure_protocols_risk(&self, scan_results: &[ScanResult]) -> RiskCategory {
        let insecure_services = scan_results
            .iter()
            .filter(|r| r.is_open && matches!(r.port, 21 | 23 | 80 | 110 | 143))
            .count();

        let score = if insecure_services > 0 {
            50 - (insecure_services * 15).min(40) as u8
        } else {
            100
        };

        let findings = scan_results
            .iter()
            .filter(|r| r.is_open && matches!(r.port, 21 | 23 | 80 | 110 | 143))
            .map(|r| format!("Insecure service on port {}", r.port))
            .collect();

        RiskCategory {
            category: RiskCategoryType::InsecureProtocols,
            score,
            weight: 0.2,
            findings,
            mitigation_priority: if insecure_services > 0 {
                Priority::High
            } else {
                Priority::Low
            },
        }
    }

    fn assess_unencrypted_traffic_risk(
        &self,
        scan_results: &[ScanResult],
        ssl_analysis: &[SslAnalysisResult],
    ) -> RiskCategory {
        let unencrypted_services = scan_results
            .iter()
            .filter(|r| r.is_open && matches!(r.port, 21 | 23 | 80 | 110 | 143))
            .count();

        let weak_ssl_services = ssl_analysis
            .iter()
            .filter(|s| s.is_ssl_enabled && s.security_score < 70)
            .count();

        let total_risk_services = unencrypted_services + weak_ssl_services;
        let score = if total_risk_services > 0 {
            70 - (total_risk_services * 20).min(60) as u8
        } else {
            100
        };

        let mut findings = Vec::new();
        findings.extend(
            scan_results
                .iter()
                .filter(|r| r.is_open && matches!(r.port, 21 | 23 | 80 | 110 | 143))
                .map(|r| format!("Unencrypted service on port {}", r.port)),
        );
        findings.extend(
            ssl_analysis
                .iter()
                .filter(|s| s.is_ssl_enabled && s.security_score < 70)
                .map(|s| format!("Weak SSL/TLS on port {}", s.port)),
        );

        RiskCategory {
            category: RiskCategoryType::UnencryptedTraffic,
            score,
            weight: 0.15,
            findings,
            mitigation_priority: if total_risk_services > 0 {
                Priority::High
            } else {
                Priority::Low
            },
        }
    }

    fn assess_database_exposure_risk(&self, scan_results: &[ScanResult]) -> RiskCategory {
        let database_ports = scan_results
            .iter()
            .filter(|r| r.is_open && matches!(r.port, 3306 | 5432 | 1433 | 1521 | 27017 | 6379))
            .count();

        let score = if database_ports > 0 {
            40 - (database_ports * 15).min(30) as u8
        } else {
            100
        };

        let findings = scan_results
            .iter()
            .filter(|r| r.is_open && matches!(r.port, 3306 | 5432 | 1433 | 1521 | 27017 | 6379))
            .map(|r| format!("Database service exposed on port {}", r.port))
            .collect();

        RiskCategory {
            category: RiskCategoryType::DatabaseExposure,
            score,
            weight: 0.2,
            findings,
            mitigation_priority: if database_ports > 0 {
                Priority::High
            } else {
                Priority::Low
            },
        }
    }

    fn assess_remote_access_risk(&self, scan_results: &[ScanResult]) -> RiskCategory {
        let remote_access_ports = scan_results
            .iter()
            .filter(|r| r.is_open && matches!(r.port, 22 | 23 | 3389 | 5900))
            .count();

        let score = if remote_access_ports > 2 {
            60
        } else if remote_access_ports > 0 {
            80
        } else {
            100
        };

        let findings = scan_results
            .iter()
            .filter(|r| r.is_open && matches!(r.port, 22 | 23 | 3389 | 5900))
            .map(|r| format!("Remote access service on port {}", r.port))
            .collect();

        RiskCategory {
            category: RiskCategoryType::RemoteAccess,
            score,
            weight: 0.2,
            findings,
            mitigation_priority: if remote_access_ports > 1 {
                Priority::High
            } else {
                Priority::Medium
            },
        }
    }

    fn calculate_overall_risk_score(&self, categories: &[RiskCategory]) -> u8 {
        let weighted_sum: f64 = categories
            .iter()
            .map(|cat| cat.score as f64 * cat.weight)
            .sum();

        let total_weight: f64 = categories.iter().map(|cat| cat.weight).sum();

        if total_weight > 0.0 {
            (weighted_sum / total_weight) as u8
        } else {
            100
        }
    }

    fn determine_security_posture(&self, score: u8) -> SecurityPosture {
        match score {
            0..=30 => SecurityPosture::Critical,
            31..=50 => SecurityPosture::Poor,
            51..=70 => SecurityPosture::Fair,
            71..=85 => SecurityPosture::Good,
            86..=100 => SecurityPosture::Excellent,
            _ => SecurityPosture::Excellent, // Fallback for values > 100 (should not occur)
        }
    }

    fn generate_recommendations(
        &self,
        categories: &[RiskCategory],
        critical_findings: &[CriticalFinding],
    ) -> Vec<SecurityRecommendation> {
        let mut recommendations = Vec::new();

        // Critical findings recommendations
        for finding in critical_findings {
            recommendations.push(SecurityRecommendation {
                priority: Priority::Immediate,
                category: "Critical Security".to_string(),
                title: format!("Address: {}", finding.title),
                description: finding.remediation.clone(),
                implementation_effort: ImplementationEffort::Medium,
                cost_impact: CostImpact::Low,
                security_benefit: SecurityBenefit::Critical,
                timeline: "Immediate".to_string(),
            });
        }

        // Category-based recommendations
        for category in categories {
            if category.score < 70 {
                let recommendation = match category.category {
                    RiskCategoryType::ExposedServices => SecurityRecommendation {
                        priority: Priority::High,
                        category: "Network Security".to_string(),
                        title: "Reduce Attack Surface".to_string(),
                        description: "Close unnecessary ports and services. Implement network segmentation and firewall rules.".to_string(),
                        implementation_effort: ImplementationEffort::Medium,
                        cost_impact: CostImpact::Low,
                        security_benefit: SecurityBenefit::High,
                        timeline: "1-2 weeks".to_string(),
                    },
                    RiskCategoryType::InsecureProtocols => SecurityRecommendation {
                        priority: Priority::High,
                        category: "Protocol Security".to_string(),
                        title: "Migrate to Secure Protocols".to_string(),
                        description: "Replace insecure protocols (Telnet, FTP, HTTP) with secure alternatives (SSH, SFTP, HTTPS).".to_string(),
                        implementation_effort: ImplementationEffort::High,
                        cost_impact: CostImpact::Medium,
                        security_benefit: SecurityBenefit::High,
                        timeline: "2-4 weeks".to_string(),
                    },
                    RiskCategoryType::UnencryptedTraffic => SecurityRecommendation {
                        priority: Priority::High,
                        category: "Encryption".to_string(),
                        title: "Implement Encryption".to_string(),
                        description: "Enable encryption for all data in transit. Update SSL/TLS configurations.".to_string(),
                        implementation_effort: ImplementationEffort::Medium,
                        cost_impact: CostImpact::Low,
                        security_benefit: SecurityBenefit::High,
                        timeline: "1-3 weeks".to_string(),
                    },
                    RiskCategoryType::DatabaseExposure => SecurityRecommendation {
                        priority: Priority::Immediate,
                        category: "Data Protection".to_string(),
                        title: "Secure Database Access".to_string(),
                        description: "Restrict database access to authorized networks only. Implement database firewalls and monitoring.".to_string(),
                        implementation_effort: ImplementationEffort::Medium,
                        cost_impact: CostImpact::Medium,
                        security_benefit: SecurityBenefit::Critical,
                        timeline: "Immediate".to_string(),
                    },
                    RiskCategoryType::RemoteAccess => SecurityRecommendation {
                        priority: Priority::High,
                        category: "Access Control".to_string(),
                        title: "Secure Remote Access".to_string(),
                        description: "Implement VPN, multi-factor authentication, and restrict remote access to necessary users only.".to_string(),
                        implementation_effort: ImplementationEffort::High,
                        cost_impact: CostImpact::Medium,
                        security_benefit: SecurityBenefit::High,
                        timeline: "2-3 weeks".to_string(),
                    },
                    _ => continue,
                };
                recommendations.push(recommendation);
            }
        }

        // General security recommendations
        recommendations.push(SecurityRecommendation {
            priority: Priority::Medium,
            category: "Monitoring".to_string(),
            title: "Implement Security Monitoring".to_string(),
            description: "Deploy SIEM, intrusion detection systems, and log monitoring for early threat detection.".to_string(),
            implementation_effort: ImplementationEffort::High,
            cost_impact: CostImpact::High,
            security_benefit: SecurityBenefit::High,
            timeline: "4-8 weeks".to_string(),
        });

        recommendations.push(SecurityRecommendation {
            priority: Priority::Low,
            category: "Compliance".to_string(),
            title: "Regular Security Assessments".to_string(),
            description: "Conduct regular penetration testing and vulnerability assessments."
                .to_string(),
            implementation_effort: ImplementationEffort::Low,
            cost_impact: CostImpact::Medium,
            security_benefit: SecurityBenefit::Medium,
            timeline: "Ongoing".to_string(),
        });

        recommendations
    }

    fn assess_compliance(
        &self,
        scan_results: &[ScanResult],
        ssl_analysis: &[SslAnalysisResult],
    ) -> ComplianceStatus {
        let mut frameworks = HashMap::new();
        let mut gaps = Vec::new();

        // PCI DSS Assessment
        let pci_result = self.assess_pci_compliance(scan_results, ssl_analysis);
        if let Some(framework) = self.compliance_frameworks.get("PCI_DSS") {
            if pci_result.compliance_percentage < 100 {
                gaps.push(ComplianceGap {
                    control_id: "PCI-2.2.1".to_string(),
                    framework: "PCI DSS".to_string(),
                    requirement: "Remove unnecessary services".to_string(),
                    current_status: "Non-compliant".to_string(),
                    remediation: "Close unnecessary ports and services".to_string(),
                });
            }
        }
        frameworks.insert("PCI_DSS".to_string(), pci_result);

        // NIST Assessment
        let nist_result = self.assess_nist_compliance(scan_results, ssl_analysis);
        frameworks.insert("NIST".to_string(), nist_result);

        let overall_compliance_score = frameworks
            .values()
            .map(|f| f.compliance_percentage as u32)
            .sum::<u32>()
            / frameworks.len() as u32;

        ComplianceStatus {
            frameworks,
            gaps,
            overall_compliance_score: overall_compliance_score as u8,
        }
    }

    fn assess_pci_compliance(
        &self,
        scan_results: &[ScanResult],
        ssl_analysis: &[SslAnalysisResult],
    ) -> ComplianceResult {
        let mut passing = 0;
        let mut failing = 0;

        // Check for unnecessary services (PCI Requirement 2.2.1)
        let has_insecure_services = scan_results
            .iter()
            .any(|r| r.is_open && matches!(r.port, 21 | 23));

        if has_insecure_services {
            failing += 1;
        } else {
            passing += 1;
        }

        // Check encryption requirements (PCI Requirement 4.1)
        let has_weak_encryption = ssl_analysis
            .iter()
            .any(|s| s.is_ssl_enabled && s.security_score < 80);

        if has_weak_encryption {
            failing += 1;
        } else {
            passing += 1;
        }

        let total = passing + failing;
        let compliance_percentage = if total > 0 {
            (passing * 100) / total
        } else {
            100
        };

        ComplianceResult {
            framework: "PCI DSS".to_string(),
            compliance_percentage: compliance_percentage as u8,
            passing_controls: passing,
            failing_controls: failing,
            not_applicable: 0,
        }
    }

    fn assess_nist_compliance(
        &self,
        scan_results: &[ScanResult],
        ssl_analysis: &[SslAnalysisResult],
    ) -> ComplianceResult {
        let mut passing = 0;
        let mut failing = 0;

        // Access Control (PR.AC-1)
        let has_default_services = scan_results.iter().any(|r| {
            r.is_open
                && matches!(r.port, 161 | 1433)
                && r.service.as_ref().map_or(false, |s| s.contains("default"))
        });

        if has_default_services {
            failing += 1;
        } else {
            passing += 1;
        }

        // Data Protection (PR.DS-2)
        let has_unencrypted_data = scan_results
            .iter()
            .any(|r| r.is_open && matches!(r.port, 21 | 23 | 80));

        if has_unencrypted_data {
            failing += 1;
        } else {
            passing += 1;
        }

        let total = passing + failing;
        let compliance_percentage = if total > 0 {
            (passing * 100) / total
        } else {
            100
        };

        ComplianceResult {
            framework: "NIST Cybersecurity Framework".to_string(),
            compliance_percentage: compliance_percentage as u8,
            passing_controls: passing,
            failing_controls: failing,
            not_applicable: 0,
        }
    }

    fn analyze_attack_surface(&self, scan_results: &[ScanResult]) -> AttackSurface {
        let open_ports = scan_results
            .iter()
            .filter(|r| r.is_open)
            .collect::<Vec<_>>();
        let total_exposed_ports = open_ports.len() as u32;

        let high_risk_services = open_ports
            .iter()
            .filter(|r| {
                self.port_risk_database
                    .get(&r.port)
                    .map_or(false, |p| p.base_risk_score > 70)
            })
            .map(|r| r.service.as_deref().unwrap_or("Unknown").to_string())
            .collect();

        let entry_points = open_ports
            .iter()
            .map(|r| {
                let risk_level = self
                    .port_risk_database
                    .get(&r.port)
                    .map(|p| match p.base_risk_score {
                        80.. => Severity::Critical,
                        60..79 => Severity::High,
                        40..59 => Severity::Medium,
                        _ => Severity::Low,
                    })
                    .unwrap_or(Severity::Low);

                let attack_vectors = self
                    .port_risk_database
                    .get(&r.port)
                    .map(|p| p.attack_vectors.clone())
                    .unwrap_or_else(|| vec!["Generic network attack".to_string()]);

                EntryPoint {
                    port: r.port,
                    service: r.service.as_deref().unwrap_or("Unknown").to_string(),
                    risk_level,
                    attack_vectors,
                    mitigation_status: MitigationStatus::Missing,
                }
            })
            .collect();

        let lateral_movement_risks = vec![
            "SMB shares accessible".to_string(),
            "Database connections available".to_string(),
            "Remote desktop exposed".to_string(),
        ]
        .into_iter()
        .filter(|risk| match risk.as_str() {
            "SMB shares accessible" => open_ports.iter().any(|r| r.port == 445),
            "Database connections available" => open_ports
                .iter()
                .any(|r| matches!(r.port, 3306 | 5432 | 1433)),
            "Remote desktop exposed" => open_ports.iter().any(|r| r.port == 3389),
            _ => false,
        })
        .collect();

        let data_exfiltration_risks = vec![
            "Database exposure".to_string(),
            "File sharing services".to_string(),
            "Web applications".to_string(),
        ]
        .into_iter()
        .filter(|risk| match risk.as_str() {
            "Database exposure" => open_ports
                .iter()
                .any(|r| matches!(r.port, 3306 | 5432 | 1433 | 27017)),
            "File sharing services" => open_ports.iter().any(|r| matches!(r.port, 21 | 445 | 2049)),
            "Web applications" => open_ports.iter().any(|r| matches!(r.port, 80 | 443 | 8080)),
            _ => false,
        })
        .collect();

        AttackSurface {
            total_exposed_ports,
            high_risk_services,
            entry_points,
            lateral_movement_risks,
            data_exfiltration_risks,
        }
    }

    fn build_threat_model(
        &self,
        scan_results: &[ScanResult],
        os_fingerprint: &Option<OSFingerprint>,
        target: &str,
    ) -> ThreatModel {
        let threat_actors = vec![
            ThreatActor {
                actor_type: "Opportunistic Attacker".to_string(),
                capability_level: CapabilityLevel::Basic,
                motivation: "Financial gain through automated attacks".to_string(),
                likely_attack_methods: vec![
                    "Automated vulnerability scanning".to_string(),
                    "Brute force attacks".to_string(),
                    "Exploitation of known vulnerabilities".to_string(),
                ],
            },
            ThreatActor {
                actor_type: "Targeted Attacker".to_string(),
                capability_level: CapabilityLevel::Intermediate,
                motivation: "Specific data theft or system compromise".to_string(),
                likely_attack_methods: vec![
                    "Reconnaissance".to_string(),
                    "Social engineering".to_string(),
                    "Custom exploit development".to_string(),
                ],
            },
            ThreatActor {
                actor_type: "Insider Threat".to_string(),
                capability_level: CapabilityLevel::Advanced,
                motivation: "Data theft, sabotage, or financial gain".to_string(),
                likely_attack_methods: vec![
                    "Privilege abuse".to_string(),
                    "Data exfiltration".to_string(),
                    "System manipulation".to_string(),
                ],
            },
        ];

        let attack_scenarios = self.generate_attack_scenarios(scan_results);

        let asset_criticality = self.determine_asset_criticality(scan_results, target);
        let data_sensitivity = self.determine_data_sensitivity(scan_results);

        ThreatModel {
            threat_actors,
            attack_scenarios,
            asset_criticality,
            data_sensitivity,
        }
    }

    fn generate_attack_scenarios(&self, scan_results: &[ScanResult]) -> Vec<AttackScenario> {
        let mut scenarios = Vec::new();

        // Database compromise scenario
        if scan_results
            .iter()
            .any(|r| r.is_open && matches!(r.port, 3306 | 5432 | 1433))
        {
            scenarios.push(AttackScenario {
                name: "Database Compromise".to_string(),
                probability: 0.7,
                impact: BusinessImpact::Critical,
                attack_path: vec![
                    "Network reconnaissance".to_string(),
                    "Database service discovery".to_string(),
                    "Credential brute force".to_string(),
                    "Data extraction".to_string(),
                ],
                detection_difficulty: DetectionDifficulty::Medium,
                prevention_measures: vec![
                    "Network segmentation".to_string(),
                    "Strong authentication".to_string(),
                    "Database activity monitoring".to_string(),
                ],
            });
        }

        // Remote access compromise
        if scan_results
            .iter()
            .any(|r| r.is_open && matches!(r.port, 22 | 3389 | 5900))
        {
            scenarios.push(AttackScenario {
                name: "Remote Access Compromise".to_string(),
                probability: 0.6,
                impact: BusinessImpact::High,
                attack_path: vec![
                    "Service enumeration".to_string(),
                    "Credential attacks".to_string(),
                    "System access".to_string(),
                    "Lateral movement".to_string(),
                ],
                detection_difficulty: DetectionDifficulty::Easy,
                prevention_measures: vec![
                    "Multi-factor authentication".to_string(),
                    "VPN requirement".to_string(),
                    "Access logging".to_string(),
                ],
            });
        }

        // Web application attack
        if scan_results
            .iter()
            .any(|r| r.is_open && matches!(r.port, 80 | 443 | 8080))
        {
            scenarios.push(AttackScenario {
                name: "Web Application Attack".to_string(),
                probability: 0.8,
                impact: BusinessImpact::Medium,
                attack_path: vec![
                    "Web application discovery".to_string(),
                    "Vulnerability scanning".to_string(),
                    "Exploit execution".to_string(),
                    "Data extraction or system compromise".to_string(),
                ],
                detection_difficulty: DetectionDifficulty::Hard,
                prevention_measures: vec![
                    "Web application firewall".to_string(),
                    "Input validation".to_string(),
                    "Security testing".to_string(),
                ],
            });
        }

        scenarios
    }

    fn determine_asset_criticality(
        &self,
        scan_results: &[ScanResult],
        target: &str,
    ) -> AssetCriticality {
        let has_databases = scan_results
            .iter()
            .any(|r| r.is_open && matches!(r.port, 3306 | 5432 | 1433));
        let has_web_services = scan_results
            .iter()
            .any(|r| r.is_open && matches!(r.port, 80 | 443));
        let open_port_count = scan_results.iter().filter(|r| r.is_open).count();

        if has_databases || target.contains("prod") || target.contains("db") {
            AssetCriticality::Critical
        } else if has_web_services || open_port_count > 10 {
            AssetCriticality::High
        } else if open_port_count > 5 {
            AssetCriticality::Medium
        } else {
            AssetCriticality::Low
        }
    }

    fn determine_data_sensitivity(&self, scan_results: &[ScanResult]) -> DataSensitivity {
        let has_databases = scan_results
            .iter()
            .any(|r| r.is_open && matches!(r.port, 3306 | 5432 | 1433));
        let has_file_services = scan_results
            .iter()
            .any(|r| r.is_open && matches!(r.port, 21 | 445 | 2049));

        if has_databases {
            DataSensitivity::Confidential
        } else if has_file_services {
            DataSensitivity::Internal
        } else {
            DataSensitivity::Public
        }
    }

    fn get_port_remediation(&self, port: u16) -> String {
        match port {
            23 => "Disable Telnet service. Use SSH for secure remote access.".to_string(),
            21 => "Replace FTP with SFTP or FTPS. Disable anonymous access.".to_string(),
            445 => {
                "Restrict SMB access to internal networks. Enable SMB signing and apply patches."
                    .to_string()
            }
            3389 => {
                "Use VPN for RDP access. Enable Network Level Authentication and strong passwords."
                    .to_string()
            }
            3306 => {
                "Restrict MySQL access to application servers only. Use strong passwords and SSL."
                    .to_string()
            }
            5432 => "Limit PostgreSQL network access. Enable SSL and use strong authentication."
                .to_string(),
            1433 => "Secure SQL Server with Windows Authentication. Restrict network access."
                .to_string(),
            161 => "Change default SNMP community strings. Use SNMPv3 with encryption.".to_string(),
            _ => {
                "Review service necessity and implement appropriate security controls.".to_string()
            }
        }
    }
}

// Utility function for formatting risk assessment results
pub fn format_risk_assessment(assessment: &RiskAssessment) -> String {
    let mut output = String::new();

    output.push_str(&format!("\n🛡️  SECURITY RISK ASSESSMENT\n"));
    output.push_str(&"═".repeat(60));
    output.push('\n');

    // Overall Risk Score
    let score_emoji = match assessment.security_posture {
        SecurityPosture::Excellent => "🟢",
        SecurityPosture::Good => "🟡",
        SecurityPosture::Fair => "🟠",
        SecurityPosture::Poor => "🔴",
        SecurityPosture::Critical => "💀",
    };

    output.push_str(&format!(
        "{} Overall Risk Score: {}/100 ({:?})\n\n",
        score_emoji, assessment.overall_risk_score, assessment.security_posture
    ));

    // Critical Findings
    if !assessment.critical_findings.is_empty() {
        output.push_str("🚨 CRITICAL FINDINGS:\n");
        for finding in &assessment.critical_findings {
            output.push_str(&format!(
                "   • {} (Ports: {:?})\n",
                finding.title, finding.affected_ports
            ));
            output.push_str(&format!("     Remediation: {}\n", finding.remediation));
        }
        output.push('\n');
    }

    // Risk Categories
    output.push_str("📊 RISK CATEGORIES:\n");
    for category in &assessment.risk_categories {
        let category_emoji = if category.score < 50 {
            "🔴"
        } else if category.score < 70 {
            "🟠"
        } else {
            "🟢"
        };
        output.push_str(&format!(
            "   {} {:?}: {}/100 ({:?} priority)\n",
            category_emoji, category.category, category.score, category.mitigation_priority
        ));
    }

    // Top Recommendations
    output.push_str("\n💡 TOP RECOMMENDATIONS:\n");
    for (i, rec) in assessment.recommendations.iter().take(5).enumerate() {
        let priority_emoji = match rec.priority {
            Priority::Immediate => "🚨",
            Priority::High => "🔴",
            Priority::Medium => "🟡",
            Priority::Low => "🟢",
        };
        output.push_str(&format!("   {}. {} {}\n", i + 1, priority_emoji, rec.title));
        output.push_str(&format!("      {}\n", rec.description));
    }

    // Attack Surface Summary
    output.push_str(&format!("\n🎯 ATTACK SURFACE:\n"));
    output.push_str(&format!(
        "   • {} total exposed ports\n",
        assessment.attack_surface.total_exposed_ports
    ));
    output.push_str(&format!(
        "   • {} high-risk services\n",
        assessment.attack_surface.high_risk_services.len()
    ));
    output.push_str(&format!(
        "   • {} potential entry points\n",
        assessment.attack_surface.entry_points.len()
    ));

    // Compliance Status
    output.push_str(&format!("\n📋 COMPLIANCE STATUS:\n"));
    output.push_str(&format!(
        "   • Overall Compliance: {}%\n",
        assessment.compliance_status.overall_compliance_score
    ));
    for (framework, result) in &assessment.compliance_status.frameworks {
        output.push_str(&format!(
            "   • {}: {}%\n",
            framework, result.compliance_percentage
        ));
    }

    output.push_str(&"\n═".repeat(60));
    output.push('\n');

    output
}
