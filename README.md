# Port Scanner

A fast, modern port scanner written in Rust with async networking, IPv4/IPv6 dual-stack support, TCP/UDP scanning, stealth SYN scan, SSL/TLS analysis, advanced service detection, OS fingerprinting, **comprehensive security risk assessment**, interactive mode, and beautiful HTML reporting capabilities. Inspired by Nmap but built for speed, simplicity, and enterprise-grade security analysis.

## 🚀 Features

### Core Scanning Features
- **IPv4/IPv6 Dual Stack**: Complete support for both IPv4 and IPv6 protocols
- **Fast Async Scanning**: Built with Tokio for high-performance concurrent scanning
- **TCP & UDP Support**: Comprehensive scanning for both TCP and UDP protocols
- **Stealth SYN Scan**: Raw socket SYN scanning for speed and stealth (Linux/Unix)
- **SSL/TLS Analysis**: Complete SSL/TLS security assessment with vulnerability detection
- **UDP Service Detection**: Protocol-specific probes for common UDP services
- **Banner Grabbing**: Extract service banners and version information (TCP)

### Advanced Detection
- **Advanced Service Detection**: Nmap-style service identification with 150+ signatures
- **OS Fingerprinting**: Operating system detection via TCP/IP stack analysis
- **Certificate Analysis**: SSL certificate validation and security assessment
- **Vulnerability Detection**: SSL/TLS vulnerability scanning (e.g., POODLE, BEAST)
- **Security Scoring**: Automated security assessment with recommendations

### Security Risk Assessment
- **Comprehensive Risk Analysis**: Multi-dimensional security risk scoring (0-100)
- **Critical Findings Detection**: Automated identification of high-risk exposures
- **Vulnerability Assessment**: Port and service-specific vulnerability identification
- **Compliance Framework Support**: PCI DSS and NIST Cybersecurity Framework checking
- **Attack Surface Analysis**: Entry point identification and lateral movement risk assessment
- **Threat Modeling**: Advanced threat actor profiling and attack scenario generation
- **Security Recommendations**: Prioritized, actionable remediation guidance

### User Experience
- **🎮 Interactive Mode**: Guided setup with menu-driven configuration
- **🌈 Beautiful UI**: Colored terminal output with progress bars and animations
- **📊 Real-time Progress**: Live progress tracking with ETA and speed metrics
- **🎯 Smart Recommendations**: Context-aware security suggestions
- **🔍 Quick Scan Mode**: Instant scanning with optimized settings

### Output & Reporting
- **📄 HTML Reports**: Professional, responsive HTML reports with security dashboards
- **📋 JSON Export**: Structured data export for automation and SIEM integration
- **🎨 Rich Terminal Output**: Syntax highlighting and visual indicators
- **📈 Performance Metrics**: Detailed scan statistics and timing information
- **🔒 Security Assessment**: Automated risk analysis and recommendations
- **📊 Executive Dashboards**: High-level security posture visualization

### Configuration & Flexibility
- **Multiple Target Support**: Scan IPv4/IPv6 addresses or hostnames
- **Configurable**: Customize concurrency, timeouts, and port ranges
- **Safe**: Built-in rate limiting and timeout controls
- **Auto Mode**: Intelligent scan type selection based on privileges
- **Preset Configurations**: Quick setup for common scenarios

## 🛡️ Security Risk Assessment

### Risk Analysis Features

The integrated risk assessment engine provides enterprise-grade security analysis:

```bash
# Basic risk assessment
portscanner -t example.com --risk-assessment

# Compliance checking
portscanner -t example.com --compliance pci-dss
portscanner -t example.com --compliance nist
portscanner -t example.com --compliance all

# Threat modeling
portscanner -t example.com --threat-model

# Comprehensive security analysis
portscanner -t example.com --aggressive
```

### Security Posture Classifications

- **🟢 Excellent (86-100)**: Minimal security risks, strong configuration
- **🟡 Good (71-85)**: Generally secure with minor improvements needed
- **🟠 Fair (51-70)**: Moderate risks requiring attention
- **🔴 Poor (31-50)**: Significant security concerns
- **💀 Critical (0-30)**: Immediate security action required

### Risk Categories Analyzed

1. **🎯 Exposed Services**: Attack surface and unnecessary service exposure
2. **🔓 Insecure Protocols**: Use of deprecated or unencrypted protocols
3. **🔐 Weak Authentication**: Default credentials and weak access controls
4. **📡 Unencrypted Traffic**: Missing or weak encryption implementation
5. **📊 Database Exposure**: Database service exposure and security
6. **🚪 Remote Access**: Remote administration service security
7. **🖥️ Network Devices**: Network infrastructure security assessment
8. **🌐 Web Applications**: Web service security and configuration

### Compliance Frameworks

- **📋 PCI DSS**: Payment Card Industry Data Security Standard
- **🏛️ NIST**: NIST Cybersecurity Framework
- **🔒 SOC 2**: Service Organization Control 2 (planned)
- **🌐 ISO 27001**: International security management standard (planned)

## 🎮 Interactive Mode

Launch the interactive mode for guided scanning with security assessment:

```bash
# Start interactive mode
./target/release/portscanner --interactive

# Or use the short flag
./target/release/portscanner -i
```

The enhanced interactive mode now includes:
- **🛡️ Risk Assessment Configuration**: Enable comprehensive security analysis
- **📋 Compliance Framework Selection**: Choose specific compliance standards
- **🎯 Threat Modeling Options**: Advanced threat analysis configuration
- **📊 Report Format Selection**: Choose output formats including security dashboards

### Enhanced Interactive Mode Screenshot

```
🎮 Interactive Port Scanner Setup
══════════════════════════════════════════════════════════════

🎯 Target (IP/hostname): scanme.nmap.org
🔌 Protocol: Both TCP and UDP
📡 Port range: Top 1000 ports (default)
⚡ Performance level: Balanced (100)
🔧 Enable advanced features:
  ✅ Service Detection
  ✅ OS Fingerprinting
  ✅ SSL/TLS Analysis
  ✅ Banner Grabbing
  ✅ Risk Assessment
  ✅ Threat Modeling
📋 Compliance framework: PCI DSS
📊 Output format: HTML report with security dashboard

📋 Scan Configuration Summary:
   Target: scanme.nmap.org
   Ports: 1-1000
   Protocol: both
   Concurrency: 100
   Features: Service Detection, OS Fingerprinting, SSL Analysis, 
            Banner Grabbing, Risk Assessment, Threat Modeling
   Compliance: PCI DSS

🚀 Start scan with these settings? [Y/n]: y
```

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/genc-murat/portscanner.git
cd portscanner

# Build the project
cargo build --release

# Try interactive mode first
./target/release/portscanner --interactive

# Run a basic scan with security assessment
./target/release/portscanner -t google.com -p 80,443 --risk-assessment

# Generate comprehensive security report
./target/release/portscanner -t scanme.nmap.org --aggressive --html security_report.html
```

### Security Assessment Commands

```bash
# Interactive mode with guided security setup
portscanner --interactive

# Quick security assessment
portscanner -t example.com --risk-assessment

# Compliance checking
portscanner -t example.com --compliance pci-dss --html compliance_report.html

# Comprehensive threat analysis
portscanner -t example.com --threat-model --json > threat_model.json

# Executive security dashboard
portscanner -t example.com --aggressive --html executive_dashboard.html

# SIEM integration (JSON output with all security data)
portscanner -t example.com --aggressive --json > siem_data.json
```

### Basic Usage with Security Features

```bash
# Security-focused scan
portscanner -t example.com --risk-assessment --ssl-analysis

# Compliance audit scan
portscanner -t example.com --compliance all --html audit_report.html

# Threat intelligence gathering
portscanner -t example.com --threat-model --os-detection --service-detection

# Vulnerability assessment
portscanner -t example.com --aggressive --compliance nist
```

## 🎨 Enhanced User Interface

### Security-Enhanced Visual Features

- **🛡️ Security Scoring Displays**: Real-time risk score visualization
- **🚨 Critical Alert Highlighting**: Immediate attention to high-risk findings
- **📊 Compliance Status Indicators**: Visual compliance framework status
- **🎯 Threat Level Indicators**: Color-coded threat severity levels
- **💡 Smart Security Recommendations**: Contextual security guidance

### Enhanced Progress Tracking

```
🚀 SCAN INITIALIZATION
╔═══════════════════════════════════════════════════════════════╗
║                    🚀 SCAN INITIALIZATION                     ║
╚═══════════════════════════════════════════════════════════════╝
🎯 Target:           example.com
📡 Total Ports:      1000
🔧 Scan Method:      TCP Connect
🔌 Protocol(s):      TCP
⚡ Concurrency:      100
⏱️ Timeout:          3000ms
🔍 Service Detection: ENABLED
🖥️ OS Fingerprinting: ENABLED
🔐 SSL/TLS Analysis:  ENABLED
🛡️ Risk Assessment:   ENABLED
📋 Compliance Check:  PCI DSS
🎯 Threat Modeling:   ENABLED

🔍 Scanning example.com [████████████████████████████████████████████████████] 100% (1000/1000)
  🌐 TCP  [████████████████████████████████████████████████████] 1000/1000 scanning...
  🔐 SSL  [████████████████████████████████████████████████████] 3/3 analyzing...
  🖥️ OS   [████████████████████████████████████████████████████] 100% fingerprinting...
  🛡️ Risk [████████████████████████████████████████████████████] 100% assessing...
```

### Enhanced Security Results Display

```
╔═══════════════════════════════════════════════════════════════╗
║                     🛡️ SECURITY ASSESSMENT                   ║
╚═══════════════════════════════════════════════════════════════╝

🛡️ Overall Risk Score: 73/100 (Good)

🚨 CRITICAL FINDINGS:
   • High-Risk Service Exposed: Port 23 (Telnet)
     Remediation: Disable Telnet service. Use SSH for secure remote access.

📊 RISK CATEGORIES:
   🟢 Exposed Services: 85/100 (Good priority)
   🔴 Insecure Protocols: 45/100 (High priority)
   🟡 Unencrypted Traffic: 60/100 (Medium priority)
   🟢 Database Exposure: 100/100 (Low priority)
   🟡 Remote Access: 70/100 (Medium priority)

💡 TOP RECOMMENDATIONS:
   1. 🚨 Address: High-Risk Service Exposed: Port 23
      Disable Telnet service. Use SSH for secure remote access.
   2. 🔴 Migrate to Secure Protocols
      Replace insecure protocols (Telnet, FTP, HTTP) with secure alternatives.
   3. 🔴 Implement Encryption
      Enable encryption for all data in transit. Update SSL/TLS configurations.

🎯 ATTACK SURFACE:
   • 5 total exposed ports
   • 1 high-risk services
   • 3 potential entry points

📋 COMPLIANCE STATUS:
   • Overall Compliance: 78%
   • PCI DSS: 65%
   • NIST: 91%

🎯 THREAT MODEL:
   • 3 threat actors identified
   • 4 attack scenarios modeled
   • Asset criticality: High
   • Data sensitivity: Confidential
```

## 📊 Usage

```
🚀 Advanced Port Scanner with Security Risk Assessment

USAGE:
    portscanner [OPTIONS] --target <TARGET>

ARGUMENTS:
    -t, --target <IP/HOSTNAME>     🎯 Target IP address or hostname

OPTIONS:
    -p, --ports <PORT_RANGE>       📡 Ports to scan [default: 1-1000]
        --protocol <PROTOCOL>      🔌 Protocol to scan [default: tcp] [possible values: tcp, udp, both]
    -c, --concurrency <THREADS>    ⚡ Number of concurrent connections [default: 100]
    -T, --timeout <MILLISECONDS>   ⏱️ Connection timeout [default: 3000]
    -i, --interactive              🎮 Interactive mode with guided setup
    -q, --quick                    ⚡ Quick scan mode (top 100 ports)
    -v, --verbose                  📝 Verbose output with detailed information

SCANNING MODES:
    -b, --banner                   🏷️ Enable banner grabbing
    -s, --stealth                  👤 Use stealth SYN scan (requires root)
        --scan-type <TYPE>         🔍 Scan technique [default: auto]
        --service-detection        🔧 Enable advanced service detection
        --ssl-analysis             🔐 Enable SSL/TLS analysis
    -O, --os-detection             🖥️ Enable OS fingerprinting
    -A, --aggressive               🚀 Enable all detection methods + security analysis
    -U, --udp-common               📡 Scan common UDP ports

SECURITY ASSESSMENT:
        --risk-assessment          🛡️ Enable comprehensive security risk assessment
        --compliance <FRAMEWORK>   📋 Check compliance [possible values: pci-dss, nist, all]
        --threat-model             🎯 Generate threat model and attack scenarios

OUTPUT OPTIONS:
    -j, --json                     📋 Output in JSON format (includes security data)
        --html <FILENAME>          📊 Generate HTML report with security dashboard
        --ipv6-only                🌐 Force IPv6 resolution
        --ipv4-only                🌍 Force IPv4 resolution

EXAMPLES:
    # Interactive mode with security guidance
    portscanner --interactive

    # Quick security assessment
    portscanner -t example.com --risk-assessment

    # Compliance audit
    portscanner -t example.com --compliance pci-dss --html audit.html

    # Comprehensive security analysis
    portscanner -t example.com --aggressive

    # Threat intelligence
    portscanner -t example.com --threat-model --json > threat_intel.json

    # Executive security report
    portscanner -t example.com --aggressive --html executive_report.html
```

## 🎯 Sample Security Assessment Output

### Enhanced Terminal Output with Security Analysis

```
🛡️  SECURITY RISK ASSESSMENT
════════════════════════════════════════════════════════════════

🟡 Overall Risk Score: 73/100 (Good)

🚨 CRITICAL FINDINGS:
   • High-Risk Service Exposed: Port 23 (Ports: [23])
     Remediation: Disable Telnet service. Use SSH for secure remote access.

📊 RISK CATEGORIES:
   🟢 ExposedServices: 85/100 (Medium priority)
   🔴 InsecureProtocols: 45/100 (High priority)
   🟡 UnencryptedTraffic: 60/100 (High priority)
   🟢 DatabaseExposure: 100/100 (Low priority)
   🟡 RemoteAccess: 70/100 (Medium priority)

💡 TOP RECOMMENDATIONS:
   1. 🚨 Address: High-Risk Service Exposed: Port 23
      Disable Telnet service. Use SSH for secure remote access.
   2. 🔴 Migrate to Secure Protocols
      Replace insecure protocols (Telnet, FTP, HTTP) with secure alternatives (SSH, SFTP, HTTPS).
   3. 🔴 Implement Encryption
      Enable encryption for all data in transit. Update SSL/TLS configurations.
   4. 🟡 Implement Security Monitoring
      Deploy SIEM, intrusion detection systems, and log monitoring for early threat detection.
   5. 🟢 Regular Security Assessments
      Conduct regular penetration testing and vulnerability assessments.

🎯 ATTACK SURFACE:
   • 5 total exposed ports
   • 1 high-risk services
   • 3 potential entry points

📋 COMPLIANCE STATUS:
   • Overall Compliance: 78%
   • PCI_DSS: 65%
   • NIST: 91%

════════════════════════════════════════════════════════════════
```

## 🔧 Building from Source

### Enhanced Dependencies

```toml
[dependencies]
tokio = { version = "1.0", features = ["full"] }
clap = { version = "4.0", features = ["derive"] }
colored = "2.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rand = "0.8"
regex = "1.10"
async-trait = "0.1"
thiserror = "1.0"
futures = "0.3"
chrono = { version = "0.4", features = ["serde"] }
indicatif = "0.17"
dialoguer = "0.10"
console = "0.15"
crossterm = "0.27"

# Unix-specific dependencies for raw socket support
[target.'cfg(unix)'.dependencies]
libc = "0.2"
```

### Build Steps with Security Testing

```bash
# Clone the repository
git clone https://github.com/genc-murat/portscanner.git
cd portscanner

# Build optimized release version
cargo build --release

# Run comprehensive tests (includes security assessment tests)
cargo test

# Test interactive mode with security features
cargo run -- --interactive

# Test security assessment functionality
cargo run -- -t 127.0.0.1 --risk-assessment --compliance all

# Test threat modeling
cargo run -- -t localhost --threat-model --json

# Test comprehensive security analysis
cargo run -- -t scanme.nmap.org --aggressive --html security_test.html
```

## 🎯 IPv6 Support with Security Analysis

IPv6 targets receive full security assessment including:

```bash
# IPv6 security assessment
portscanner -t 2001:db8::1 --risk-assessment

# IPv6 compliance checking
portscanner -t 2606:4700::6810:85e5 --compliance pci-dss

# Comprehensive IPv6 security analysis
portscanner -t 2001:4860:4860::8888 --aggressive --html ipv6_security.html
```

## 🎨 Enhanced HTML Security Reports

The HTML reports now include comprehensive security dashboards:

### Security Dashboard Features
- **📊 Executive Summary**: High-level security posture overview
- **🛡️ Risk Score Visualization**: Interactive risk scoring charts
- **🚨 Critical Findings**: Prioritized security issues
- **📋 Compliance Matrix**: Framework-specific compliance status
- **🎯 Attack Surface Map**: Visual attack vector analysis
- **💡 Remediation Roadmap**: Prioritized action items with timelines

### Security Report Sections
1. **Executive Summary**: C-level security overview
2. **Risk Assessment**: Detailed risk analysis and scoring
3. **Critical Findings**: Immediate action items
4. **Vulnerability Details**: Technical vulnerability information
5. **Compliance Status**: Framework-specific compliance checking
6. **Attack Surface Analysis**: Entry points and lateral movement risks
7. **Threat Model**: Advanced threat intelligence
8. **Recommendations**: Prioritized remediation guidance
9. **Technical Details**: Standard port scan results
10. **Appendices**: Reference materials and methodology

## 🤝 Contributing

Contributions are welcome! Security-focused contributions are especially appreciated:

### Security Development Areas
- **🛡️ Risk Assessment Engine**: Enhance risk calculation algorithms
- **📋 Compliance Frameworks**: Add support for additional standards
- **🎯 Threat Intelligence**: Improve threat modeling capabilities
- **🔒 Vulnerability Database**: Expand vulnerability detection
- **📊 Reporting**: Enhance security visualization and dashboards

### Development Setup with Security Testing

```bash
# Fork and clone the repo
git clone https://github.com/genc-murat/portscanner.git
cd portscanner

# Create a security feature branch
git checkout -b feature/security-enhancement

# Test security features
cargo test
cargo run -- -t 127.0.0.1 --aggressive
cargo run -- --interactive

# Validate security assessment accuracy
cargo run -- -t scanme.nmap.org --risk-assessment --compliance all --html test_security.html

# Commit and push
git commit -m "Add security enhancement"
git push origin feature/security-enhancement
```

## 📝 License

This project is licensed under the MIT License - see the **LICENSE** file for details.

## ⚠️ Security Disclaimer

This tool is designed for authorized security testing and assessment purposes only. The risk assessment and vulnerability detection features should be used responsibly:

- ✅ **Authorized Testing**: Only scan systems you own or have explicit permission to test
- ✅ **Security Research**: Use for legitimate security research and hardening
- ✅ **Compliance Auditing**: Employ for regulatory compliance verification
- ❌ **Unauthorized Scanning**: Never scan systems without proper authorization
- ❌ **Malicious Use**: Do not use for illegal or harmful activities

## 🙏 Acknowledgments

- Inspired by the original [Nmap](https://nmap.org/) project
- Security assessment methodologies based on industry standards
- Built with the amazing [Tokio](https://tokio.rs/) async runtime
- CLI powered by [Clap](https://clap.rs/)
- Interactive UI powered by [Dialoguer](https://github.com/console-rs/dialoguer)
- Progress bars by [Indicatif](https://github.com/console-rs/indicatif)
- Risk assessment frameworks inspired by NIST and OWASP guidelines

---

⭐ If you find this project useful for your security assessments, please consider giving it a star on GitHub!

## 📚 Security Resources

### Risk Assessment Resources
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
- [CVSS Scoring Guide](https://www.first.org/cvss/user-guide)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)

### Vulnerability Assessment Resources
- [CVE Database](https://cve.mitre.org/)
- [NVD Vulnerability Database](https://nvd.nist.gov/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Common Weakness Enumeration](https://cwe.mitre.org/)

### Compliance Resources
- [PCI DSS Self-Assessment](https://www.pcisecuritystandards.org/pci_security/completing_self_assessment)
- [NIST Compliance Guide](https://www.nist.gov/cyberframework/getting-started)
- [SOC 2 Compliance](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)
- [ISO 27001 Information Security](https://www.iso.org/isoiec-27001-information-security.html)

### IPv6 Security Resources
- [RFC 4942 - IPv6 Transition/Coexistence Security Considerations](https://tools.ietf.org/html/rfc4942)
- [NIST IPv6 Security Guidelines](https://csrc.nist.gov/publications/detail/sp/800-119/final)
- [IPv6 Security Best Practices](https://www.internetsociety.org/deploy360/ipv6/security/)

---

🛡️ **Ready for comprehensive security assessment? Start with interactive mode!**

```bash
./target/release/portscanner --interactive
```

🚀 **Quick security check:**

```bash
./target/release/portscanner -t your-target.com --risk-assessment --compliance all
```