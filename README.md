# Port Scanner

A fast, modern port scanner written in Rust with async networking, TCP/UDP scanning, stealth SYN scan, SSL/TLS analysis, advanced service detection, and OS fingerprinting capabilities. Inspired by Nmap but built for speed and simplicity.

## Features

- **Fast Async Scanning**: Built with Tokio for high-performance concurrent scanning
- **TCP & UDP Support**: Comprehensive scanning for both TCP and UDP protocols
- **Stealth SYN Scan**: Raw socket SYN scanning for speed and stealth (Linux/Unix)
- **SSL/TLS Analysis**: Complete SSL/TLS security assessment with vulnerability detection
- **UDP Service Detection**: Protocol-specific probes for common UDP services
- **Banner Grabbing**: Extract service banners and version information (TCP)
- **Advanced Service Detection**: Nmap-style service identification with 150+ signatures
- **OS Fingerprinting**: Operating system detection via TCP/IP stack analysis
- **Certificate Analysis**: SSL certificate validation and security assessment
- **Vulnerability Detection**: SSL/TLS vulnerability scanning (Heartbleed, POODLE, BEAST, etc.)
- **Multiple Target Support**: Scan IP addresses or hostnames
- **Service Detection**: Identify services with version and product information
- **Colored Output**: Beautiful terminal output with syntax highlighting
- **JSON Export**: Export results in JSON format for further analysis
- **Configurable**: Customize concurrency, timeouts, and port ranges
- **Safe**: Built-in rate limiting and timeout controls
- **Auto Mode**: Intelligent scan type selection based on privileges

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/genc-murat/portscanner.git
cd portscanner

# Build the project
cargo build --release

# Run a basic TCP scan
./target/release/portscanner -t google.com -p 80,443

# Run a UDP scan
./target/release/portscanner -t 8.8.8.8 --protocol udp -p 53,123

# Run both TCP and UDP scan
./target/release/portscanner -t 192.168.1.1 --protocol both -p 1-1000

# Run SSL/TLS analysis
./target/release/portscanner -t secure-site.com -p 443 --ssl-analysis

# Run common UDP ports scan
./target/release/portscanner -t 192.168.1.1 --udp-common

# Run with service detection
./target/release/portscanner -t 192.168.1.1 -p 1-1000 --service-detection

# Run with OS fingerprinting (TCP only)
./target/release/portscanner -t 192.168.1.1 -p 22,80,443 -O

# Run aggressive scan (everything enabled including SSL analysis)
./target/release/portscanner -t 192.168.1.1 --protocol both -A

# Run stealth SYN scan (requires root)
sudo ./target/release/portscanner -t 192.168.1.1 -s
```

### Basic Usage

```bash
# Scan common TCP ports on a target
portscanner -t 192.168.1.1

# Scan UDP ports
portscanner -t 192.168.1.1 --protocol udp

# Scan both TCP and UDP
portscanner -t 192.168.1.1 --protocol both

# Scan specific ports with banner grabbing (TCP only)
portscanner -t example.com -p 22,80,443 -b

# SSL/TLS security assessment
portscanner -t example.com -p 443,993,995 --ssl-analysis

# Scan port range with high concurrency
portscanner -t 192.168.1.1 -p 1-1000 -c 200

# Export results to JSON
portscanner -t target.com --protocol both --ssl-analysis -p 80,443,53,123 -j > results.json
```

## Usage

```
Port Scanner v0.4.0

USAGE:
    portscanner [OPTIONS] --target <TARGET>

OPTIONS:
    -t, --target <TARGET>           Target IP address or hostname
    -p, --ports <PORTS>             Ports to scan (e.g., 80,443,22-25) [default: 1-1000]
        --protocol <PROTOCOL>       Protocol to scan: tcp, udp, or both [default: tcp]
    -c, --concurrency <CONCURRENCY> Number of concurrent connections [default: 100]
    -T, --timeout <TIMEOUT>         Connection timeout in milliseconds [default: 3000]
    -b, --banner                    Enable banner grabbing (TCP only)
    -s, --stealth                   Use stealth SYN scan for TCP (requires root)
    -j, --json                      Output results in JSON format
        --scan-type <TYPE>          Scan type: tcp, syn, udp, or auto [default: auto]
        --service-detection         Enable advanced service detection
        --ssl-analysis              Enable SSL/TLS analysis for HTTPS and other SSL services
    -O, --os-detection              Enable OS fingerprinting (TCP only)
    -A, --aggressive               Aggressive mode (service detection + banner + OS detection + SSL analysis)
    -U, --udp-common               Scan common UDP ports
        --top-ports <NUM>          Scan top N most common ports for selected protocol(s)
    -h, --help                      Print help information
    -V, --version                   Print version information
```

## Examples

### Basic Port Scanning

```bash
# Scan default TCP port range (1-1000)
portscanner -t 192.168.1.1

# Scan UDP ports
portscanner -t 192.168.1.1 --protocol udp -p 53,123,161

# Scan both TCP and UDP
portscanner -t 192.168.1.1 --protocol both -p 1-100

# Scan specific ports
portscanner -t google.com -p 80,443,22

# Scan port ranges
portscanner -t 192.168.1.1 -p 1-100

# Mixed port specification
portscanner -t example.com -p 22,80-90,443,8080-8090
```

### SSL/TLS Security Assessment

```bash
# Basic SSL analysis
portscanner -t google.com -p 443 --ssl-analysis

# Multiple SSL ports analysis
portscanner -t mail.example.com -p 443,993,995,465 --ssl-analysis

# Comprehensive SSL security audit
portscanner -t example.com -p 443,8443,9443 --ssl-analysis --service-detection

# SSL analysis with JSON output
portscanner -t secure-site.com -p 443 --ssl-analysis -j > ssl_report.json

# Enterprise SSL assessment
portscanner -t corporate-site.com -p 443,993,995,465,587,636,853,990 --ssl-analysis -A
```

### UDP Scanning

```bash
# Common UDP ports scan
portscanner -t 192.168.1.1 --udp-common

# Specific UDP services
portscanner -t 8.8.8.8 --protocol udp -p 53 --service-detection

# UDP with custom timeout (recommended for UDP)
portscanner -t 192.168.1.1 --protocol udp -p 1-500 -T 5000

# Top UDP ports
portscanner -t target.com --protocol udp --top-ports 20
```

### Advanced Scanning

```bash
# High-speed TCP scanning with increased concurrency
portscanner -t 192.168.1.1 -p 1-65535 -c 500

# Banner grabbing for TCP service identification
portscanner -t 192.168.1.1 -p 21,22,80,443 -b

# Custom timeout for slow networks
portscanner -t slow-server.com -p 1-1000 -T 5000

# JSON output for automation
portscanner -t target.com --protocol both --ssl-analysis -p 80,443,53,123 -j | jq '.[] | select(.is_open)'

# Mixed protocol scanning with SSL analysis
portscanner -t 192.168.1.1 --protocol both --ssl-analysis --service-detection --top-ports 100
```

### Real-world Examples

```bash
# Web server security assessment (TCP + UDP + SSL)
portscanner -t example.com --protocol both --ssl-analysis -p 80,443,53,8080,8443

# Mail server security audit
portscanner -t mail.example.com --ssl-analysis -p 25,465,587,993,995,143,110 -A

# Database server discovery
portscanner -t db-server.local -p 3306,5432,1433,27017,6379 -b

# Network infrastructure scan (TCP + UDP)
portscanner -t 192.168.1.1 --protocol both -p 21,22,23,53,67,80,161,443,514,1900

# Complete security assessment
portscanner -t target.com --protocol both --ssl-analysis -A --top-ports 200

# DNS server analysis
portscanner -t 8.8.8.8 --protocol udp -p 53 --service-detection

# DHCP server discovery
portscanner -t 192.168.1.1 --protocol udp -p 67,68 --service-detection

# Development environment scan
portscanner -t localhost --protocol both --ssl-analysis -p 3000,4000,5000,8000,8080,9000
```

## Sample Output

### Standard Output (Comprehensive Scan with SSL Analysis)
```
Port Scanner v0.4.0
Target: secure-example.com
Protocol(s): TCP, UDP
Aggressive mode enabled (service detection + banner grabbing + OS detection + SSL analysis)
Advanced service detection enabled
OS fingerprinting enabled
SSL/TLS analysis enabled

Starting scan: secure-example.com (8 ports)
Scan method: Mixed TCP/UDP Scan
 Performing SSL/TLS analysis on 2 ports
 Performing OS detection for secure-example.com

================================================================================
Port Scan Results - secure-example.com
================================================================================

TCP Ports
----------------------------------------
4 open TCP ports found:

🔗    22/tcp open ssh OpenSSH 8.2p1        (  45ms)
        Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
        CPE: cpe:/a:openbsd:openssh:8.2p1

🔗    80/tcp open http Apache httpd 2.4.41  ( 156ms)
        Banner: Server: Apache/2.4.41 (Ubuntu)
        CPE: cpe:/a:apache:http_server:2.4.41

🔗   443/tcp open https nginx 1.18.0       ( 198ms)
        Banner: Server: nginx/1.18.0
        CPE: cpe:/a:nginx:nginx:1.18.0

🔗   993/tcp open imaps Dovecot imapd      ( 234ms)
        Banner: * OK [CAPABILITY IMAP4rev1] Dovecot ready
        CPE: cpe:/a:dovecot:dovecot

UDP Ports
----------------------------------------
2 open UDP ports found:

📡    53/udp open DNS Server                ( 145ms)
        Response: DNS Server

📡   123/udp open NTP Server (v4)          ( 267ms)
        Response: NTP Server (v4)

1 UDP ports open|filtered (no response):
❓   161/udp open|filtered snmp

SSL/TLS Analysis for secure-example.com:443
============================================================
🟢 Security Score: 92/100 (Excellent)

Certificate Information
------------------------------
Subject: CN=secure-example.com
Issuer: CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
🟢 Valid until: 2025-06-15T23:59:59Z (267 days)
🟢 Public Key: RSA 2048 bits
🟢 Signature: SHA256-RSA
🔗 Alt Names: secure-example.com, *.secure-example.com, www.secure-example.com

Supported Protocols
------------------------------
🟢 TLS 1.2
🟢 TLS 1.3

Cipher Suites
------------------------------
🟢 🔒 TLS_AES_256_GCM_SHA384 (TLS 1.3)
🟢 🔒 TLS_AES_128_GCM_SHA256 (TLS 1.3)
🟢 🔒 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (TLS 1.2)
🟢 🔒 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)

Recommendations
------------------------------
• 🟢 SSL/TLS configuration is secure
• 💡 Implement HTTP Strict Transport Security (HSTS)
• 💡 Consider certificate transparency monitoring

Analysis completed in 2.34s
============================================================

SSL/TLS Analysis for secure-example.com:993
============================================================
🟡 Security Score: 78/100 (Good)

Certificate Information
------------------------------
Subject: CN=secure-example.com
Issuer: CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
🟡 Valid until: 2025-01-20T23:59:59Z (120 days)
🟢 Public Key: RSA 2048 bits
🟢 Signature: SHA256-RSA

Supported Protocols
------------------------------
🟢 TLS 1.2
🟢 TLS 1.3

Recommendations
------------------------------
• 🟢 SSL/TLS configuration is secure
• Certificate expires in 4 months - consider renewal planning

⏱️ Analysis completed in 1.87s
============================================================

OS Detection Results
----------------------------------------
Operating System: Linux (87% confidence)
    Details:
      • TTL: 64
      • Window Size: 29200
      • MSS: 1460
      • TCP Timestamps: Enabled
      • Window Scaling: Enabled
      • SACK: Enabled

Scan Summary
----------------------------------------
Total ports scanned: 8
Open ports: 6
Open|Filtered ports: 1
Closed ports: 0
Filtered ports: 0
SSL/TLS services found: 2
Scan time: 3.12s
Scan method: Mixed TCP/UDP Scan
Protocols: TCP, UDP
Average response time: 0.189s
Services identified with high confidence: TCP 4/4, UDP 2/2
OS detection: Success (High confidence)
SSL/TLS analysis: 2 services analyzed

================================================================================
```

### JSON Output (Including SSL Analysis)
```json
{
  "target": "secure-example.com",
  "scan_results": [
    {
      "port": 22,
      "is_open": true,
      "service": "ssh",
      "service_info": {
        "name": "ssh",
        "version": "8.2p1",
        "product": "OpenSSH",
        "confidence": 95,
        "cpe": "cpe:/a:openbsd:openssh:8.2p1"
      },
      "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
      "response_time": 45,
      "scan_type": "TCP",
      "protocol": "TCP",
      "udp_state": null
    },
    {
      "port": 443,
      "is_open": true,
      "service": "https",
      "service_info": {
        "name": "https",
        "product": "nginx",
        "version": "1.18.0",
        "confidence": 90
      },
      "response_time": 198,
      "scan_type": "TCP", 
      "protocol": "TCP"
    }
  ],
  "ssl_analysis": [
    {
      "target": "secure-example.com",
      "port": 443,
      "is_ssl_enabled": true,
      "certificate_info": {
        "subject": "CN=secure-example.com",
        "issuer": "CN=DigiCert Global Root CA",
        "days_until_expiry": 267,
        "is_expired": false,
        "is_self_signed": false,
        "public_key_algorithm": "RSA",
        "public_key_size": 2048,
        "signature_algorithm": "SHA256-RSA",
        "subject_alt_names": ["secure-example.com", "*.secure-example.com"]
      },
      "supported_protocols": [
        {
          "version": "TLS 1.2",
          "supported": true,
          "deprecated": false,
          "security_level": "Secure"
        },
        {
          "version": "TLS 1.3",
          "supported": true,
          "deprecated": false,
          "security_level": "Secure"
        }
      ],
      "cipher_suites": [
        {
          "name": "TLS_AES_256_GCM_SHA384",
          "protocol": "TLS 1.3",
          "security_level": "Secure",
          "is_forward_secret": true
        }
      ],
      "vulnerabilities": [],
      "security_score": 92,
      "recommendations": [
        "🟢 SSL/TLS configuration is secure",
        "Implement HTTP Strict Transport Security (HSTS)"
      ],
      "scan_time": 2.34
    }
  ],
  "os_fingerprint": {
    "os_family": "Linux",
    "os_name": "Linux",
    "confidence": 87,
    "details": ["TTL: 64", "Window Size: 29200"]
  },
  "scan_summary": {
    "total_ports": 8,
    "open_ports": 6,
    "open_filtered_ports": 1,
    "ssl_services_found": 2,
    "scan_time": 3.12,
    "protocols_scanned": ["TCP", "UDP"]
  }
}
```

## SSL/TLS Security Analysis Features

### Certificate Analysis
- **Validity Check**: Expiration dates and validity periods
- **Issuer Verification**: Certificate authority validation
- **Key Strength**: Public key algorithms and sizes
- **Signature Algorithms**: SHA-1, SHA-256, etc. assessment
- **Subject Alternative Names**: Domain coverage analysis
- **Self-signed Detection**: Identifies self-signed certificates
- **Wildcard Certificates**: Detects wildcard usage

### Protocol Security Assessment
- **Protocol Versions**: SSL 2.0/3.0, TLS 1.0/1.1/1.2/1.3 support testing
- **Deprecated Protocols**: Identifies insecure protocol versions
- **Cipher Suite Analysis**: Encryption strength evaluation
- **Forward Secrecy**: Perfect Forward Secrecy assessment
- **Key Exchange**: ECDHE, DHE, RSA evaluation

### Vulnerability Detection
- **Heartbleed (CVE-2014-0160)**: OpenSSL memory disclosure
- **POODLE (CVE-2014-3566)**: SSL 3.0 padding oracle attack
- **BEAST (CVE-2011-3389)**: TLS 1.0 CBC vulnerability
- **CRIME (CVE-2012-4929)**: TLS compression attack
- **BREACH (CVE-2013-3587)**: HTTP compression vulnerability

### Security Scoring
- **0-100 Scale**: Comprehensive security assessment
- **Color-coded Results**: Visual security status indicators
- **Detailed Recommendations**: Actionable security improvements
- **Risk Assessment**: Critical, High, Medium, Low severity levels

## UDP Scanning Notes

### Understanding UDP Results

UDP scanning produces different states compared to TCP:
- **Open**: Service responded to probe
- **Open|Filtered**: No response (common for UDP - service may be running)
- **Closed**: ICMP Port Unreachable received
- **Filtered**: ICMP filtering or firewall blocking

### UDP Performance Tips

```bash
# For local network UDP scanning
portscanner -t 192.168.1.1 --protocol udp -c 100 -T 3000

# For internet UDP scanning (more conservative)
portscanner -t remote-host.com --protocol udp -c 50 -T 5000

# Quick common UDP services check
portscanner -t target --udp-common --service-detection
```

## Building from Source

### Prerequisites

- Rust 1.70 or later
- Cargo package manager

### Dependencies

```toml
[dependencies]
tokio = { version = "1.0", features = ["full"] }
clap = { version = "4.0", features = ["derive"] }
colored = "2.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rand = "0.8"
regex = "1.10"

# Unix-specific dependencies for raw socket support
[target.'cfg(unix)'.dependencies]
libc = "0.2"
```

### Build Steps

```bash
# Clone the repository
git clone https://github.com/genc-murat/portscanner.git
cd portscanner

# Build in debug mode
cargo build

# Build optimized release version
cargo build --release

# Run tests
cargo test

# Run with cargo (TCP scan)
cargo run -- -t google.com -p 80,443

# Run with cargo (UDP scan)
cargo run -- -t 8.8.8.8 --protocol udp -p 53

# Run with cargo (SSL analysis)
cargo run -- -t example.com -p 443 --ssl-analysis
```

## 🔧 Configuration

### Performance Tuning

- **Concurrency**: Increase `-c` for faster scans, but be mindful of network limits
- **Timeout**: Adjust `-T` based on network conditions (UDP and SSL need higher timeouts)
- **Port Ranges**: Use specific ports instead of broad ranges for faster results
- **Protocol Selection**: Use `--protocol tcp` for faster TCP-only scans

### Best Practices

```bash
# For local networks (fast)
portscanner -t 192.168.1.1 -p 1-1000 -c 300 -T 1000

# For internet hosts (moderate)
portscanner -t example.com --protocol both --ssl-analysis -p 1-1000 -c 100 -T 3000

# For slow/filtered networks (conservative)
portscanner -t target.com --protocol both --ssl-analysis -p 80,443,53,123 -c 50 -T 10000

# UDP-specific recommendations
portscanner -t target --protocol udp --udp-common -T 5000 -c 50

# SSL analysis recommendations
portscanner -t target --ssl-analysis -T 8000 -c 20
```

## Supported Detection

### **TCP Service Detection (150+ signatures)**
- **Web Services**: Apache, nginx, IIS, lighttpd, Node.js, Django
- **Remote Access**: OpenSSH, Dropbear, Telnet, RDP, VNC
- **Mail Services**: Postfix, Sendmail, Exchange, Dovecot, Courier
- **Databases**: MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle
- **File Services**: vsftpd, ProFTPD, Samba, NFS, TFTP
- **Network Services**: BIND DNS, DHCP, SNMP, NTP

### **UDP Service Detection**
- **DNS (53)**: BIND, dnsmasq, PowerDNS with version detection
- **NTP (123)**: Network time servers with version identification
- **SNMP (161/162)**: Network management protocols
- **DHCP (67/68)**: Dynamic host configuration
- **TFTP (69)**: Trivial file transfer protocol
- **NetBIOS (137/138)**: Windows networking services
- **mDNS (5353)**: Multicast DNS/Bonjour services
- **UPnP SSDP (1900)**: Universal Plug and Play discovery
- **SIP (5060)**: VoIP signaling protocol
- **Syslog (514)**: System logging services

### **SSL/TLS Service Detection**
- **HTTPS (443, 8443, 9443)**: Web servers with SSL/TLS
- **SMTPS (465)**: SMTP over SSL
- **SMTP+TLS (587)**: SMTP with STARTTLS
- **IMAPS (993)**: IMAP over SSL
- **POP3S (995)**: POP3 over SSL
- **LDAPS (636)**: LDAP over SSL
- **DNS-over-TLS (853)**: Secure DNS
- **FTPS (990)**: FTP over SSL
- **WinRM HTTPS (5986)**: Windows Remote Management over HTTPS

### **OS Fingerprinting (TCP-based)**
- **Linux**: Ubuntu, CentOS, RHEL, Debian, Alpine, Android
- **Windows**: 7, 8, 10, 11, Server 2016/2019/2022
- **Unix**: FreeBSD, OpenBSD, NetBSD, Solaris
- **Apple**: macOS 10.x, 11.x, 12.x+
- **Network Devices**: Cisco IOS, Juniper JunOS
- **Embedded**: IoT devices, routers, switches

## Protocol-Specific Features

### TCP Scanning
- **Connection-based**: Reliable open/closed detection
- **Banner Grabbing**: Extract service banners and headers
- **Stealth SYN**: Raw socket scanning (Linux/Unix + root)
- **OS Fingerprinting**: TCP/IP stack analysis
- **SSL/TLS Analysis**: Complete SSL security assessment
- **Fast**: Generally faster than UDP scanning

### UDP Scanning
- **Connectionless**: Uses service-specific probes
- **Service Detection**: Protocol-aware payload generation
- **State Detection**: Open, Open|Filtered, Closed, Filtered
- **Retry Logic**: Built-in retries for reliability
- **Timeout Sensitive**: Requires appropriate timeout values

### SSL/TLS Analysis
- **Certificate Validation**: Complete certificate chain analysis
- **Protocol Testing**: Support for all SSL/TLS versions
- **Cipher Assessment**: Encryption strength evaluation
- **Vulnerability Scanning**: Known SSL/TLS vulnerabilities
- **Security Scoring**: 0-100 security assessment
- **Compliance Checking**: Industry standard validation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
# Fork and clone the repo
git clone https://github.com/genc-murat/portscanner.git
cd portscanner

# Create a feature branch
git checkout -b feature/awesome-feature

# Make your changes and test
cargo test
cargo build

# Test all functionality
cargo run -- -t 127.0.0.1 --protocol both --ssl-analysis -p 22,53,80,123,443

# Commit and push
git commit -m "Add awesome feature"
git push origin feature/awesome-feature
```

### Code Style

- Follow Rust conventions and use `cargo fmt`
- Add tests for new features
- Update documentation as needed
- Ensure `cargo clippy` passes without warnings
- Test TCP, UDP, and SSL functionality when making changes

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. Always ensure you have permission to scan the target systems. The developers are not responsible for any misuse of this software.

## Acknowledgments

- Inspired by the original [Nmap](https://nmap.org/) project
- Built with the amazing [Tokio](https://tokio.rs/) async runtime
- CLI powered by [Clap](https://clap.rs/)

---

⭐ If you find this project useful, please consider giving it a star on GitHub!