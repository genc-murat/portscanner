# Port Scanner

A fast, modern port scanner written in Rust with async networking, IPv4/IPv6 dual-stack support, TCP/UDP scanning, stealth SYN scan, SSL/TLS analysis, advanced service detection, OS fingerprinting, and HTML reporting capabilities. Inspired by Nmap but built for speed and simplicity.

## Features

  - **IPv4/IPv6 Dual Stack**: Complete support for both IPv4 and IPv6 protocols.
  - **Fast Async Scanning**: Built with Tokio for high-performance concurrent scanning.
  - **TCP & UDP Support**: Comprehensive scanning for both TCP and UDP protocols.
  - **Stealth SYN Scan**: Raw socket SYN scanning for speed and stealth (Linux/Unix).
  - **SSL/TLS Analysis**: Complete SSL/TLS security assessment with vulnerability detection.
  - **UDP Service Detection**: Protocol-specific probes for common UDP services.
  - **Banner Grabbing**: Extract service banners and version information (TCP).
  - **Advanced Service Detection**: Nmap-style service identification with 150+ signatures.
  - **OS Fingerprinting**: Operating system detection via TCP/IP stack analysis.
  - **Certificate Analysis**: SSL certificate validation and security assessment.
  - **Vulnerability Detection**: SSL/TLS vulnerability scanning (e.g., POODLE, BEAST).
  - **Multiple Target Support**: Scan IPv4/IPv6 addresses or hostnames.
  - **Colored Output**: Beautiful terminal output with syntax highlighting.
  - **JSON Export**: Export results in JSON format for further analysis.
  - **HTML Export**: Generate a professional, self-contained HTML report for easy viewing.
  - **Configurable**: Customize concurrency, timeouts, and port ranges.
  - **Safe**: Built-in rate limiting and timeout controls.
  - **Auto Mode**: Intelligent scan type selection based on privileges.

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/genc-murat/portscanner.git
cd portscanner

# Build the project
cargo build --release

# Run a basic TCP scan (IPv4)
./target/release/portscanner -t google.com -p 80,443

# Run a basic TCP scan (IPv6)
./target/release/portscanner -t 2001:4860:4860::8888 -p 80,443

# Generate an HTML report (IPv4)
./target/release/portscanner -t scanme.nmap.org -A --html report.html

# Generate an HTML report (IPv6)
./target/release/portscanner -t 2606:4700::6810:85e5 -A --html ipv6_report.html
```

### Basic Usage

```bash
# Scan common TCP ports on an IPv6 target
portscanner -t 2001:db8::1

# Scan both TCP and UDP (IPv6)
portscanner -t 2001:db8::1 --protocol both

# SSL/TLS security assessment (IPv6)
portscanner -t 2606:4700::6810:85e5 -p 443,993,995 --ssl-analysis

# Export results to JSON (IPv6)
portscanner -t 2606:4700::6810:85e5 -p 80,443 -j > results.json

# Export aggressive scan results to an HTML file (IPv6)
portscanner -t 2001:db8::1 -A --html detailed_report.html
```

-----

## IPv6 Support

### IPv6 Address Formats

The scanner supports all standard IPv6 address formats:

```bash
# Full IPv6 address
portscanner -t 2001:0db8:85a3:0000:0000:8a2e:0370:7334

# Compressed IPv6 address
portscanner -t 2001:db8:85a3::8a2e:370:7334

# IPv6 localhost
portscanner -t ::1

# IPv6 with zone identifier (link-local)
portscanner -t fe80::1%eth0

# Dual-stack scanning (both IPv4 and IPv6)
portscanner -t example.com # Will resolve to both IPv4 and IPv6
```

### IPv6 Stealth Scanning

```bash
# IPv6 aggressive stealth scan with HTML output
sudo ./target/release/portscanner -t 2001:db8::1 --stealth -A --html stealth_report.html
```

-----

## Usage

```
Port Scanner v0.5.0

USAGE:
    portscanner [OPTIONS] --target <TARGET>

OPTIONS:
    -t, --target <TARGET>          Target IPv4/IPv6 address or hostname
    -p, --ports <PORTS>            Ports to scan (e.g., 80,443,22-25) [default: 1-1000]
        --protocol <PROTOCOL>      Protocol to scan: tcp, udp, or both [default: tcp]
    -c, --concurrency <NUM>        Number of concurrent connections [default: 100]
    -T, --timeout <MS>             Connection timeout in milliseconds [default: 3000]
    -b, --banner                   Enable banner grabbing (TCP only)
    -s, --stealth                  Use stealth SYN scan for TCP (requires root, supports IPv6)
    -j, --json                     Output results in JSON format
        --html <FILENAME>          Output results in an HTML file
        --scan-type <TYPE>         Scan type: tcp, syn, udp, or auto [default: auto]
        --service-detection        Enable advanced service detection
        --ssl-analysis             Enable SSL/TLS analysis for HTTPS and other SSL services
    -O, --os-detection             Enable OS fingerprinting (TCP only)
    -A, --aggressive               Aggressive mode (service detection + banner + OS detection + SSL analysis)
    -U, --udp-common               Scan common UDP ports
        --top-ports <NUM>          Scan top N most common ports for the selected protocol(s)
    -h, --help                     Print help information
    -V, --version                  Print version information
```

-----

## Sample Output

### IPv6 Standard Output (Comprehensive Scan with SSL Analysis)

```
Port Scanner v0.5.0
Target: 2606:4700::6810:85e5
Protocol(s): TCP, UDP
Aggressive mode enabled (service detection + banner grabbing + OS detection + SSL analysis)
Advanced service detection enabled
OS fingerprinting enabled
SSL/TLS analysis enabled

Starting scan: 2606:4700::6810:85e5 (8 ports)
Scan method: Mixed TCP/UDP Scan
IPv6 address detected: 2606:4700::6810:85e5 (Cloudflare)
 Performing SSL/TLS analysis on 2 ports
 Performing OS detection for 2606:4700::6810:85e5

================================================================================
Port Scan Results - 2606:4700::6810:85e5 (IPv6)
================================================================================

TCP Ports
----------------------------------------
3 open TCP ports found:

🔗     80/tcp open http Cloudflare                ( 156ms)
         Banner: Server: cloudflare
         CPE: cpe:/a:cloudflare:cloudflare

🔗   443/tcp open https Cloudflare               ( 198ms)
         Banner: Server: cloudflare
         CPE: cpe:/a:cloudflare:cloudflare

🔗  2053/tcp open dns Cloudflare DNS             ( 234ms)
         Banner: Cloudflare DNS over HTTPS

UDP Ports
----------------------------------------
1 open UDP ports found:

📡    53/udp open DNS Server                     ( 145ms)
         Response: DNS Server (Cloudflare)

SSL/TLS Analysis for 2606:4700::6810:85e5:443
============================================================
🟢 Security Score: 95/100 (Excellent)

Certificate Information
------------------------------
Subject: CN=*.example.com
Issuer: CN=Cloudflare Inc ECC CA-3, O=Cloudflare, Inc., C=US
🟢 Valid until: 2025-06-15T23:59:59Z (267 days)
🟢 Public Key: ECDSA P-256
🟢 Signature: SHA256-ECDSA
🔗 Alt Names: *.example.com, example.com
🔸 Wildcard certificate

Supported Protocols
------------------------------
🟢 TLS 1.2
🟢 TLS 1.3

Cipher Suites
------------------------------
🟢  TLS_AES_256_GCM_SHA384 (TLS 1.3)
🟢  TLS_AES_128_GCM_SHA256 (TLS 1.3)
🟢  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (TLS 1.2)
🟢  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)

Recommendations
------------------------------
• 🟢 SSL/TLS configuration is excellent
• 🟢 Strong elliptic curve cryptography in use
•  HTTP Strict Transport Security (HSTS) detected

Analysis completed in 1.87s
============================================================

OS Detection Results
----------------------------------------
🖥️  Operating System: Linux (82% confidence)
    Details:
      • TTL: 64
      • Window Size: 29200
      • IPv6 Flow Label: 0x00000
      • TCP Timestamps: Enabled
      • Window Scaling: Enabled
      • SACK: Enabled
      • IPv6 Extension Headers: None

Scan Summary
----------------------------------------
Total ports scanned: 8
Open ports: 4
Open|Filtered ports: 0
Closed ports: 3
Filtered ports: 1
SSL/TLS services found: 1
Scan time: 2.45s
Scan method: Mixed TCP/UDP Scan
Protocols: TCP, UDP
Protocol Version: IPv6
Average response time: 0.183s
Services identified with high confidence: TCP 3/3, UDP 1/1
OS detection: Success (High confidence)
SSL/TLS analysis: 1 services analyzed

================================================================================
```

### HTML Report Output

When using the `--html` flag, the scanner generates a single, self-contained HTML file. This report is designed for clarity and includes:

  - **Scan Summary**: An overview of the target, number of ports scanned, and total scan time.
  - **OS Detection**: If enabled, shows the detected operating system with confidence levels.
  - **Port Tables**: Separate, sortable tables for open TCP and UDP ports, detailing the service, banner, and response time.
  - **SSL/TLS Analysis**: In-depth cards for each SSL-enabled port, showing certificate details, protocol support, vulnerabilities, and a final security score.
  - **Responsive Design**: The report is readable on both desktop and mobile devices.

 \#\#\# IPv6 JSON Output

```json
{
  "target": "2606:4700::6810:85e5",
  "target_type": "IPv6",
  "scan_results": [
    {
      "port": 80,
      "is_open": true,
      "service": "http",
      "service_info": {
        "name": "http",
        "product": "Cloudflare",
        "confidence": 95,
        "cpe": "cpe:/a:cloudflare:cloudflare"
      },
      "banner": "Server: cloudflare",
      "response_time": 156,
      "scan_type": "TCP",
      "protocol": "TCP",
      "ip_version": "IPv6"
    },
    {
      "port": 443,
      "is_open": true,
      "service": "https",
      "service_info": {
        "name": "https",
        "product": "Cloudflare",
        "confidence": 95
      },
      "response_time": 198,
      "scan_type": "TCP",
      "protocol": "TCP",
      "ip_version": "IPv6"
    }
  ],
  "ssl_analysis": [
    {
      "target": "2606:4700::6810:85e5",
      "port": 443,
      "ip_version": "IPv6",
      "is_ssl_enabled": true,
      "certificate_info": {
        "subject": "CN=*.example.com",
        "issuer": "CN=Cloudflare Inc ECC CA-3",
        "days_until_expiry": 267,
        "public_key_algorithm": "ECDSA",
        "public_key_size": 256,
        "signature_algorithm": "SHA256-ECDSA"
      },
      "security_score": 95,
      "scan_time": 1.87
    }
  ],
  "scan_summary": {
    "target_ip_version": "IPv6",
    "total_ports": 8,
    "open_ports": 4,
    "ssl_services_found": 1,
    "scan_time": 2.45
  }
}
```

-----

## IPv6 Configuration Tips

### Performance Tuning for IPv6

```bash
# For local IPv6 networks (fast)
portscanner -t 2001:db8::1 -p 1-1000 -c 300 -T 1000

# For internet IPv6 hosts (moderate)
portscanner -t 2606:4700::6810:85e5 --protocol both --ssl-analysis -p 1-1000 -c 100 -T 3000

# For slow/filtered IPv6 networks (conservative)
portscanner -t 2001:db8:remote::1 --protocol both --ssl-analysis -p 80,443,53,123 -c 50 -T 10000
```

### IPv6 Best Practices

  - **Link-Local Addresses**: Specify interface with `%interface` (e.g., `fe80::1%eth0`)
  - **Zone Identifiers**: Required for link-local addresses on multi-interface systems
  - **Timeouts**: IPv6 may require longer timeouts due to routing complexity
  - **Stealth Scanning**: Requires root privileges, same as IPv4
  - **SSL Analysis**: Works identically on IPv6 as IPv4

-----

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

# Unix-specific dependencies for raw socket support (IPv4 and IPv6)
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

# Run tests (includes IPv6 tests)
cargo test

# Test IPv4 functionality
cargo run -- -t google.com -p 80,443

# Test IPv6 functionality
cargo run -- -t 2001:4860:4860::8888 -p 53

# Test dual-stack
cargo run -- -t example.com --protocol both -p 80,443,53
```

-----

## Supported Detection

### **IPv4/IPv6 Protocol Support**

  - **Full IPv6 Support**: All features work with IPv6 addresses
  - **Dual-Stack**: Automatic protocol detection and handling
  - **Address Formats**: All standard IPv6 notation formats supported
  - **Zone Identifiers**: Link-local address support with interface specification
  - **Raw Sockets**: IPv6 stealth SYN scanning on Linux/Unix systems

### **TCP Service Detection (150+ signatures, IPv4/IPv6)**

  - **Web Services**: Apache, nginx, IIS, lighttpd, Node.js, Django
  - **Remote Access**: OpenSSH, Dropbear, Telnet, RDP, VNC
  - **Mail Services**: Postfix, Sendmail, Exchange, Dovecot, Courier
  - **Databases**: MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle
  - **File Services**: vsftpd, ProFTPD, Samba, NFS, TFTP
  - **Network Services**: BIND DNS, DHCP, SNMP, NTP

### **UDP Service Detection (IPv4/IPv6)**

  - **DNS (53)**: BIND, dnsmasq, PowerDNS with version detection
  - **NTP (123)**: Network time servers with version identification
  - **SNMP (161/162)**: Network management protocols
  - **DHCP (67/68)**: Dynamic host configuration (DHCPv6: 546/547)
  - **TFTP (69)**: Trivial file transfer protocol
  - **NetBIOS (137/138)**: Windows networking services
  - **mDNS (5353)**: Multicast DNS/Bonjour services
  - **UPnP SSDP (1900)**: Universal Plug and Play discovery
  - **SIP (5060)**: VoIP signaling protocol
  - **Syslog (514)**: System logging services

### **SSL/TLS Service Detection (IPv4/IPv6)**

  - **HTTPS (443, 8443, 9443)**: Web servers with SSL/TLS
  - **SMTPS (465)**: SMTP over SSL
  - **SMTP+TLS (587)**: SMTP with STARTTLS
  - **IMAPS (993)**: IMAP over SSL
  - **POP3S (995)**: POP3 over SSL
  - **LDAPS (636)**: LDAP over SSL
  - **DNS-over-TLS (853)**: Secure DNS (especially important for IPv6)
  - **FTPS (990)**: FTP over SSL
  - **WinRM HTTPS (5986)**: Windows Remote Management over HTTPS

### **OS Fingerprinting (TCP-based, IPv4/IPv6)**

  - **Linux**: Ubuntu, CentOS, RHEL, Debian, Alpine, Android
  - **Windows**: 7, 8, 10, 11, Server 2016/2019/2022
  - **Unix**: FreeBSD, OpenBSD, NetBSD, Solaris
  - **Apple**: macOS 10.x, 11.x, 12.x+
  - **Network Devices**: Cisco IOS, Juniper JunOS
  - **Embedded**: IoT devices, routers, switches
  - **IPv6 Enhancements**: IPv6-specific TCP/IP stack fingerprinting

-----

## IPv6-Specific Features

### IPv6 Address Resolution

  - **AAAA Record Lookup**: Automatic IPv6 DNS resolution
  - **Dual-Stack Resolution**: Resolves both A and AAAA records
  - **Address Validation**: Comprehensive IPv6 address format checking
  - **Address Normalization**: Converts various IPv6 formats to standard form

### IPv6 Network Support

  - **Global Unicast**: Internet-routable IPv6 addresses (2000::/3)
  - **Link-Local**: fe80::/10 addresses with zone identifier support
  - **Unique Local**: fd00::/8 private IPv6 addresses
  - **Multicast**: ff00::/8 multicast address support
  - **Loopback**: ::1 localhost support

### IPv6 Stealth Features

  - **Raw Socket Support**: Full IPv6 raw socket implementation
  - **ICMPv6 Handling**: Proper IPv6 error message processing
  - **Flow Labels**: IPv6 flow label support in packets
  - **Extension Headers**: IPv6 extension header parsing
  - **Neighbor Discovery**: IPv6 ND protocol awareness

-----

## Contributing

Contributions are welcome\! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
# Fork and clone the repo
git clone https://github.com/genc-murat/portscanner.git
cd portscanner

# Create a feature branch
git checkout -b feature/ipv6-enhancement

# Make your changes and test
cargo test
cargo build

# Test IPv4 functionality
cargo run -- -t 127.0.0.1 --protocol both --ssl-analysis -p 22,53,80,123,443

# Test IPv6 functionality
cargo run -- -t ::1 --protocol both --ssl-analysis -p 22,53,80,123,443

# Test dual-stack
cargo run -- -t localhost --protocol both -p 80,443

# Commit and push
git commit -m "Add IPv6 enhancement"
git push origin feature/ipv6-enhancement
```

### Code Style

  - Follow Rust conventions and use `cargo fmt`
  - Add tests for new features (include IPv6 test cases)
  - Update documentation as needed
  - Ensure `cargo clippy` passes without warnings
  - Test both IPv4 and IPv6 functionality when making changes
  - Validate IPv6 address handling and edge cases

-----

## License

This project is licensed under the MIT License - see the **LICENSE** file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. Always ensure you have permission to scan the target systems. The developers are not responsible for any misuse of this software.

## Acknowledgments

  - Inspired by the original [Nmap](https://nmap.org/) project
  - Built with the amazing [Tokio](https://tokio.rs/) async runtime
  - CLI powered by [Clap](https://clap.rs/)
  - IPv6 support follows RFC 4291 and related standards

-----

⭐ If you find this project useful, please consider giving it a star on GitHub\!

## IPv6 Resources

  - [RFC 4291 - IPv6 Addressing Architecture](https://tools.ietf.org/html/rfc4291)
  - [RFC 4861 - Neighbor Discovery for IPv6](https://tools.ietf.org/html/rfc4861)
  - [RFC 8200 - IPv6 Specification](https://tools.ietf.org/html/rfc8200)
  - [IPv6 Address Planning](https://www.ripe.net/publications/docs/ripe-690)