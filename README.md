# Port Scanner

A fast, modern port scanner written in Rust with async networking, IPv4/IPv6 dual-stack support, TCP/UDP scanning, stealth SYN scan, SSL/TLS analysis, advanced service detection, and OS fingerprinting capabilities. Inspired by Nmap but built for speed and simplicity.

## Features

- **IPv4/IPv6 Dual Stack**: Complete support for both IPv4 and IPv6 protocols
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
- **Multiple Target Support**: Scan IPv4/IPv6 addresses or hostnames
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

# Run a basic TCP scan (IPv4)
./target/release/portscanner -t google.com -p 80,443

# Run a basic TCP scan (IPv6)
./target/release/portscanner -t 2001:4860:4860::8888 -p 80,443

# Run a UDP scan (IPv4)
./target/release/portscanner -t 8.8.8.8 --protocol udp -p 53,123

# Run a UDP scan (IPv6)
./target/release/portscanner -t 2001:4860:4860::8888 --protocol udp -p 53,123

# Run both TCP and UDP scan (IPv6)
./target/release/portscanner -t 2001:db8::1 --protocol both -p 1-1000

# Run SSL/TLS analysis (IPv6)
./target/release/portscanner -t 2606:4700::6810:85e5 -p 443 --ssl-analysis

# Run with service detection (IPv6)
./target/release/portscanner -t ::1 -p 1-1000 --service-detection

# Run stealth SYN scan (requires root, IPv6)
sudo ./target/release/portscanner -t 2001:db8::1 -s

# Run aggressive scan (everything enabled, IPv6)
./target/release/portscanner -t 2001:db8::1 --protocol both -A
```

### Basic Usage

```bash
# Scan common TCP ports on IPv4 target
portscanner -t 192.168.1.1

# Scan common TCP ports on IPv6 target
portscanner -t 2001:db8::1

# Scan IPv6 localhost
portscanner -t ::1

# Scan UDP ports (IPv6)
portscanner -t 2001:4860:4860::8888 --protocol udp

# Scan both TCP and UDP (IPv6)
portscanner -t 2001:db8::1 --protocol both

# Scan specific ports with banner grabbing (IPv6)
portscanner -t 2606:4700::6810:85e5 -p 22,80,443 -b

# SSL/TLS security assessment (IPv6)
portscanner -t 2606:4700::6810:85e5 -p 443,993,995 --ssl-analysis

# Scan port range with high concurrency (IPv6)
portscanner -t 2001:db8::1 -p 1-1000 -c 200

# Export results to JSON (IPv6)
portscanner -t 2606:4700::6810:85e5 --protocol both --ssl-analysis -p 80,443,53,123 -j > results.json
```

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

# IPv6 addresses in brackets (for clarity)
portscanner -t [2001:db8::1]

# Dual-stack scanning (both IPv4 and IPv6)
portscanner -t example.com  # Will resolve to both IPv4 and IPv6
```

### IPv6 Stealth Scanning

IPv6 stealth SYN scanning requires root privileges and uses IPv6 raw sockets:

```bash
# IPv6 stealth SYN scan
sudo ./target/release/portscanner -t 2001:db8::1 -p 22,80,443 --stealth

# IPv6 stealth scan with service detection
sudo ./target/release/portscanner -t 2001:db8::1 -p 1-1000 --stealth --service-detection

# IPv6 aggressive stealth scan
sudo ./target/release/portscanner -t 2001:db8::1 --stealth -A
```

### IPv6 Network Discovery Examples

```bash
# Scan IPv6 link-local network
portscanner -t fe80::1 -p 22,80,443

# Scan IPv6 unique local address (ULA)
portscanner -t fd00::1 -p 1-100

# Scan IPv6 global unicast
portscanner -t 2001:db8::1 --protocol both -p 1-1000

# IPv6 DNS servers
portscanner -t 2001:4860:4860::8888 --protocol udp -p 53 --service-detection
portscanner -t 2001:4860:4860::8844 --protocol udp -p 53 --service-detection

# IPv6 NTP servers
portscanner -t 2610:20:6f15:15::27 --protocol udp -p 123 --service-detection
```

## Usage

```
Port Scanner v0.4.0

USAGE:
    portscanner [OPTIONS] --target <TARGET>

OPTIONS:
    -t, --target <TARGET>           Target IPv4/IPv6 address or hostname
    -p, --ports <PORTS>             Ports to scan (e.g., 80,443,22-25) [default: 1-1000]
        --protocol <PROTOCOL>       Protocol to scan: tcp, udp, or both [default: tcp]
    -c, --concurrency <CONCURRENCY> Number of concurrent connections [default: 100]
    -T, --timeout <TIMEOUT>         Connection timeout in milliseconds [default: 3000]
    -b, --banner                    Enable banner grabbing (TCP only)
    -s, --stealth                   Use stealth SYN scan for TCP (requires root, supports IPv6)
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

### IPv4 and IPv6 Basic Scanning

```bash
# IPv4 scanning
portscanner -t 192.168.1.1
portscanner -t google.com -p 80,443,22
portscanner -t 8.8.8.8 --protocol udp -p 53

# IPv6 scanning
portscanner -t 2001:db8::1
portscanner -t 2606:4700::6810:85e5 -p 80,443,22
portscanner -t 2001:4860:4860::8888 --protocol udp -p 53

# Mixed IPv4/IPv6 hostname resolution
portscanner -t google.com --protocol both -p 80,443,53

# IPv6 link-local scanning
portscanner -t fe80::1%eth0 -p 22,80,443

# IPv6 localhost scanning
portscanner -t ::1 -p 1-1000
```

### IPv6 SSL/TLS Security Assessment

```bash
# Basic IPv6 SSL analysis
portscanner -t 2606:4700::6810:85e5 -p 443 --ssl-analysis

# Multiple IPv6 SSL ports analysis
portscanner -t 2001:db8::1 -p 443,993,995,465 --ssl-analysis

# Comprehensive IPv6 SSL security audit
portscanner -t 2606:4700::6810:85e5 -p 443,8443,9443 --ssl-analysis --service-detection

# IPv6 SSL analysis with JSON output
portscanner -t 2606:4700::6810:85e5 -p 443 --ssl-analysis -j > ssl_report_ipv6.json

# Enterprise IPv6 SSL assessment
portscanner -t 2001:db8:corp::1 -p 443,993,995,465,587,636,853,990 --ssl-analysis -A
```

### IPv6 UDP Scanning

```bash
# IPv6 common UDP ports scan
portscanner -t 2001:db8::1 --udp-common

# IPv6 specific UDP services
portscanner -t 2001:4860:4860::8888 --protocol udp -p 53 --service-detection

# IPv6 UDP with custom timeout
portscanner -t 2001:db8::1 --protocol udp -p 1-500 -T 5000

# IPv6 top UDP ports
portscanner -t 2606:4700::6810:85e5 --protocol udp --top-ports 20
```

### IPv6 Advanced Scanning

```bash
# High-speed IPv6 TCP scanning
portscanner -t 2001:db8::1 -p 1-65535 -c 500

# IPv6 banner grabbing for service identification
portscanner -t 2001:db8::1 -p 21,22,80,443 -b

# IPv6 custom timeout for slow networks
portscanner -t 2001:db8:slow::1 -p 1-1000 -T 5000

# IPv6 JSON output for automation
portscanner -t 2606:4700::6810:85e5 --protocol both --ssl-analysis -p 80,443,53,123 -j | jq '.[] | select(.is_open)'

# IPv6 mixed protocol scanning with SSL analysis
portscanner -t 2001:db8::1 --protocol both --ssl-analysis --service-detection --top-ports 100
```

### Real-world IPv6 Examples

```bash
# IPv6 web server security assessment
portscanner -t 2606:4700::6810:85e5 --protocol both --ssl-analysis -p 80,443,53,8080,8443

# IPv6 mail server security audit
portscanner -t 2001:db8:mail::1 --ssl-analysis -p 25,465,587,993,995,143,110 -A

# IPv6 database server discovery
portscanner -t 2001:db8:db::1 -p 3306,5432,1433,27017,6379 -b

# IPv6 network infrastructure scan
portscanner -t 2001:db8:gw::1 --protocol both -p 21,22,23,53,67,80,161,443,514,1900

# IPv6 complete security assessment
portscanner -t 2001:db8:target::1 --protocol both --ssl-analysis -A --top-ports 200

# IPv6 DNS over TLS analysis
portscanner -t 2606:4700:4700::1111 --protocol both --ssl-analysis -p 53,853

# IPv6 development environment scan
portscanner -t ::1 --protocol both --ssl-analysis -p 3000,4000,5000,8000,8080,9000
```

## Sample Output

### IPv6 Standard Output (Comprehensive Scan with SSL Analysis)
```
Port Scanner v0.4.0
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

🔗    80/tcp open http Cloudflare            ( 156ms)
        Banner: Server: cloudflare
        CPE: cpe:/a:cloudflare:cloudflare

🔗   443/tcp open https Cloudflare           ( 198ms)
        Banner: Server: cloudflare
        CPE: cpe:/a:cloudflare:cloudflare

🔗  2053/tcp open dns Cloudflare DNS        ( 234ms)
        Banner: Cloudflare DNS over HTTPS

UDP Ports
----------------------------------------
1 open UDP ports found:

📡    53/udp open DNS Server                ( 145ms)
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

### IPv6 JSON Output
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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. Always ensure you have permission to scan the target systems. The developers are not responsible for any misuse of this software.

## Acknowledgments

- Inspired by the original [Nmap](https://nmap.org/) project
- Built with the amazing [Tokio](https://tokio.rs/) async runtime
- CLI powered by [Clap](https://clap.rs/)
- IPv6 support follows RFC 4291 and related standards

---

⭐ If you find this project useful, please consider giving it a star on GitHub!

## IPv6 Resources

- [RFC 4291 - IPv6 Addressing Architecture](https://tools.ietf.org/html/rfc4291)
- [RFC 4861 - Neighbor Discovery for IPv6](https://tools.ietf.org/html/rfc4861)
- [RFC 8200 - IPv6 Specification](https://tools.ietf.org/html/rfc8200)
- [IPv6 Address Planning](https://www.ripe.net/publications/docs/ripe-690)