# Port Scanner

A fast, modern port scanner written in Rust with async networking, IPv4/IPv6 dual-stack support, TCP/UDP scanning, stealth SYN scan, SSL/TLS analysis, advanced service detection, OS fingerprinting, interactive mode, and beautiful HTML reporting capabilities. Inspired by Nmap but built for speed, simplicity, and user experience.

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

### User Experience
- **🎮 Interactive Mode**: Guided setup with menu-driven configuration
- **🌈 Beautiful UI**: Colored terminal output with progress bars and animations
- **📊 Real-time Progress**: Live progress tracking with ETA and speed metrics
- **🎯 Smart Recommendations**: Context-aware security suggestions
- **🔍 Quick Scan Mode**: Instant scanning with optimized settings

### Output & Reporting
- **📄 HTML Reports**: Professional, responsive HTML reports with charts
- **📋 JSON Export**: Structured data export for automation and integration
- **🎨 Rich Terminal Output**: Syntax highlighting and visual indicators
- **📈 Performance Metrics**: Detailed scan statistics and timing information
- **🔒 Security Assessment**: Automated risk analysis and recommendations

### Configuration & Flexibility
- **Multiple Target Support**: Scan IPv4/IPv6 addresses or hostnames
- **Configurable**: Customize concurrency, timeouts, and port ranges
- **Safe**: Built-in rate limiting and timeout controls
- **Auto Mode**: Intelligent scan type selection based on privileges
- **Preset Configurations**: Quick setup for common scenarios

## 🎮 Interactive Mode

Launch the interactive mode for guided scanning:

```bash
# Start interactive mode
./target/release/portscanner --interactive

# Or use the short flag
./target/release/portscanner -i
```

The interactive mode provides:
- **Step-by-step configuration** with clear prompts
- **Performance level selection** (Conservative, Balanced, Aggressive, Maximum)
- **Feature selection** with multi-select menus
- **Output format choice** (Console, JSON, HTML)
- **Configuration summary** before starting
- **Built-in help** and explanations

### Interactive Mode Screenshot

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
📊 Output format: HTML report

📋 Scan Configuration Summary:
   Target: scanme.nmap.org
   Ports: 1-1000
   Protocol: both
   Concurrency: 100
   Features: Service Detection, OS Fingerprinting, SSL Analysis, Banner Grabbing

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

# Or run a basic TCP scan (IPv4)
./target/release/portscanner -t google.com -p 80,443

# Run a basic TCP scan (IPv6)
./target/release/portscanner -t 2001:4860:4860::8888 -p 80,443

# Generate an HTML report (IPv4)
./target/release/portscanner -t scanme.nmap.org -A --html report.html

# Generate an HTML report (IPv6)
./target/release/portscanner -t 2606:4700::6810:85e5 -A --html ipv6_report.html
```

### Quick Commands

```bash
# Interactive mode (recommended for beginners)
portscanner --interactive

# Quick scan with progress bar
portscanner -t example.com --quick

# Aggressive scan with all features
portscanner -t example.com --aggressive

# Stealth scan (requires root)
sudo portscanner -t example.com --stealth

# UDP common ports
portscanner -t example.com --udp-common

# SSL/TLS security assessment
portscanner -t example.com --ssl-analysis --html ssl_report.html
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

## 🎨 Enhanced User Interface

### Visual Features

- **🎭 ASCII Art Banner**: Eye-catching startup banner
- **🌈 Color-coded Output**: Different colors for ports, services, and states
- **📊 Progress Bars**: Real-time scanning progress with ETA
- **⚡ Performance Metrics**: Live speed and statistics
- **🎯 Smart Highlighting**: Important findings highlighted
- **🔍 Search Tips**: Contextual help and suggestions

### Progress Tracking

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

🔍 Scanning example.com [████████████████████████████████████████████████████] 100% (1000/1000)
  🌐 TCP  [████████████████████████████████████████████████████] 1000/1000 scanning...
  🔐 SSL  [████████████████████████████████████████████████████] 3/3 analyzing...
  🖥️ OS   [████████████████████████████████████████████████████] 100% fingerprinting...
```

### Enhanced Results Display

```
╔═══════════════════════════════════════════════════════════════╗
║                     🌐 TCP SCAN RESULTS                      ║
╚═══════════════════════════════════════════════════════════════╝

🎯 5 open TCP ports discovered:

─────────────────────────────────────────────────────────────────────────────
PORT     STATE        SERVICE                   VERSION         RESPONSE
─────────────────────────────────────────────────────────────────────────────
⚡ 22/tcp  open         ssh                      OpenSSH 8.2     45ms
         └─ Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
         └─ CPE: cpe:/a:openbsd:openssh:8.2p1

🔗 80/tcp  open         http                     Apache 2.4.41   89ms
         └─ Banner: Server: Apache/2.4.41 (Ubuntu)
         └─ Confidence: 95%

🔗 443/tcp open         https                    Apache 2.4.41   112ms
         └─ Banner: Server: Apache/2.4.41 (Ubuntu)
─────────────────────────────────────────────────────────────────────────────

🎯 Security Assessment:
   Overall Security Score: 78/100 (Good)
   🟡 1 potential security concern detected
   💡 Consider disabling unnecessary services
```

## 📊 Usage

```
🚀 Advanced Port Scanner with Modern Features

USAGE:
    portscanner [OPTIONS] --target <TARGET>

ARGUMENTS:
    -t, --target <IP/HOSTNAME>     🎯 Target IP address or hostname

OPTIONS:
    -p, --ports <PORT_RANGE>       📡 Ports to scan (supports ranges and lists) [default: 1-1000]
        --protocol <PROTOCOL>      🔌 Protocol to scan [default: tcp] [possible values: tcp, udp, both]
    -c, --concurrency <THREADS>    ⚡ Number of concurrent connections [default: 100]
    -T, --timeout <MILLISECONDS>   ⏱️ Connection timeout [default: 3000]
    -i, --interactive              🎮 Interactive mode with guided setup
    -q, --quick                    ⚡ Quick scan mode (top 100 ports)
    -v, --verbose                  📝 Verbose output with detailed information

SCANNING MODES:
    -b, --banner                   🏷️ Enable banner grabbing
    -s, --stealth                  👤 Use stealth SYN scan (requires root)
        --scan-type <TYPE>         🔍 Scan technique [default: auto] [possible values: tcp, syn, udp, auto]
        --service-detection        🔧 Enable advanced service detection
        --ssl-analysis             🔐 Enable SSL/TLS analysis
    -O, --os-detection             🖥️ Enable OS fingerprinting
    -A, --aggressive               🚀 Enable all detection methods
    -U, --udp-common               📡 Scan common UDP ports
        --top-ports <NUMBER>       🎯 Scan top N most common ports

OUTPUT OPTIONS:
    -j, --json                     📋 Output in JSON format
        --html <FILENAME>          📊 Generate HTML report
        --ipv6-only                🌐 Force IPv6 resolution
        --ipv4-only                🌍 Force IPv4 resolution

EXAMPLES:
    portscanner --interactive                           # Interactive mode
    portscanner -t example.com --quick                 # Quick scan
    portscanner -t example.com --aggressive            # Full analysis
    portscanner -t example.com --html report.html      # HTML report
    portscanner -t 2001:db8::1 --protocol both         # IPv6 scan
    sudo portscanner -t example.com --stealth          # Stealth scan
```

## 🎯 Sample Output

### Enhanced Terminal Output

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║    ██████╗  ██████╗ ██████╗ ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗      ║
║    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║      ║
║    ██████╔╝██║   ██║██████╔╝   ██║   ███████╗██║     ███████║██╔██╗ ██║      ║
║    ██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║      ║
║    ██║     ╚██████╔╝██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║      ║
║    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝      ║
║                                                                               ║
║                🚀 Advanced Port Scanner with Modern Features 🚀               ║
║                           Version 0.4.0 - Rust Edition                       ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

✨ Features Overview:
   🔍 TCP & UDP Scanning with high-speed concurrent connections
   👤 Stealth SYN scan for covert network reconnaissance
   🔧 Advanced service detection with 150+ signatures
   🖥️ OS fingerprinting using TCP/IP stack analysis
   🔐 SSL/TLS security analysis and vulnerability assessment
   🌐 Full IPv6 support for modern networks
   📊 Professional HTML reports with interactive charts
   📋 JSON export for integration with other tools

🎯 Quick Start Examples:
   • Basic scan:     portscanner -t example.com
   • Stealth scan:   portscanner -t 192.168.1.1 --stealth
   • Full analysis:  portscanner -t target.com --aggressive
   • Interactive:    portscanner --interactive

💡 Pro Tips:
   • Use --concurrency 200 for faster results
   • Add --aggressive for detailed analysis
   • Try --html report.html for professional reports

════════════════════════════════════════════════════════════════════════════════

🔍 Validating target: example.com
   🌐 Resolving hostname... ✅ Resolved to 93.184.216.34

🚀 Initializing scan engines⚡ Loading...
🚀 Scan engines ready! ✅

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

🔍 Scanning example.com [████████████████████████████████████████████████████] 100% (1000/1000)
  🌐 TCP  [████████████████████████████████████████████████████] 1000/1000 3 open ports found
  🔐 SSL  [████████████████████████████████████████████████████] 1/1 1 services analyzed
  🖥️ OS   [████████████████████████████████████████████████████] 100% 85% confidence

╔═══════════════════════════════════════════════════════════════╗
║                SCAN RESULTS FOR example.com                  ║
╚═══════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────┐
│                     🌐 TCP SCAN RESULTS                      │
└─────────────────────────────────────────────────────────────┘

🎯 3 open TCP ports discovered:

─────────────────────────────────────────────────────────────────────────────
PORT     STATE        SERVICE                   VERSION         RESPONSE
─────────────────────────────────────────────────────────────────────────────
⚡ 22/tcp  open         ssh                      OpenSSH 8.2     45ms
         └─ Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
         └─ CPE: cpe:/a:openbsd:openssh:8.2p1

🔗 80/tcp  open         http                     Apache 2.4.41   89ms
         └─ Banner: Server: Apache/2.4.41 (Ubuntu)
         └─ Confidence: 95%

🔗 443/tcp open         https                    Apache 2.4.41   112ms
         └─ Banner: Server: Apache/2.4.41 (Ubuntu)
─────────────────────────────────────────────────────────────────────────────

┌─────────────────────────────────────────────────────────────┐
│                  🖥️ OS DETECTION RESULTS                    │
└─────────────────────────────────────────────────────────────┘

🟢 Operating System: Ubuntu Linux 20.04
   📊 Confidence: 85% (High)
   💻 Device Type: Server
   🏢 Vendor: Canonical Ltd.
   ⚙️ Architecture: x86_64

   🔧 Technical Details:
      • TTL: 64
      • Window Size: 29200
      • TCP Timestamps: Enabled
      • Window Scaling: Enabled
      • SACK: Enabled
      • Closed Port Response: RST

   🏷️ CPE: cpe:/o:canonical:ubuntu_linux:20.04

┌─────────────────────────────────────────────────────────────┐
│                  🔐 SSL/TLS ANALYSIS RESULTS                │
└─────────────────────────────────────────────────────────────┘

🟢 Port 443: Security Score 92/100 (Excellent)
   📜 Certificate: CN=example.com
   🏢 Issuer: DigiCert Inc
   🟢 Expires: 2025-03-15 (89 days)
   🔌 Protocols: TLS 1.2, TLS 1.3
   💡 Recommendations:
      🟢 SSL/TLS configuration is secure
      • Implement HTTP Strict Transport Security (HSTS)
      • Consider certificate transparency monitoring

┌─────────────────────────────────────────────────────────────┐
│                      📊 SCAN SUMMARY                        │
└─────────────────────────────────────────────────────────────┘

📈 Statistics:
   ┌─────────────────────┬─────────────────────┐
   │ Total Ports Scanned │                1000 │
   │ Open Ports          │                   3 │
   │ Closed Ports        │                 997 │
   │ Filtered Ports      │                   0 │
   │ Scan Time           │               2.45s │
   └─────────────────────┴─────────────────────┘

⚡ Performance: 408 ports/second

🛡️ Security Assessment:
   Overall Security Score: 85/100 (Good)
   🟢 No immediate security concerns detected

🔌 Protocol Breakdown:
   TCP: 3 open / 1000 scanned

🔍 Service Identification:
   TCP services identified: 3/3

🔐 SSL/TLS Services: 1 analyzed

💡 Security Recommendations:
   🟢 SSH detected - ensure key-based authentication
   🟢 HTTPS enabled - good security practice
   🟢 No immediate security concerns detected

─────────────────────────────────────────────────────────────────────────────
✅ Scan completed at 2024-01-15 14:30:45 UTC
─────────────────────────────────────────────────────────────────────────────

🎉 SCAN COMPLETED SUCCESSFULLY! 🎉
══════════════════════════════════════════════════════════════

✅ 3 open ports discovered!
⏱️ Scan completed in 2.45 seconds
🚀 Thank you for using PortScanner!
```

### IPv6 Terminal Output

```
🔍 Validating target: 2606:4700::6810:85e5
   ✅ Valid IPv6 address

Target IP version: IPv6
Normalized: 2606:4700::6810:85e5

IPv6 Scanning Notes:
• IPv6 stealth scanning requires root privileges
• All features (SSL, service detection, OS fingerprinting) work with IPv6
• Consider using higher timeouts for IPv6 networks

╔═══════════════════════════════════════════════════════════════╗
║           SCAN RESULTS FOR 2606:4700::6810:85e5 (IPv6)      ║
╚═══════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────┐
│                     🌐 TCP SCAN RESULTS                      │
└─────────────────────────────────────────────────────────────┘

🎯 3 open TCP ports discovered:

─────────────────────────────────────────────────────────────────────────────
PORT     STATE        SERVICE                   VERSION         RESPONSE
─────────────────────────────────────────────────────────────────────────────
🔗 80/tcp  open         http                     Cloudflare      156ms
         └─ Banner: Server: cloudflare
         └─ CPE: cpe:/a:cloudflare:cloudflare

🔗 443/tcp open         https                    Cloudflare      198ms
         └─ Banner: Server: cloudflare
         └─ CPE: cpe:/a:cloudflare:cloudflare

🔗 2053/tcp open        dns                      Cloudflare      234ms
         └─ Banner: Cloudflare DNS over HTTPS
─────────────────────────────────────────────────────────────────────────────

┌─────────────────────────────────────────────────────────────┐
│                     📡 UDP SCAN RESULTS                      │
└─────────────────────────────────────────────────────────────┘

🎯 1 open UDP ports discovered:

─────────────────────────────────────────────────────────────────────────────
PORT     STATE        SERVICE                   RESPONSE        TIME
─────────────────────────────────────────────────────────────────────────────
📡 53/udp  open         DNS Server               Cloudflare      145ms
         └─ Response: DNS Server (Cloudflare)
─────────────────────────────────────────────────────────────────────────────

🛡️ Security Assessment:
   Overall Security Score: 88/100 (Good)
   🟢 IPv6 implementation appears secure
   🟢 Modern services with good security practices
```

## 🔧 Building from Source

### Prerequisites

- Rust 1.70 or later
- Cargo package manager
- For interactive mode: Terminal with Unicode support

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

# Try interactive mode
cargo run -- --interactive

# Test IPv4 functionality
cargo run -- -t google.com -p 80,443

# Test IPv6 functionality
cargo run -- -t 2001:4860:4860::8888 -p 53

# Test dual-stack
cargo run -- -t example.com --protocol both -p 80,443,53
```

## 🎯 IPv6 Support

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

### IPv6 Interactive Mode

```bash
# Interactive mode with IPv6 support
portscanner --interactive

# In interactive mode, you can:
# - Enter IPv6 addresses in any format
# - Choose IPv6-only or dual-stack scanning
# - Configure IPv6-specific timeouts
# - Generate IPv6-aware reports
```

## 🎨 Enhanced HTML Reports

The HTML reports now include:

### Interactive Features
- **📊 Dynamic Charts**: Real-time port distribution graphs
- **🔍 Search & Filter**: Find specific ports or services
- **📱 Mobile Responsive**: Works on all devices
- **🌙 Dark Mode**: Automatic theme switching
- **⚡ Fast Navigation**: Quick jump to sections

### Visual Enhancements
- **🎭 Modern Design**: Clean, professional appearance
- **📈 Progress Indicators**: Visual scan progress
- **🔔 Alert System**: Important findings highlighted
- **📋 Export Options**: PDF, CSV, and JSON export
- **🔗 Hyperlinks**: Clickable CPE and CVE references

### Security Dashboard
- **🛡️ Security Score**: Color-coded risk assessment
- **📊 Vulnerability Matrix**: Comprehensive security overview
- **💡 Recommendations**: Actionable security advice
- **🔒 SSL/TLS Report**: Detailed certificate analysis
- **📈 Trend Analysis**: Historical comparison support

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
# Fork and clone the repo
git clone https://github.com/genc-murat/portscanner.git
cd portscanner

# Create a feature branch
git checkout -b feature/ui-enhancement

# Make your changes and test
cargo test
cargo build

# Test interactive mode
cargo run -- --interactive

# Test IPv4 functionality
cargo run -- -t 127.0.0.1 --protocol both --ssl-analysis -p 22,53,80,123,443

# Test IPv6 functionality  
cargo run -- -t ::1 --protocol both --ssl-analysis -p 22,53,80,123,443

# Test dual-stack
cargo run -- -t localhost --protocol both -p 80,443

# Commit and push
git commit -m "Add UI enhancement"
git push origin feature/ui-enhancement
```

### Code Style

- Follow Rust conventions and use `cargo fmt`
- Add tests for new features (include IPv6 test cases)
- Update documentation as needed
- Ensure `cargo clippy` passes without warnings
- Test both IPv4 and IPv6 functionality when making changes
- Validate UI components work in different terminals
- Test interactive mode thoroughly

## 📝 License

This project is licensed under the MIT License - see the **LICENSE** file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Always ensure you have permission to scan the target systems. The developers are not responsible for any misuse of this software.

## 🙏 Acknowledgments

- Inspired by the original [Nmap](https://nmap.org/) project
- Built with the amazing [Tokio](https://tokio.rs/) async runtime
- CLI powered by [Clap](https://clap.rs/)
- Interactive UI powered by [Dialoguer](https://github.com/console-rs/dialoguer)
- Progress bars by [Indicatif](https://github.com/console-rs/indicatif)
- Colors by [Colored](https://github.com/colored-rs/colored)
- IPv6 support follows RFC 4291 and related standards

---

⭐ If you find this project useful, please consider giving it a star on GitHub!

## 📚 Resources

### IPv6 Resources
- [RFC 4291 - IPv6 Addressing Architecture](https://tools.ietf.org/html/rfc4291)
- [RFC 4861 - Neighbor Discovery for IPv6](https://tools.ietf.org/html/rfc4861)
- [RFC 8200 - IPv6 Specification](https://tools.ietf.org/html/rfc8200)
- [IPv6 Address Planning](https://www.ripe.net/publications/docs/ripe-690)

### Security Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SSL/TLS Best Practices](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [IPv6 Security Best Practices](https://tools.ietf.org/html/rfc4942)

### Development Resources
- [Rust Book](https://doc.rust-lang.org/book/)
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)
- [Clap Documentation](https://docs.rs/clap/latest/clap/)
- [Async Programming in Rust](https://rust-lang.github.io/async-book/)

---

🚀 **Ready to scan? Try interactive mode first!**

```bash
./target/release/portscanner --interactive
```