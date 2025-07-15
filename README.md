# Port Scanner

A fast, modern port scanner written in Rust with async networking, stealth SYN scan, advanced service detection, and OS fingerprinting capabilities. Inspired by Nmap but built for speed and simplicity.

## Features

- **Fast Async Scanning**: Built with Tokio for high-performance concurrent scanning
- **Stealth SYN Scan**: Raw socket SYN scanning for speed and stealth (Linux/Unix)
- **Banner Grabbing**: Extract service banners and version information
- **Advanced Service Detection**: Nmap-style service identification with 150+ signatures
- **OS Fingerprinting**: Operating system detection via TCP/IP stack analysis
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
cd port_scanner

# Build the project
cargo build --release

# Run a basic TCP scan
./target/release/port_scanner -t google.com -p 80,443

# Run with service detection
./target/release/port_scanner -t 192.168.1.1 -p 1-1000 --service-detection

# Run with OS fingerprinting
./target/release/port_scanner -t 192.168.1.1 -p 22,80,443 -O

# Run aggressive scan (everything enabled)
./target/release/port_scanner -t 192.168.1.1 -p 1-1000 -A

# Run stealth SYN scan (requires root)
sudo ./target/release/port_scanner -t 192.168.1.1 -s
```

### Basic Usage

```bash
# Scan common ports on a target
port_scanner -t 192.168.1.1

# Scan specific ports with banner grabbing
port_scanner -t example.com -p 22,80,443 -b

# Scan port range with high concurrency
port_scanner -t 192.168.1.1 -p 1-1000 -c 200

# Export results to JSON
port_scanner -t target.com -p 80,443 -b -j > results.json
```

## Usage

```
Port Scanner v0.4.0

USAGE:
    port_scanner [OPTIONS] --target <TARGET>

OPTIONS:
    -t, --target <TARGET>           Target IP address or hostname
    -p, --ports <PORTS>             Ports to scan (e.g., 80,443,22-25) [default: 1-1000]
    -c, --concurrency <CONCURRENCY> Number of concurrent connections [default: 100]
    -T, --timeout <TIMEOUT>         Connection timeout in milliseconds [default: 3000]
    -b, --banner                    Enable banner grabbing
    -s, --stealth                   Use stealth SYN scan (requires root)
    -j, --json                      Output results in JSON format
        --scan-type <TYPE>          Scan type: tcp, syn, or auto [default: auto]
        --service-detection         Enable advanced service detection
    -O, --os-detection              Enable OS fingerprinting
    -A, --aggressive               Aggressive mode (service detection + banner + OS detection)
    -h, --help                      Print help information
    -V, --version                   Print version information
```

## Examples

### Basic Port Scanning

```bash
# Scan default port range (1-1000)
port_scanner -t 192.168.1.1

# Scan specific ports
port_scanner -t google.com -p 80,443,22

# Scan port ranges
port_scanner -t 192.168.1.1 -p 1-100

# Mixed port specification
port_scanner -t example.com -p 22,80-90,443,8080-8090
```

### Advanced Scanning

```bash
# High-speed scanning with increased concurrency
port_scanner -t 192.168.1.1 -p 1-65535 -c 500

# Banner grabbing for service identification
port_scanner -t 192.168.1.1 -p 21,22,80,443 -b

# Custom timeout for slow networks
port_scanner -t slow-server.com -p 1-1000 -T 5000

# JSON output for automation
port_scanner -t target.com -p 80,443 -b -j | jq '.[] | select(.is_open)'
```

### Real-world Examples

```bash
# Web server reconnaissance
port_scanner -t example.com -p 80,443,8080,8443,8000,9000 -b

# Database server discovery
port_scanner -t db-server.local -p 3306,5432,1433,27017,6379 -b

# Network infrastructure scan
port_scanner -t 192.168.1.1 -p 21,22,23,53,80,443,161,162 -b

# Development environment scan
port_scanner -t localhost -p 3000,4000,5000,8000,8080,9000 -b
```

## Sample Output

### Standard Output (Aggressive Scan)
```
Port Scanner v0.4.0
Target: 192.168.1.1
 Aggressive mode enabled (service detection + banner grabbing + OS detection)
 Advanced service detection enabled
  OS fingerprinting enabled

Starting scan: 192.168.1.1 (3 ports)
Performing OS detection for 192.168.1.1

================================================================================
Port Scan Results - 192.168.1.1
================================================================================
3 open ports found:

🔗    22 open ssh OpenSSH 8.2p1        (  45ms)
        Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
        CPE: cpe:/a:openbsd:openssh:8.2p1

🔗    80 open http Apache httpd 2.4.41  ( 156ms)
        Banner: Server: Apache/2.4.41 (Ubuntu)
        CPE: cpe:/a:apache:http_server:2.4.41

🔗   443 open https nginx 1.18.0       ( 198ms)
        Banner: Server: nginx/1.18.0
        CPE: cpe:/a:nginx:nginx:1.18.0

OS Detection Results
----------------------------------------
Operating System: Linux (85% confidence)
    Details:
      • TTL: 64
      • Window Size: 29200
      • MSS: 1460
      • TCP Timestamps: Enabled
      • Window Scaling: Enabled
      • SACK: Enabled

Scan Summary
----------------------------------------
Total ports scanned: 3
Open ports: 3
Scan time: 0.25s
Services identified with high confidence: 3/3
OS detection: Success (High confidence)
```

### JSON Output
```json
[
  {
    "port": 80,
    "is_open": true,
    "service": "http",
    "banner": "Server: ECS (dcb/7F83)",
    "response_time": 156
  },
  {
    "port": 443,
    "is_open": true,
    "service": "https",
    "banner": "Server: ECS (dcb/7F83)",
    "response_time": 198
  }
]
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
cd port_scanner

# Build in debug mode
cargo build

# Build optimized release version
cargo build --release

# Run tests
cargo test

# Run with cargo
cargo run -- -t google.com -p 80,443
```

## 🔧 Configuration

### Performance Tuning

- **Concurrency**: Increase `-c` for faster scans, but be mindful of network limits
- **Timeout**: Adjust `-T` based on network conditions
- **Port Ranges**: Use specific ports instead of broad ranges for faster results

### Best Practices

```bash
# For local networks (fast)
port_scanner -t 192.168.1.1 -p 1-1000 -c 300 -T 1000

# For internet hosts (moderate)
port_scanner -t example.com -p 1-1000 -c 100 -T 3000

# For slow/filtered networks (conservative)
port_scanner -t target.com -p 80,443 -c 50 -T 10000
```

## Supported Detection

### **Service Detection (150+ signatures)**
- **Web Services**: Apache, nginx, IIS, lighttpd, Node.js, Django
- **Remote Access**: OpenSSH, Dropbear, Telnet, RDP, VNC
- **Mail Services**: Postfix, Sendmail, Exchange, Dovecot, Courier
- **Databases**: MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle
- **File Services**: vsftpd, ProFTPD, Samba, NFS, TFTP
- **Network Services**: BIND DNS, DHCP, SNMP, NTP

### **OS Fingerprinting**
- **Linux**: Ubuntu, CentOS, RHEL, Debian, Alpine, Android
- **Windows**: 7, 8, 10, 11, Server 2016/2019/2022
- **Unix**: FreeBSD, OpenBSD, NetBSD, Solaris
- **Apple**: macOS 10.x, 11.x, 12.x+
- **Network Devices**: Cisco IOS, Juniper JunOS
- **Embedded**: IoT devices, routers, switches

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
# Fork and clone the repo
git clone https://github.com/genc-murat/portscanner.git
cd port_scanner

# Create a feature branch
git checkout -b feature/awesome-feature

# Make your changes and test
cargo test
cargo build

# Commit and push
git commit -m "Add awesome feature"
git push origin feature/awesome-feature
```

### Code Style

- Follow Rust conventions and use `cargo fmt`
- Add tests for new features
- Update documentation as needed
- Ensure `cargo clippy` passes without warnings

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