# Port Scanner

A fast, modern port scanner written in Rust with async networking and banner grabbing capabilities. Inspired by Nmap but built for speed and simplicity.

## Features

- **Fast Async Scanning**: Built with Tokio for high-performance concurrent scanning
- **Banner Grabbing**: Extract service banners and version information
- **Multiple Target Support**: Scan IP addresses or hostnames
- **Service Detection**: Identify 150+ common services automatically
- **Colored Output**: Beautiful terminal output with syntax highlighting
- **JSON Export**: Export results in JSON format for further analysis
- **Configurable**: Customize concurrency, timeouts, and port ranges
- **Safe**: Built-in rate limiting and timeout controls

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/genc-murat/port_scanner.git
cd port_scanner

# Build the project
cargo build --release

# Run a basic scan
./target/release/port_scanner -t google.com -p 80,443
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
Port Scanner v0.1.0

USAGE:
    port_scanner [OPTIONS] --target <TARGET>

OPTIONS:
    -t, --target <TARGET>           Target IP address or hostname
    -p, --ports <PORTS>             Ports to scan (e.g., 80,443,22-25) [default: 1-1000]
    -c, --concurrency <CONCURRENCY> Number of concurrent connections [default: 100]
    -T, --timeout <TIMEOUT>         Connection timeout in milliseconds [default: 3000]
    -b, --banner                    Enable banner grabbing
    -j, --json                      Output results in JSON format
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

### Standard Output
```
Port Scanner v0.1.0
Target: example.com
Ports: 22,80,443
Concurrent connections: 100
Timeout: 3000ms
Banner grabbing enabled!

Starting scan: 93.184.216.34 (3 ports)

======================================================================
Port Scan Results - 93.184.216.34
======================================================================
2 open ports found:

   80 open http         ( 156ms)
      Banner: Server: ECS (dcb/7F83)

  443 open https        ( 198ms)
      Banner: Server: ECS (dcb/7F83)

======================================================================
Scan completed! Total time: 0.20s
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
```

### Build Steps

```bash
# Clone the repository
git clone https://github.com/genc-murat/port_scanner.git
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

## Configuration

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

## Service Detection

The scanner can automatically identify 150+ services including:

- **Web Services**: HTTP, HTTPS, Apache, Nginx, IIS
- **Databases**: MySQL, PostgreSQL, MongoDB, Redis, MSSQL
- **Remote Access**: SSH, Telnet, RDP, VNC
- **Mail Services**: SMTP, POP3, IMAP, Exchange
- **File Transfer**: FTP, SFTP, TFTP, SMB, NFS
- **Development**: Node.js, Python, Docker, Kubernetes
- **And many more...**

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
# Fork and clone the repo
git clone https://github.com/genc-murat/port_scanner.git
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

If you find this project useful, please consider giving it a star on GitHub!