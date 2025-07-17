use chrono::Utc;
use colored::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

// Args struct definition for progress module
#[derive(Debug, Clone)]
pub struct Args {
    pub target: String,
    pub ports: String,
    pub concurrency: usize,
    pub timeout: u64,
    pub json: bool,
    pub html_output: Option<String>,
    pub banner: bool,
    pub stealth: bool,
    pub scan_type: String,
    pub protocol: Option<String>,
    pub service_detection: bool,
    pub os_detection: bool,
    pub ssl_analysis: bool,
    pub aggressive: bool,
    pub risk_assessment: bool,
    pub compliance_check: Option<String>,
    pub threat_model: bool,
}

pub struct ScanProgress {
    multi_progress: Arc<MultiProgress>,
    main_bar: Arc<Mutex<ProgressBar>>,
    tcp_bar: Arc<Mutex<Option<ProgressBar>>>,
    udp_bar: Arc<Mutex<Option<ProgressBar>>>,
    ssl_bar: Arc<Mutex<Option<ProgressBar>>>,
    os_bar: Arc<Mutex<Option<ProgressBar>>>,
    current_target: Arc<Mutex<String>>,
    total_ports: usize,
    completed_ports: Arc<Mutex<usize>>,
    open_ports: Arc<Mutex<usize>>,
    start_time: std::time::Instant,
}

impl ScanProgress {
    pub fn new(total_ports: usize, target: &str) -> Self {
        let multi_progress = Arc::new(MultiProgress::new());

        // Main progress bar
        let main_bar = ProgressBar::new(total_ports as u64);
        main_bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] {wide_bar:.cyan/blue} {pos}/{len} ports ({eta})")
                .unwrap()
                .progress_chars("███")
        );
        main_bar.set_message(format!("🔍 Scanning {}", target.cyan().bold()));

        let main_bar = Arc::new(Mutex::new(multi_progress.add(main_bar)));

        Self {
            multi_progress,
            main_bar,
            tcp_bar: Arc::new(Mutex::new(None)),
            udp_bar: Arc::new(Mutex::new(None)),
            ssl_bar: Arc::new(Mutex::new(None)),
            os_bar: Arc::new(Mutex::new(None)),
            current_target: Arc::new(Mutex::new(target.to_string())),
            total_ports,
            completed_ports: Arc::new(Mutex::new(0)),
            open_ports: Arc::new(Mutex::new(0)),
            start_time: std::time::Instant::now(),
        }
    }

    pub async fn create_tcp_bar(&self, tcp_port_count: usize) {
        let bar = ProgressBar::new(tcp_port_count as u64);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("  🌐 TCP  [{wide_bar:.blue/cyan}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("███"),
        );
        bar.set_message("scanning...".dimmed().to_string());

        let bar = self.multi_progress.add(bar);
        *self.tcp_bar.lock().await = Some(bar);
    }

    pub async fn create_udp_bar(&self, udp_port_count: usize) {
        let bar = ProgressBar::new(udp_port_count as u64);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("  📡 UDP  [{wide_bar:.magenta/purple}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("███"),
        );
        bar.set_message("scanning...".dimmed().to_string());

        let bar = self.multi_progress.add(bar);
        *self.udp_bar.lock().await = Some(bar);
    }

    pub async fn create_ssl_bar(&self, ssl_port_count: usize) {
        let bar = ProgressBar::new(ssl_port_count as u64);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("  🔐 SSL  [{wide_bar:.green/yellow}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("███"),
        );
        bar.set_message("analyzing...".dimmed().to_string());

        let bar = self.multi_progress.add(bar);
        *self.ssl_bar.lock().await = Some(bar);
    }

    pub async fn create_os_bar(&self) {
        let bar = ProgressBar::new(100);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("  🖥️ OS   [{wide_bar:.yellow/red}] {pos}% {msg}")
                .unwrap()
                .progress_chars("███"),
        );
        bar.set_message("fingerprinting...".dimmed().to_string());

        let bar = self.multi_progress.add(bar);
        *self.os_bar.lock().await = Some(bar);
    }

    pub async fn update_tcp_progress(&self, completed: u64, message: &str) {
        if let Some(bar) = self.tcp_bar.lock().await.as_ref() {
            bar.set_position(completed);
            bar.set_message(message.to_string());
        }
    }

    pub async fn update_udp_progress(&self, completed: u64, message: &str) {
        if let Some(bar) = self.udp_bar.lock().await.as_ref() {
            bar.set_position(completed);
            bar.set_message(message.to_string());
        }
    }

    pub async fn update_ssl_progress(&self, completed: u64, message: &str) {
        if let Some(bar) = self.ssl_bar.lock().await.as_ref() {
            bar.set_position(completed);
            bar.set_message(message.to_string());
        }
    }

    pub async fn update_os_progress(&self, percent: u64, message: &str) {
        if let Some(bar) = self.os_bar.lock().await.as_ref() {
            bar.set_position(percent);
            bar.set_message(message.to_string());
        }
    }

    pub async fn increment_main(&self, port: u16, is_open: bool) {
        let mut completed = self.completed_ports.lock().await;
        *completed += 1;

        if is_open {
            let mut open = self.open_ports.lock().await;
            *open += 1;

            // Update main bar message with found port
            let main_bar = self.main_bar.lock().await;
            main_bar.set_message(format!(
                "🎯 Found open port: {}",
                port.to_string().green().bold()
            ));
        }

        let main_bar = self.main_bar.lock().await;
        main_bar.set_position(*completed as u64);

        // Update ETA and speed
        let elapsed = self.start_time.elapsed();
        let rate = *completed as f64 / elapsed.as_secs_f64();
        if rate > 0.0 {
            let eta = Duration::from_secs_f64((self.total_ports - *completed) as f64 / rate);
            main_bar.set_message(format!("🔍 Scanning... {:.1} ports/sec", rate));
        }
    }

    pub async fn finish_tcp(&self, open_count: usize) {
        if let Some(bar) = self.tcp_bar.lock().await.as_ref() {
            bar.finish_with_message(format!(
                "{} open ports found",
                open_count.to_string().green().bold()
            ));
        }
    }

    pub async fn finish_udp(&self, open_count: usize, open_filtered_count: usize) {
        if let Some(bar) = self.udp_bar.lock().await.as_ref() {
            bar.finish_with_message(format!(
                "{} open, {} open|filtered",
                open_count.to_string().green().bold(),
                open_filtered_count.to_string().yellow().bold()
            ));
        }
    }

    pub async fn finish_ssl(&self, analyzed_count: usize) {
        if let Some(bar) = self.ssl_bar.lock().await.as_ref() {
            bar.finish_with_message(format!(
                "{} services analyzed",
                analyzed_count.to_string().cyan().bold()
            ));
        }
    }

    pub async fn finish_os(&self, confidence: u8) {
        if let Some(bar) = self.os_bar.lock().await.as_ref() {
            bar.set_position(100);
            bar.finish_with_message(format!(
                "{}% confidence",
                confidence.to_string().green().bold()
            ));
        }
    }

    pub async fn finish_all(&self) {
        let main_bar = self.main_bar.lock().await;
        let open_ports = *self.open_ports.lock().await;
        let elapsed = self.start_time.elapsed();

        main_bar.finish_with_message(format!(
            "✅ Scan completed! {} open ports found in {:.2}s",
            open_ports.to_string().green().bold(),
            elapsed.as_secs_f64()
        ));

        // Small delay to show completion
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    pub fn get_multi_progress(&self) -> Arc<MultiProgress> {
        self.multi_progress.clone()
    }
}

pub struct InteractiveScanner {
    target: String,
    ports: String,
    protocol: String,
    concurrency: usize,
    timeout: u64,
    enable_service_detection: bool,
    enable_os_detection: bool,
    enable_ssl_analysis: bool,
    enable_banner_grabbing: bool,
    use_stealth: bool,
    output_format: OutputFormat,
    output_file: Option<String>,
    enable_risk_assessment: bool,
    compliance_framework: Option<String>,
    enable_threat_model: bool,
}

#[derive(Debug, Clone)]
pub enum OutputFormat {
    Console,
    Json,
    Html,
}

impl InteractiveScanner {
    pub fn new() -> Self {
        Self {
            target: String::new(),
            ports: "1-1000".to_string(),
            protocol: "tcp".to_string(),
            concurrency: 100,
            timeout: 3000,
            enable_service_detection: false,
            enable_os_detection: false,
            enable_ssl_analysis: false,
            enable_banner_grabbing: false,
            use_stealth: false,
            output_format: OutputFormat::Console,
            output_file: None,
            // NEW fields initialization
            enable_risk_assessment: false,
            compliance_framework: None,
            enable_threat_model: false,
        }
    }

    pub fn interactive_setup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        use dialoguer::{Confirm, Input, MultiSelect, Select};

        println!("{}", "🎮 Interactive Port Scanner Setup".cyan().bold());
        println!("{}", "═".repeat(50));

        // Target selection
        self.target = Input::new()
            .with_prompt("🎯 Target (IP/hostname)")
            .interact_text()?;

        // Protocol selection
        let protocols = vec!["TCP only", "UDP only", "Both TCP and UDP"];
        let protocol_selection = Select::new()
            .with_prompt("🔌 Protocol")
            .items(&protocols)
            .default(0)
            .interact()?;

        self.protocol = match protocol_selection {
            0 => "tcp".to_string(),
            1 => "udp".to_string(),
            2 => "both".to_string(),
            _ => "tcp".to_string(),
        };

        // Port range selection
        let port_options = vec![
            "Top 100 ports (quick)",
            "Top 1000 ports (default)",
            "All ports (1-65535)",
            "Custom range",
        ];

        let port_selection = Select::new()
            .with_prompt("📡 Port range")
            .items(&port_options)
            .default(1)
            .interact()?;

        self.ports = match port_selection {
            0 => self.get_top_ports(100),
            1 => "1-1000".to_string(),
            2 => "1-65535".to_string(),
            3 => Input::new()
                .with_prompt("   Custom ports (e.g., 80,443,8000-9000)")
                .interact_text()?,
            _ => "1-1000".to_string(),
        };

        // Performance settings
        let performance_levels = vec![
            "Conservative (50)",
            "Balanced (100)",
            "Aggressive (200)",
            "Maximum (500)",
        ];
        let perf_selection = Select::new()
            .with_prompt("⚡ Performance level")
            .items(&performance_levels)
            .default(1)
            .interact()?;

        self.concurrency = match perf_selection {
            0 => 50,
            1 => 100,
            2 => 200,
            3 => 500,
            _ => 100,
        };

        // Advanced features
        let features = vec![
            "Service Detection",
            "OS Fingerprinting",
            "SSL/TLS Analysis",
            "Banner Grabbing",
            "Stealth SYN Scan (requires root)",
            "Risk Assessment", // NEW
            "Threat Modeling", // NEW
        ];

        let selected_features = MultiSelect::new()
            .with_prompt("🔧 Enable advanced features")
            .items(&features)
            .interact()?;

        for &index in &selected_features {
            match index {
                0 => self.enable_service_detection = true,
                1 => self.enable_os_detection = true,
                2 => self.enable_ssl_analysis = true,
                3 => self.enable_banner_grabbing = true,
                4 => self.use_stealth = true,
                5 => self.enable_risk_assessment = true, // NEW
                6 => self.enable_threat_model = true,    // NEW
                _ => {}
            }
        }

        // NEW: Compliance framework selection
        if self.enable_risk_assessment {
            let compliance_options = vec![
                "None",
                "PCI DSS",
                "NIST Cybersecurity Framework",
                "All frameworks",
            ];
            let compliance_selection = Select::new()
                .with_prompt("📋 Compliance framework")
                .items(&compliance_options)
                .default(0)
                .interact()?;

            self.compliance_framework = match compliance_selection {
                1 => Some("pci-dss".to_string()),
                2 => Some("nist".to_string()),
                3 => Some("all".to_string()),
                _ => None,
            };
        }

        // Output format
        let output_formats = vec!["Console output", "JSON file", "HTML report"];
        let output_selection = Select::new()
            .with_prompt("📊 Output format")
            .items(&output_formats)
            .default(0)
            .interact()?;

        self.output_format = match output_selection {
            0 => OutputFormat::Console,
            1 => {
                self.output_file = Some(
                    Input::new()
                        .with_prompt("   JSON filename")
                        .default("scan_results.json".to_string())
                        .interact_text()?,
                );
                OutputFormat::Json
            }
            2 => {
                self.output_file = Some(
                    Input::new()
                        .with_prompt("   HTML filename")
                        .default("scan_report.html".to_string())
                        .interact_text()?,
                );
                OutputFormat::Html
            }
            _ => OutputFormat::Console,
        };

        // Confirmation
        println!("\n{}", "📋 Scan Configuration Summary:".yellow().bold());
        println!("   Target: {}", self.target.cyan());
        println!("   Ports: {}", self.ports.green());
        println!("   Protocol: {}", self.protocol.blue());
        println!("   Concurrency: {}", self.concurrency.to_string().yellow());
        println!(
            "   Features: {}",
            self.get_enabled_features().join(", ").magenta()
        );

        let confirm = Confirm::new()
            .with_prompt("🚀 Start scan with these settings?")
            .default(true)
            .interact()?;

        if !confirm {
            println!("❌ Scan cancelled.");
            std::process::exit(0);
        }

        Ok(())
    }

    fn get_top_ports(&self, count: usize) -> String {
        let top_ports = vec![
            80, 443, 22, 21, 25, 53, 110, 993, 995, 143, 23, 135, 139, 445, 3389, 5900, 1433, 3306,
            5432, 1521, 111, 2049, 2000, 8080, 8000, 8443, 8888, 9000, 9200, 5000, 5001, 6379,
            27017, 11211, 6000, 1080, 1194, 1701, 1723, 500, 4500, 1900, 5353, 5060, 5061, 554,
            1935, 8554, 873, 548,
        ];

        top_ports
            .iter()
            .take(count)
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn get_enabled_features(&self) -> Vec<String> {
        let mut features = Vec::new();

        if self.enable_service_detection {
            features.push("Service Detection".to_string());
        }
        if self.enable_os_detection {
            features.push("OS Fingerprinting".to_string());
        }
        if self.enable_ssl_analysis {
            features.push("SSL Analysis".to_string());
        }
        if self.enable_banner_grabbing {
            features.push("Banner Grabbing".to_string());
        }
        if self.use_stealth {
            features.push("Stealth Scan".to_string());
        }
        if self.enable_risk_assessment {
            features.push("Risk Assessment".to_string());
        }
        if self.enable_threat_model {
            features.push("Threat Modeling".to_string());
        }
        if let Some(ref framework) = self.compliance_framework {
            features.push(format!("Compliance ({})", framework));
        }

        if features.is_empty() {
            features.push("Basic Scan".to_string());
        }

        features
    }

    pub fn to_args(&self) -> Args {
        Args {
            target: self.target.clone(),
            ports: self.ports.clone(),
            protocol: Some(self.protocol.clone()),
            concurrency: self.concurrency,
            timeout: self.timeout,
            json: matches!(self.output_format, OutputFormat::Json),
            html_output: if matches!(self.output_format, OutputFormat::Html) {
                self.output_file.clone()
            } else {
                None
            },
            banner: self.enable_banner_grabbing,
            stealth: self.use_stealth,
            scan_type: if self.use_stealth {
                "syn".to_string()
            } else {
                "auto".to_string()
            },
            service_detection: self.enable_service_detection,
            os_detection: self.enable_os_detection,
            ssl_analysis: self.enable_ssl_analysis,
            aggressive: self.enable_service_detection
                && self.enable_os_detection
                && self.enable_ssl_analysis,
            risk_assessment: self.enable_risk_assessment, // NEW
            compliance_check: self.compliance_framework.clone(), // NEW
            threat_model: self.enable_threat_model,       // NEW
        }
    }
}

pub fn print_welcome_banner() {
    println!(
        "{}",
        r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║    ██████╗  ██████╗ ██████╗ ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗       ║
║    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║       ║
║    ██████╔╝██║   ██║██████╔╝   ██║   ███████╗██║     ███████║██╔██╗ ██║       ║
║    ██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║       ║
║    ██║     ╚██████╔╝██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║       ║
║    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝       ║
║                                                                               ║
║                🚀 Advanced Port Scanner with Modern Features 🚀              ║
║                          Version 0.4.0 - Rust Edition                         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#
        .cyan()
    );

    println!("{}", "✨ Features Overview:".yellow().bold());
    println!(
        "   {} TCP & UDP Scanning with high-speed concurrent connections",
        "🔍".cyan()
    );
    println!(
        "   {} Stealth SYN scan for covert network reconnaissance",
        "👤".cyan()
    );
    println!(
        "   {} Advanced service detection with 150+ signatures",
        "🔧".cyan()
    );
    println!(
        "   {} OS fingerprinting using TCP/IP stack analysis",
        "🖥️".cyan()
    );
    println!(
        "   {} SSL/TLS security analysis and vulnerability assessment",
        "🔐".cyan()
    );
    println!("   {} Full IPv6 support for modern networks", "🌐".cyan());
    println!(
        "   {} Professional HTML reports with interactive charts",
        "📊".cyan()
    );
    println!(
        "   {} JSON export for integration with other tools",
        "📋".cyan()
    );

    println!("\n{}", "🎯 Quick Start Examples:".green().bold());
    println!(
        "   {} Basic scan:     portscanner -t example.com",
        "•".blue()
    );
    println!(
        "   {} Stealth scan:   portscanner -t 192.168.1.1 --stealth",
        "•".blue()
    );
    println!(
        "   {} Full analysis:  portscanner -t target.com --aggressive",
        "•".blue()
    );
    println!(
        "   {} Interactive:    portscanner --interactive",
        "•".blue()
    );

    println!("\n{}", "💡 Pro Tips:".yellow().bold());
    println!(
        "   {} Use {} for faster results",
        "•".dimmed(),
        "--concurrency 200".green()
    );
    println!(
        "   {} Add {} for detailed analysis",
        "•".dimmed(),
        "--aggressive".green()
    );
    println!(
        "   {} Try {} for professional reports",
        "•".dimmed(),
        "--html report.html".green()
    );

    println!("{}", "═".repeat(80));
}

pub fn print_scan_start_animation() {
    use std::thread;
    use std::time::Duration;

    let frames = vec!["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

    print!("🚀 Initializing scan engines");

    for _ in 0..20 {
        for frame in &frames {
            print!("\r🚀 Initializing scan engines {}", frame.cyan());
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            thread::sleep(Duration::from_millis(100));
        }
    }

    println!("\r🚀 Scan engines ready! ✅");
}

pub fn show_completion_celebration(open_ports: usize, scan_time: f64) {
    println!("\n{}", "🎉 SCAN COMPLETED SUCCESSFULLY! 🎉".green().bold());
    println!("{}", "═".repeat(50));

    if open_ports > 0 {
        println!(
            "✅ {} open ports discovered!",
            open_ports.to_string().green().bold()
        );
    } else {
        println!("🔒 No open ports found - target appears well secured!");
    }

    println!("⏱️ Scan completed in {:.2} seconds", scan_time);
    println!("🚀 Thank you for using PortScanner!");

    // ASCII art celebration for significant findings
    if open_ports > 10 {
        println!(
            "\n{}",
            r#"
    🎯 SIGNIFICANT FINDINGS DETECTED! 🎯
    
         ╔═══════════════════════════╗
         ║  Review results carefully ║
         ║     Security assessment   ║
         ║        recommended        ║
         ╚═══════════════════════════╝
        "#
            .yellow()
        );
    }
}

pub fn print_error_help(error: &str) {
    println!("\n{} Error: {}", "❌".red(), error.red());

    println!("\n{} Troubleshooting:", "💡".yellow().bold());

    if error.contains("permission") || error.contains("root") {
        println!("   • Run with sudo for stealth scan: sudo portscanner -t target --stealth");
        println!("   • Or use regular TCP scan: portscanner -t target --scan-type tcp");
    }

    if error.contains("resolve") || error.contains("hostname") {
        println!("   • Check hostname spelling and network connectivity");
        println!("   • Try using IP address instead of hostname");
        println!("   • Verify DNS resolution: nslookup hostname");
    }

    if error.contains("timeout") || error.contains("connection") {
        println!("   • Increase timeout: --timeout 5000");
        println!("   • Reduce concurrency: --concurrency 50");
        println!("   • Check firewall settings");
    }

    println!("\n{} For more help:", "ℹ️".blue());
    println!("   portscanner --help");
    println!("   portscanner --interactive");
}
