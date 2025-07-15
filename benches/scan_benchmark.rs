// benches/scan_benchmark.rs
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::net::IpAddr;
use std::str::FromStr;
use tokio::runtime::Runtime;

// Mock benchmark since we can't easily benchmark network operations
fn port_parser_benchmark(c: &mut Criterion) {
    use portscanner::port_parser::parse_ports;

    let mut group = c.benchmark_group("port_parser");

    let test_cases = vec![
        ("single", "80"),
        ("range", "1-1000"),
        ("mixed", "22,80,443,8000-9000"),
        (
            "complex",
            "21,22,23,25,53,80,110,143,443,993,995,8080-8090,9000-9010",
        ),
    ];

    for (name, ports) in test_cases {
        group.bench_with_input(BenchmarkId::new("parse_ports", name), &ports, |b, ports| {
            b.iter(|| parse_ports(black_box(ports)));
        });
    }

    group.finish();
}

fn service_detection_benchmark(c: &mut Criterion) {
    use portscanner::service_detection::{ServiceDetector, ServiceInfo, format_service_info};

    let mut group = c.benchmark_group("service_detection");

    // Benchmark service detector creation
    group.bench_function("create_detector", |b| {
        b.iter(|| {
            let detector = ServiceDetector::new();
            black_box(detector);
        });
    });

    // Benchmark banner analysis using the public method
    let detector = ServiceDetector::new();
    let test_banners = vec![
        ("ssh", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"),
        ("http_apache", "Server: Apache/2.4.41 (Ubuntu)"),
        ("http_nginx", "Server: nginx/1.18.0"),
        ("ftp_vsftpd", "220 Welcome to vsftpd 3.0.3"),
        ("smtp_postfix", "220 mail.example.com ESMTP Postfix"),
    ];

    for (name, banner) in test_banners {
        group.bench_with_input(
            BenchmarkId::new("analyze_banner", name),
            &banner,
            |b, banner| {
                b.iter(|| detector.analyze_banner(black_box(80), black_box(banner)));
            },
        );
    }

    // Benchmark service info formatting
    let test_service_info = ServiceInfo {
        name: "http".to_string(),
        version: Some("2.4.41".to_string()),
        product: Some("Apache httpd".to_string()),
        os_type: Some("Linux".to_string()),
        device_type: None,
        confidence: 90,
        cpe: Some("cpe:/a:apache:http_server:2.4.41".to_string()),
        extra_info: None,
    };

    group.bench_function("format_service_info", |b| {
        b.iter(|| {
            format_service_info(black_box(&test_service_info));
        });
    });

    group.finish();
}

fn os_fingerprinting_benchmark(c: &mut Criterion) {
    use portscanner::os_fingerprinting::{
        NetworkCharacteristics, OSDetector, OSFingerprint, format_os_info,
    };

    let mut group = c.benchmark_group("os_fingerprinting");

    // Benchmark OS detector creation
    group.bench_function("create_detector", |b| {
        b.iter(|| {
            let detector = OSDetector::new();
            black_box(detector);
        });
    });

    // Benchmark signature matching
    let detector = OSDetector::new();
    let test_characteristics = vec![
        (
            "linux",
            NetworkCharacteristics {
                ttl: Some(64),
                window_size: Some(29200),
                mss: Some(1460),
                tcp_options: vec![0x02, 0x04, 0x04, 0x02, 0x08, 0x0a],
                tcp_flags_response: 0x12,
                icmp_response: false,
                closed_port_response: Some("RST".to_string()),
                sequence_predictability: Some(1000000.0),
                timestamps: true,
                window_scaling: true,
                sack_permitted: true,
            },
        ),
        (
            "windows",
            NetworkCharacteristics {
                ttl: Some(128),
                window_size: Some(65535),
                mss: Some(1460),
                tcp_options: vec![0x02, 0x04, 0x04, 0x02],
                tcp_flags_response: 0x12,
                icmp_response: false,
                closed_port_response: Some("RST".to_string()),
                sequence_predictability: Some(100000.0),
                timestamps: true,
                window_scaling: true,
                sack_permitted: true,
            },
        ),
    ];

    for (name, characteristics) in test_characteristics {
        group.bench_with_input(
            BenchmarkId::new("match_signatures", name),
            &characteristics,
            |b, characteristics| {
                b.iter(|| detector.match_signatures(black_box(characteristics)));
            },
        );
    }

    // Benchmark OS info formatting
    let test_os_info = OSFingerprint {
        os_family: "Linux".to_string(),
        os_name: "Ubuntu Linux".to_string(),
        os_version: Some("20.04".to_string()),
        device_type: Some("Server".to_string()),
        confidence: 95,
        cpe: Some("cpe:/o:canonical:ubuntu_linux:20.04".to_string()),
        vendor: Some("Canonical".to_string()),
        architecture: Some("x86_64".to_string()),
        details: vec!["TTL: 64".to_string(), "Window Size: 29200".to_string()],
    };

    group.bench_function("format_os_info", |b| {
        b.iter(|| {
            format_os_info(black_box(&test_os_info));
        });
    });

    group.finish();
}

fn concurrent_scanning_simulation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("concurrent_simulation");

    // Simulate the overhead of managing concurrent tasks
    let concurrency_levels = vec![10, 50, 100, 200];

    for concurrency in concurrency_levels {
        group.bench_with_input(
            BenchmarkId::new("semaphore_overhead", concurrency),
            &concurrency,
            |b, &concurrency| {
                b.iter(|| {
                    rt.block_on(async {
                        let semaphore =
                            std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
                        let mut handles = Vec::new();

                        for _ in 0..100 {
                            // Reduced from 1000 for faster benchmarks
                            let sem = semaphore.clone();
                            let handle = tokio::spawn(async move {
                                let _permit = sem.acquire().await.unwrap();
                                // Simulate minimal work
                                tokio::task::yield_now().await;
                            });
                            handles.push(handle);
                        }

                        for handle in handles {
                            let _ = handle.await;
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

fn network_utilities_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("network_utilities");

    // Benchmark IP parsing
    let ip_strings = vec![
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "8.8.8.8",
        "2001:4860:4860::8888", // IPv6
    ];

    for ip_str in ip_strings {
        group.bench_with_input(
            BenchmarkId::new("parse_ip", ip_str.replace(":", "_")),
            &ip_str,
            |b, ip_str| {
                b.iter(|| {
                    let _ip: Result<IpAddr, _> = black_box(ip_str).parse();
                });
            },
        );
    }

    // Benchmark string operations commonly used in scanning
    group.bench_function("banner_cleaning", |b| {
        let test_banner =
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n";
        b.iter(|| {
            let cleaned = black_box(test_banner)
                .trim()
                .lines()
                .next()
                .unwrap_or("")
                .trim_end_matches('\r')
                .trim_end_matches('\n')
                .to_string();
            black_box(cleaned);
        });
    });

    // Benchmark regex matching (simulated service detection)
    group.bench_function("regex_matching", |b| {
        use regex::Regex;
        let re = Regex::new(r"Apache/(\d+\.\d+\.\d+)").unwrap();
        let test_string = "Server: Apache/2.4.41 (Ubuntu)";

        b.iter(|| {
            let _captures = re.captures(black_box(test_string));
        });
    });

    group.finish();
}

fn data_structures_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_structures");

    // Benchmark port list operations
    group.bench_function("port_vec_operations", |b| {
        b.iter(|| {
            let mut ports: Vec<u16> = (1..=1000).collect();
            ports.sort();
            ports.dedup();
            let _contains_80 = ports.binary_search(&80).is_ok();
            black_box(ports);
        });
    });

    // Benchmark HashMap operations for service mapping
    group.bench_function("service_lookup", |b| {
        use std::collections::HashMap;

        let mut services = HashMap::new();
        services.insert(80, "http");
        services.insert(443, "https");
        services.insert(22, "ssh");
        services.insert(21, "ftp");
        services.insert(25, "smtp");

        b.iter(|| {
            let _service = services.get(&black_box(80));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    port_parser_benchmark,
    service_detection_benchmark,
    os_fingerprinting_benchmark,
    concurrent_scanning_simulation,
    network_utilities_benchmark,
    data_structures_benchmark
);
criterion_main!(benches);
