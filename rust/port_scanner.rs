// ============================================================================
//  RapidScan — Fast Concurrent Port Scanner (Rust, zero dependencies)
//  ---------------------------------------------------------------------------
//  Compile :  rustc -O port_scanner.rs -o port_scanner
//  Usage   :  ./port_scanner <host> [ports] [--top N] [--threads N] [--timeout MS]
//  Example :  ./port_scanner example.com --top 100
//             ./port_scanner 192.168.1.10 22,80,443,8000-8100 --threads 500
//
//  LEGAL: Use ONLY on systems you own or have written permission to test.
// ============================================================================

use std::env;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

// Well-known services (top 100-ish) mapped to names for the report.
fn service_name(port: u16) -> &'static str {
    match port {
        20 => "FTP-data",
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 => "DHCP",
        69 => "TFTP",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPC",
        123 => "NTP",
        135 => "MSRPC",
        137 => "NetBIOS-NS",
        139 => "NetBIOS-SSN",
        143 => "IMAP",
        161 => "SNMP",
        162 => "SNMP-trap",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        514 => "Syslog",
        587 => "SMTP-submission",
        631 => "IPP",
        636 => "LDAPS",
        873 => "Rsync",
        993 => "IMAPS",
        995 => "POP3S",
        1080 => "SOCKS",
        1433 => "MSSQL",
        1521 => "Oracle",
        1723 => "PPTP",
        2049 => "NFS",
        2181 => "ZooKeeper",
        2375 => "Docker-API",
        3000 => "Dev/Node",
        3128 => "Squid-Proxy",
        3268 => "GC",
        3306 => "MySQL",
        3389 => "RDP",
        4369 => "Erlang-EPMD",
        5000 => "Dev/Flask",
        5432 => "PostgreSQL",
        5601 => "Kibana",
        5672 => "AMQP",
        5900 => "VNC",
        5984 => "CouchDB",
        5985 => "WinRM",
        6379 => "Redis",
        6443 => "K8s-API",
        7001 => "WebLogic",
        8000 => "Dev/Alt-HTTP",
        8008 => "Alt-HTTP",
        8009 => "AJP",
        8080 => "HTTP-Alt/Proxy",
        8081 => "HTTP-Alt",
        8088 => "HTTP-Alt",
        8140 => "Puppet",
        8443 => "HTTPS-Alt",
        8500 => "Consul",
        8888 => "HTTP-Alt",
        9000 => "Dev/Alt",
        9042 => "Cassandra",
        9092 => "Kafka",
        9200 => "Elasticsearch",
        9300 => "Elasticsearch-node",
        9418 => "Git",
        10000 => "Webmin",
        11211 => "Memcached",
        15672 => "RabbitMQ-Web",
        27017 => "MongoDB",
        27018 => "MongoDB-Alt",
        50000 => "SAP",
        _ => "unknown",
    }
}

fn parse_port_spec(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let lo: u16 = a.trim().parse().map_err(|_| format!("bad port range: {part}"))?;
            let hi: u16 = b.trim().parse().map_err(|_| format!("bad port range: {part}"))?;
            if lo > hi {
                return Err(format!("bad port range: {part}"));
            }
            for p in lo..=hi {
                ports.push(p);
            }
        } else {
            let p: u16 = part.parse().map_err(|_| format!("bad port: {part}"))?;
            if p == 0 {
                return Err("port 0 is invalid".into());
            }
            ports.push(p);
        }
    }
    Ok(ports)
}

fn top_ports(n: usize) -> Vec<u16> {
    // Top ~200 most scanned ports (Nmap-style common list, trimmed).
    const COMMON: &[u16] = &[
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
        465, 514, 587, 631, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 2049,
        2181, 2375, 3000, 3128, 3268, 3306, 3389, 4369, 5000, 5432, 5601, 5672,
        5900, 5984, 5985, 6379, 6443, 7001, 8000, 8008, 8009, 8080, 8081, 8088,
        8140, 8443, 8500, 8888, 9000, 9042, 9092, 9200, 9300, 9418, 10000, 11211,
        15672, 27017, 27018, 50000,
    ];
    COMMON.iter().take(n).copied().collect()
}

fn scan_port(addr: SocketAddr, timeout: Duration) -> Option<Duration> {
    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Some(start.elapsed()),
        Err(_) => None,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "RapidScan — Fast Concurrent Port Scanner (Rust)\n\
             \n\
             USAGE:\n\
             \x20 ./port_scanner <host> [ports] [--top N] [--threads N] [--timeout MS]\n\
             \n\
             EXAMPLES:\n\
             \x20 ./port_scanner example.com --top 100\n\
             \x20 ./port_scanner 10.0.0.5 22,80,443,8000-8100 --threads 500 --timeout 800\n\
             \n\
             NOTE: Use ONLY on systems you own or have explicit permission to test."
        );
        std::process::exit(1);
    }

    let host = args[1].clone();
    let mut ports: Vec<u16> = Vec::new();
    let mut threads = 200usize;
    let mut timeout_ms = 1000u64;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--top" => {
                i += 1;
                let n: usize = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(100);
                ports = top_ports(n.clamp(1, 200));
            }
            "--threads" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    threads = v.parse().unwrap_or(200).clamp(1, 5000);
                }
            }
            "--timeout" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    timeout_ms = v.parse().unwrap_or(1000).clamp(50, 30000);
                }
            }
            spec => {
                ports.extend(parse_port_spec(spec).unwrap_or_else(|e| {
                    eprintln!("[!] {e}");
                    std::process::exit(1);
                }));
            }
        }
        i += 1;
    }

    if ports.is_empty() {
        ports = top_ports(100);
    }

    // Resolve host once.
    let mut addrs: Vec<SocketAddr> = (host.as_str(), 0)
        .to_socket_addrs()
        .unwrap_or_else(|_| {
            eprintln!("[!] Could not resolve host: {host}");
            std::process::exit(1);
        })
        .collect();
    if addrs.is_empty() {
        eprintln!("[!] Could not resolve host: {host}");
        std::process::exit(1);
    }
    let base = addrs.remove(0);
    let ip = base.ip();

    println!("──────────────────────────────────────────────────");
    println!("  RapidScan v1.0  (Rust)");
    println!("  Target : {host} ({ip})");
    println!("  Ports  : {}   Threads: {}   Timeout: {}ms",
             ports.len(), threads, timeout_ms);
    println!("──────────────────────────────────────────────────");

    let start_all = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let (tx, rx) = mpsc::channel::<(u16, Duration)>();

    let chunk = (ports.len() + threads - 1) / threads.max(1);
    let mut handles = Vec::new();

    for chunk_ports in ports.chunks(chunk.max(1)) {
        let chunk_ports = chunk_ports.to_vec();
        let tx = tx.clone();
        let ip = ip;
        handles.push(thread::spawn(move || {
            for p in chunk_ports {
                let addr = SocketAddr::new(ip, p);
                if let Some(latency) = scan_port(addr, timeout) {
                    let _ = tx.send((p, latency));
                }
            }
        }));
    }
    drop(tx);

    for h in handles {
        let _ = h.join();
    }

    let mut results: Vec<(u16, Duration)> = rx.iter().collect();
    results.sort_by_key(|(p, _)| *p);

    let elapsed = start_all.elapsed();

    if results.is_empty() {
        println!("  No open ports found on {host} within the scanned range.");
    } else {
        println!("  OPEN PORTS ({})", results.len());
        println!("  ────────────────────────────────────────────────");
        for (port, latency) in &results {
            println!("  {:<6} {:<18} {:.0} ms", port, service_name(*port), latency.as_secs_f64() * 1000.0);
        }
        println!("  ────────────────────────────────────────────────");
    }
    println!(
        "  Scan finished in {:.2}s ({})",
        elapsed.as_secs_f64(),
        results.len()
    );
    println!("──────────────────────────────────────────────────");
}
