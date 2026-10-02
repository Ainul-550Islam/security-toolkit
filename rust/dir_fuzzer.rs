// ============================================================================
//  RapidDir — Fast Concurrent Directory/File Fuzzer (Rust, zero deps)
//  ---------------------------------------------------------------------------
//  Feature parity target: ffuf / feroxbuster basics (speed benchmark)
//
//  Compile :  rustc -O dir_fuzzer.rs -o dir_fuzzer
//  Usage   :  ./dir_fuzzer https://example.com [options]
//  Options :  --wordlist FILE     custom wordlist (one path per line)
//             --ext "php,bak,txt" append extensions
//             --threads N         default 50
//             --timeout MS        default 4000
//             --size S            ignore responses with body size S
//             --status "200,403"  show only these statuses
//  LEGAL: authorized testing only.
// ============================================================================

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_WORDS: &[&str] = &[
    "admin", "administrator", "api", "api/v1", "api/v2", "app", "assets", "backup",
    "backups", "bak", "beta", "blog", "cache", "cgi-bin", "config", "config.php",
    "console", "cron", "css", "dashboard", "data", "database", "db", "debug",
    "demo", "dev", "docker", "docs", "download", "downloads", "env", "error",
    "example", "favicon.ico", "files", "git", "graphql", "health", "home", "images",
    "img", "index", "index.html", "js", "json", "languages", "laravel", "lib",
    "license", "login", "logout", "log", "logs", "mail", "manage", "media",
    "monitor", "node_modules", "old", "panel", "phpinfo.php", "portal", "private",
    "prod", "public", "readme", "register", "robots.txt", "root", "rsync", "sitemap.xml",
    "sql", "src", "ssh", "static", "status", "storage", "staging", "swagger",
    "swagger.json", "swagger-ui", "test", "testing", "tmp", "tools", "uploads",
    "v1", "v2", "vendor", "web", "web.config", "wiki", "wp-admin", "wp-content",
    "wp-includes", "xmlrpc.php", ".env", ".git", ".git/HEAD", ".svn", ".htaccess",
    ".idea", ".DS_Store", "docker-compose.yml", "package.json", "composer.json",
    "requirements.txt", "webpack.config.js", "openapi.json", "redoc", "graphiql",
    "actuator", "actuator/env", "actuator/health", "server-status", "server-info",
    "phpmyadmin", "pma", "dbadmin", "adminer.php", "webshell", "shell",
];

struct FuzzResult {
    status: u16,
    size: usize,
    path: String,
    elapsed_ms: u64,
}

fn request(base: &str, path: &str, timeout: Duration) -> Option<(u16, usize, u64)> {
    // Minimal HTTP/1.1 GET over stdlib TcpStream (no external crates).
    let t0 = Instant::now();
    let host = base.trim_start_matches("https://").trim_start_matches("http://");
    let hostname = host.split('/').next().unwrap_or(host);
    let (host_part, port) = match hostname.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(80)),
        None => (hostname.to_string(), 80),
    };
    let addr = format!("{host_part}:{port}");
    let sock_addr: SocketAddr = match addr
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
    {
        Some(s) => s,
        None => return None,
    };
    let mut stream = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(5)).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_part}\r\nUser-Agent: RapidDir/1.0 (authorized-audit)\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let elapsed = t0.elapsed().as_millis() as u64;

    let status_line = text.lines().next()?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;
    // Approximate body size: bytes after \r\n\r\n
    let body_size = text.find("\r\n\r\n").map(|i| text.len() - i - 4).unwrap_or(0);
    Some((status, body_size, elapsed))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "RapidDir — Fast Concurrent Directory Fuzzer (Rust)\n\n\
             USAGE:\n  ./dir_fuzzer <url> [--wordlist FILE] [--ext a,b,c]\n  \
             [--threads N] [--timeout MS] [--status 200,403]\n\n\
             EXAMPLES:\n  ./dir_fuzzer https://example.com\n  \
             ./dir_fuzzer https://example.com --ext php,bak --threads 100\n\
             \nNOTE: authorized testing only."
        );
        std::process::exit(1);
    }
    let base = args[1].trim_end_matches('/').to_string();
    let mut wordlist: Vec<String> = DEFAULT_WORDS.iter().map(|s| s.to_string()).collect();
    let mut threads = 50usize;
    let mut timeout_ms = 4000u64;
    let mut exts: Vec<String> = Vec::new();
    let mut show_status: Option<HashSet<u16>> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--wordlist" | "-w" => {
                i += 1;
                if let Some(f) = args.get(i) {
                    if let Ok(file) = fs::File::open(f) {
                        wordlist = BufReader::new(file)
                            .lines()
                            .map_while(Result::ok)
                            .map(|l| l.trim().trim_start_matches('/').to_string())
                            .filter(|l| !l.is_empty())
                            .collect();
                    }
                }
            }
            "--ext" | "-e" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    exts = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                }
            }
            "--threads" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    threads = v.parse().unwrap_or(50).clamp(1, 1000);
                }
            }
            "--timeout" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    timeout_ms = v.parse().unwrap_or(4000);
                }
            }
            "--status" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    let set: HashSet<u16> = v.split(',').filter_map(|s| s.trim().parse().ok()).collect();
                    show_status = Some(set);
                }
            }
            _ => {}
        }
        i += 1;
    }

    // Build full path list (base words + extensions).
    let mut paths: Vec<String> = Vec::new();
    for w in &wordlist {
        paths.push(w.clone());
        if !exts.is_empty() {
            for e in &exts {
                paths.push(format!("{w}.{e}"));
            }
        }
    }
    paths.sort();
    paths.dedup();

    let timeout = Duration::from_millis(timeout_ms);
    let (tx, rx) = mpsc::channel::<FuzzResult>();
    let found = Mutex::new(false);

    println!("──────────────────────────────────────────────────");
    println!("  RapidDir v1.0 (Rust) — Directory Fuzzer");
    println!("  Target : {base}");
    println!("  Words  : {}    Threads: {}    Timeout: {}ms",
             paths.len(), threads, timeout_ms);
    println!("──────────────────────────────────────────────────");

    let t_start = Instant::now();
    let chunk = (paths.len() + threads - 1) / threads.max(1);
    let mut handles = Vec::new();

    for chunk_paths in paths.chunks(chunk.max(1)) {
        let chunk_paths = chunk_paths.to_vec();
        let base = base.clone();
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            for p in chunk_paths {
                let path = format!("/{p}");
                if let Some((status, size, ms)) = request(&base, &path, timeout) {
                    let _ = tx.send(FuzzResult { status, size, path, elapsed_ms: ms });
                }
            }
        }));
    }
    drop(tx);
    for h in handles {
        let _ = h.join();
    }

    let mut results: Vec<FuzzResult> = rx.iter().collect();
    results.sort_by(|a, b| a.status.cmp(&b.status).then(a.path.cmp(&b.path)));

    let elapsed = t_start.elapsed().as_secs_f64();
    let mut shown = 0;
    for r in &results {
        if let Some(ref set) = show_status {
            if !set.contains(&r.status) {
                continue;
            }
        }
        println!("  {:<6} {:>8} bytes  {:>5} ms   {}", r.status, r.size, r.elapsed_ms, r.path);
        shown += 1;
        *found.lock().unwrap() = true;
    }
    if shown == 0 {
        println!("  (no interesting responses)");
    }
    println!(
        "  ────────────────────────────────────────────────\n  {shown} matches from {} paths in {:.2}s",
        paths.len(),
        elapsed
    );
    println!("──────────────────────────────────────────────────");
}
