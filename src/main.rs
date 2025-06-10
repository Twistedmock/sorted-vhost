use clap::{Arg, Command};
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task;
use scraper::{Html, Selector};
use libc;

#[derive(Serialize, Deserialize, Clone)]
struct RequestResult {
    host: String,
    url: String,
    status_code: u16,
    content_length: u64,
    word_count: usize,
    error: Option<String>,
}

impl RequestResult {
    fn to_tabular(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.host,
            self.url,
            self.status_code,
            self.content_length,
            self.word_count
        )
    }

    fn to_debug_format(&self, a_result: &RequestResult, b_result: &RequestResult, title: &str) -> String {
        format!(
            "{} {} {} {} {} (A: {} CL:{} WC:{}, B: {} CL:{} WC:{}, C: {} CL:{} WC:{}) \"{}\"",
            self.host,
            self.url,
            self.status_code,
            self.content_length,
            self.word_count,
            a_result.status_code, a_result.content_length, a_result.word_count,
            b_result.status_code, b_result.content_length, b_result.word_count,
            self.status_code, self.content_length, self.word_count,
            title
        )
    }
}

fn configure_system(verbose: bool) -> io::Result<()> {
    unsafe {
        let target_limit = 1_048_576;
        let rlimit = libc::rlimit {
            rlim_cur: target_limit,
            rlim_max: target_limit,
        };
        if libc::setrlimit(libc::RLIMIT_NOFILE, &rlimit) != 0 {
            let err = io::Error::last_os_error();
            if verbose {
                eprintln!(
                    "Failed to set file descriptor limit to {}. Run 'ulimit -n {}' manually: {}",
                    target_limit, target_limit, err
                );
            }
            return Err(err);
        }
        if verbose {
            println!("Set file descriptor limit to {}", target_limit);
        }
    }

    #[cfg(target_os = "linux")]
    {
        let sysctl_settings = [
            ("net.ipv4.ip_local_port_range", "10000 65535"),
            ("net.ipv4.tcp_fin_timeout", "15"),
            ("net.ipv4.tcp_tw_reuse", "1"),
            ("fs.file-max", "2097152"),
        ];
        for (key, value) in sysctl_settings.iter() {
            let cmd = std::process::Command::new("sysctl")
                .arg("-w")
                .arg(format!("{}={}", key, value))
                .output();
            match cmd {
                Ok(output) if output.status.success() => {
                    if verbose {
                        println!("Set {} = {}", key, value);
                    }
                }
                Ok(output) => {
                    let err = String::from_utf8_lossy(&output.stderr);
                    if verbose {
                        eprintln!(
                            "Failed to set {} = {}. Run 'sudo sysctl -w {}={}' manually: {}",
                            key, value, key, value, err
                        );
                    }
                }
                Err(e) => {
                    if verbose {
                        eprintln!(
                            "Failed to run sysctl for {} = {}: {}. Run 'sudo sysctl -w {}={}' manually",
                            key, value, e, key, value
                        );
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if verbose {
            println!("TCP settings (e.g., port range, TCP reuse) are Linux-specific and not applied on macOS.");
            println!("To increase file descriptors on macOS, run:");
            println!("  sudo sysctl -w kern.maxfiles=2097152");
            println!("  sudo sysctl -w kern.maxfilesperproc=1048576");
        }
    }

    Ok(())
}

async fn send_request(client: &Client, url: String, host: Option<&str>, verbose: bool) -> RequestResult {
    let mut attempts = 0;
    let max_retries = 0; // Disable retries for speed
    loop {
        let mut request = client
            .get(&url)
            .header("User-Agent", "Mozilla/5.0 (compatible; sorted-vhost/1.0)")
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Connection", "keep-alive");
        if let Some(host) = host {
            request = request.header("Host", host);
        }
        match request.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let content_length = response
                    .headers()
                    .get("Content-Length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                return RequestResult {
                    host: host.unwrap_or("").to_string(),
                    url,
                    status_code: status,
                    content_length,
                    word_count: 0, // Defer word count to filtering stage
                    error: None,
                };
            }
            Err(e) => {
                attempts += 1;
                let error = e.to_string();
                if attempts > max_retries {
                    if verbose {
                        eprintln!("Request to {} failed: {}", url, error);
                    }
                    return RequestResult {
                        host: host.unwrap_or("").to_string(),
                        url,
                        status_code: 0,
                        content_length: 0,
                        word_count: 0,
                        error: Some(error),
                    };
                }
                if verbose {
                    eprintln!("Retrying request to {} (attempt {}): {}", url, attempts, error);
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

async fn calculate_word_count_and_title(body: &str, verbose: bool) -> (usize, String) {
    let document = Html::parse_document(body);
    let body_selector = Selector::parse("body").unwrap();
    let title_selector = Selector::parse("title").unwrap();
    
    let word_count = document
        .select(&body_selector)
        .next()
        .map(|element| element.text().collect::<String>().split_whitespace().count())
        .unwrap_or_else(|| {
            if verbose {
                eprintln!("No body element found in HTML");
            }
            0
        });
    
    let title = document
        .select(&title_selector)
        .next()
        .map(|element| element.text().collect::<String>().trim().to_string())
        .unwrap_or_else(|| {
            if verbose {
                eprintln!("No title element found in HTML");
            }
            String::new()
        });

    (word_count, title)
}

async fn calculate_word_count(client: &Client, url: &str, host: Option<&str>, verbose: bool) -> usize {
    let mut request = client
        .get(url)
        .header("User-Agent", "Mozilla/5.0 (compatible; sorted-vhost/1.0)")
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .header("Connection", "keep-alive");
    if let Some(host) = host {
        request = request.header("Host", host);
    }
    if let Ok(response) = request.send().await {
        let is_html = response
            .headers()
            .get("Content-Type")
            .map(|ct| ct.to_str().unwrap_or("").contains("text/html"))
            .unwrap_or(false);
        if is_html {
            if let Ok(body) = response.text().await {
                let (word_count, _) = calculate_word_count_and_title(&body, verbose).await;
                return word_count;
            }
        }
    }
    0
}

fn is_valid_status(status: u16) -> bool {
    status < 400 || status == 401 || status == 0
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let matches = Command::new("sorted-vhost")
        .version("1.0")
        .about("Check virtual hosts and filter unique responses")
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("FILE")
                .help("Input file with host and URL pairs")
                .required(true),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file for filtered results")
                .required(true),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("concurrency")
                .short('c')
                .long("concurrency")
                .value_name("NUM")
                .help("Number of concurrent requests")
                .default_value("100"),
        )
        .get_matches();

    let input_path = matches.get_one::<String>("input").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();
    let verbose = matches.get_flag("verbose");
    let concurrency: usize = matches
        .get_one::<String>("concurrency")
        .unwrap()
        .parse()
        .unwrap_or(100)
        .min(500); // Lower cap to 500

    if concurrency > 500 && verbose {
        eprintln!("Warning: Concurrency capped at 500 to prevent resource exhaustion.");
    }

    configure_system(verbose)?;

    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(3)) // Reduced timeout
        .build()
        .expect("Failed to build HTTP client");
    let client = Arc::new(client);

    let file = File::open(input_path)?;
    let reader = BufReader::new(file);
    let mut tasks = vec![];
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut results = vec![];

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let host = parts[0].to_string();
        let url = parts[1].to_string();
        let client = Arc::clone(&client);
        let semaphore = Arc::clone(&semaphore);
        let https_url = format!("https://{}", host);
        let http_url = format!("http://{}", host);
        let task = task::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let a_https = send_request(&client, https_url.clone(), None, verbose);
            let b = send_request(&client, url.clone(), None, verbose);
            let c = send_request(&client, url.clone(), Some(&host), verbose);
            let (a_https_result, b_result, c_result) = tokio::join!(a_https, b, c);
            let a_result = if a_https_result.status_code == 0 {
                send_request(&client, http_url, None, verbose).await
            } else {
                a_https_result
            };
            (host, url, a_result, b_result, c_result)
        });
        tasks.push(task);
    }

    for task in tasks {
        if let Ok((host, url, a_result, b_result, c_result)) = task.await {
            results.push((host, url, a_result, b_result, c_result));
        }
    }

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)?;
    let mut output_file = BufWriter::new(file);
    let mut seen = HashSet::new();

    for (_host, _url, mut a_result, mut b_result, mut c_result) in results {
        let mut a_key = (a_result.status_code, a_result.content_length, a_result.word_count);
        let mut b_key = (b_result.status_code, b_result.content_length, b_result.word_count);
        let c_key = (c_result.status_code, c_result.content_length, c_result.word_count);

        if verbose {
            if let Some(error) = &a_result.error {
                println!("Error for A ({}): {}", a_result.url, error);
            }
            if let Some(error) = &b_result.error {
                println!("Error for B ({}): {}", b_result.url, error);
            }
            if let Some(error) = &c_result.error {
                println!("Error for C ({}): {}", c_result.url, error);
            }
        }

        if c_key.0 != a_key.0 || c_key.0 != b_key.0 || c_key.1 != a_key.1 || c_key.1 != b_key.1 {
            // Calculate word counts for A and B only if C differs in status or content length
            if a_result.status_code < 400 || a_result.status_code == 401 {
                a_result.word_count = calculate_word_count(&client, &a_result.url, None, verbose).await;
            }
            if b_result.status_code < 400 || b_result.status_code == 401 {
                b_result.word_count = calculate_word_count(&client, &b_result.url, None, verbose).await;
            }
            a_key = (a_result.status_code, a_result.content_length, a_result.word_count);
            b_key = (b_result.status_code, b_result.content_length, b_result.word_count);

            if c_key != a_key && c_key != b_key && is_valid_status(c_result.status_code) {
                let mut title = String::new();
                // Fetch C response for word count and title
                let response = client
                    .get(&c_result.url)
                    .header("Host", &c_result.host)
                    .header("User-Agent", "Mozilla/5.0 (compatible; sorted-vhost/1.0)")
                    .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                    .header("Connection", "keep-alive")
                    .send()
                    .await;
                if let Ok(response) = response {
                    let is_html = response
                        .headers()
                        .get("Content-Type")
                        .map(|ct| ct.to_str().unwrap_or("").contains("text/html"))
                        .unwrap_or(false);
                    if is_html && c_result.content_length < 500_000 { // Reduced cap
                        if let Ok(body) = response.text().await {
                            let (word_count, extracted_title) = calculate_word_count_and_title(&body, verbose).await;
                            c_result.word_count = word_count;
                            title = extracted_title;
                        }
                    }
                }

                let key = format!("{}-{}", c_result.status_code, c_result.content_length);
                if !seen.contains(&key) {
                    seen.insert(key);
                    writeln!(output_file, "{}", c_result.to_debug_format(&a_result, &b_result, &title))?;
                    if verbose {
                        println!(
                            "Unique C: {} (A: {} CL:{} WC:{}, B: {} CL:{} WC:{}, C: {} CL:{} WC:{}) \"{}\"",
                            c_result.to_tabular(),
                            a_result.status_code, a_result.content_length, a_result.word_count,
                            b_result.status_code, b_result.content_length, b_result.word_count,
                            c_result.status_code, c_result.content_length, c_result.word_count,
                            title
                        );
                    }
                } else if verbose {
                    println!("Skipped (duplicate key): {}", c_result.to_tabular());
                }
            } else if verbose {
                println!(
                    "Skipped: {} (A: {} CL:{} WC:{}, B: {} CL:{} WC:{}, C: {} CL:{} WC:{})",
                    c_result.to_tabular(),
                    a_result.status_code, a_result.content_length, a_result.word_count,
                    b_result.status_code, b_result.content_length, b_result.word_count,
                    c_result.status_code, c_result.content_length, c_result.word_count
                );
            }
        } else if verbose {
            println!(
                "Skipped: {} (A: {} CL:{} WC:{}, B: {} CL:{} WC:{})",
                c_result.to_tabular(),
                a_result.status_code, a_result.content_length, a_result.word_count,
                b_result.status_code, b_result.content_length, b_result.word_count
            );
        }
    }

    output_file.flush()?;
    Ok(())
}
