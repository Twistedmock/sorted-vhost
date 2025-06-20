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
use url::Url;

#[derive(Serialize, Deserialize, Clone)]
struct RequestResult {
    host: String,
    url: String,
    status_code: u16,
    content_length: u64,
    word_count: usize,
    error: Option<String>,
    location: Option<String>,
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
        let location = self.location.as_deref().map(|l| format!("Location: {}", l)).unwrap_or_default();
        format!(
            "{} {} {} {} {} (A: {} CL:{} WC:{}, B: {} CL:{} WC:{}, C: {} CL:{} WC:{}) \"{}\" \"{}\"",
            self.host,
            self.url,
            self.status_code,
            self.content_length,
            self.word_count,
            a_result.status_code, a_result.content_length, a_result.word_count,
            b_result.status_code, b_result.content_length, b_result.word_count,
            self.status_code, self.content_length, self.word_count,
            title,
            location
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
    let mut request = client
        .get(&url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
        .header("Accept-Language", "en-US,en;q=0.5")
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
            let location = if status >= 300 && status < 400 {
                response
                    .headers()
                    .get("Location")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from)
            } else {
                None
            };
            RequestResult {
                host: host.unwrap_or("").to_string(),
                url,
                status_code: status,
                content_length,
                word_count: 0,
                error: None,
                location,
            }
        }
        Err(e) => {
            let error = e.to_string();
            if verbose {
                eprintln!("Request to {} failed: {}", url, error);
            }
            RequestResult {
                host: host.unwrap_or("").to_string(),
                url,
                status_code: 0,
                content_length: 0,
                word_count: 0,
                error: Some(error),
                location: None,
            }
        }
    }
}

fn get_apex_domain(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|u| u.domain().map(|d| d.to_string()))
        .and_then(|d| {
            let parts: Vec<&str> = d.split('.').collect();
            if parts.len() >= 2 {
                Some(format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]))
            } else {
                None
            }
        })
}

async fn follow_redirect(client: &Client, base_url: &str, location: &str, host: &str, verbose: bool) -> RequestResult {
    let redirect_url = match Url::parse(location) {
        Ok(url) => url.to_string(),
        Err(_) => {
            match Url::parse(base_url).and_then(|base| base.join(location)) {
                Ok(url) => url.to_string(),
                Err(e) => {
                    if verbose {
                        eprintln!("Failed to parse redirect URL {} from base {}: {}", location, base_url, e);
                    }
                    return RequestResult {
                        host: host.to_string(),
                        url: location.to_string(),
                        status_code: 0,
                        content_length: 0,
                        word_count: 0,
                        error: Some(e.to_string()),
                        location: None,
                    };
                }
            }
        }
    };

    let is_full_url = redirect_url.starts_with("http://") || redirect_url.starts_with("https://");
    let base_apex = get_apex_domain(base_url);
    let redirect_apex = get_apex_domain(&redirect_url);
    let is_same_site = base_apex.is_some() && redirect_apex.is_some() && base_apex == redirect_apex;

    let redirect_result = send_request(client, redirect_url.clone(), None, verbose).await;

    if is_full_url && redirect_result.status_code != 200 {
        return RequestResult {
            host: host.to_string(),
            url: redirect_url,
            status_code: 998, // Non-accessible full URL
            content_length: 0,
            word_count: 0,
            error: None,
            location: None,
        };
    }

    if redirect_result.status_code == 200 && is_same_site {
        return RequestResult {
            host: host.to_string(),
            url: redirect_url,
            status_code: 999, // Same-site 200
            content_length: 0,
            word_count: 0,
            error: None,
            location: None,
        };
    }

    redirect_result
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
        .min(500);

    if concurrency > 500 && verbose {
        eprintln!("Warning: Concurrency capped at 500 to prevent resource exhaustion.");
    }

    configure_system(verbose)?;

    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
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
            let a_https = send_request(&client, https_url.clone(), None, verbose).await;
            let mut a_result = a_https;
            if a_result.status_code >= 300 && a_result.status_code < 400 {
                if let Some(location) = &a_result.location {
                    a_result = follow_redirect(&client, &https_url, location, &host, verbose).await;
                }
            } else if a_result.status_code == 0 {
                a_result = send_request(&client, http_url, None, verbose).await;
            }

            let b = send_request(&client, url.clone(), None, verbose);
            let c = send_request(&client, url.clone(), Some(&host), verbose);
            let (b_result, c_result) = tokio::join!(b, c);
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

    for (_host, _url, a_result, b_result, mut c_result) in results {
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

        // Skip if A is 429
        if a_result.status_code == 429 {
            if verbose {
                println!(
                    "Skipped (A status 429): {} (A: {} CL:{} WC:{}, B: {} CL:{} WC:{}, C: {} CL:{} WC:{})",
                    c_result.to_tabular(),
                    a_result.status_code, a_result.content_length, a_result.word_count,
                    b_result.status_code, b_result.content_length, b_result.word_count,
                    c_result.status_code, c_result.content_length, c_result.word_count
                );
            }
            continue;
        }

        // Skip if A redirect resulted in 200 on same site or non-accessible full URL
        if a_result.status_code == 999 || a_result.status_code == 998 {
            if verbose {
                let reason = if a_result.status_code == 999 {
                    "A redirect to 200 on same site"
                } else {
                    "A redirect to non-accessible full URL"
                };
                println!(
                    "Skipped ({}): {} (A: {} CL:{} WC:{}, B: {} CL:{} WC:{}, C: {} CL:{} WC:{})",
                    reason,
                    c_result.to_tabular(),
                    a_result.status_code, a_result.content_length, a_result.word_count,
                    b_result.status_code, b_result.content_length, b_result.word_count,
                    c_result.status_code, c_result.content_length, c_result.word_count
                );
            }
            continue;
        }

        let mut title = String::new();
        // Fetch C response for word count and title
        if c_result.status_code != a_result.status_code && c_result.status_code != b_result.status_code && is_valid_status(c_result.status_code) {
            let response = client
                .get(&c_result.url)
                .header("Host", &c_result.host)
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
                .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                .header("Accept-Language", "en-US,en;q=0.5")
                .header("Connection", "keep-alive")
                .send()
                .await;
            if let Ok(response) = response {
                let is_html = response
                    .headers()
                    .get("Content-Type")
                    .map(|ct| ct.to_str().unwrap_or("").contains("text/html"))
                    .unwrap_or(false);
                if is_html && c_result.content_length < 500_000 {
                    if let Ok(body) = response.text().await {
                        let (word_count, extracted_title) = calculate_word_count_and_title(&body, verbose).await;
                        c_result.word_count = word_count;
                        title = extracted_title;

                        // Skip if title matches specific values
                        if title == "Request Rejected" || title == "Site en construction" || title == "Welcome to nginx!" || title == "Access Denied" {
                            if verbose {
                                println!(
                                    "Skipped (title '{}'): {} (A: {} CL:{} WC:{}, B: {} CL:{} WC:{}, C: {} CL:{} WC:{})",
                                    title,
                                    c_result.to_tabular(),
                                    a_result.status_code, a_result.content_length, a_result.word_count,
                                    b_result.status_code, b_result.content_length, b_result.word_count,
                                    c_result.status_code, c_result.content_length, c_result.word_count
                                );
                            }
                            continue;
                        }
                    }
                }
            }

            // Skip if C is 3xx with non-accessible full URL
            if c_result.status_code >= 300 && c_result.status_code < 400 && c_result.location.is_some() {
                let location = c_result.location.as_ref().unwrap();
                let is_full_url = location.starts_with("http://") || location.starts_with("https://");
                if is_full_url {
                    let redirect_result = send_request(&client, location.clone(), None, verbose).await;
                    if redirect_result.status_code != 200 {
                        if verbose {
                            println!(
                                "Skipped (C redirect to non-accessible full URL): {} (A: {} CL:{} WC:{}, B: {} CL:{} WC:{}, C: {} CL:{} WC:{})",
                                c_result.to_tabular(),
                                a_result.status_code, a_result.content_length, a_result.word_count,
                                b_result.status_code, b_result.content_length, b_result.word_count,
                                c_result.status_code, c_result.content_length, c_result.word_count
                            );
                        }
                        continue;
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
    }

    output_file.flush()?;
    Ok(())
}
