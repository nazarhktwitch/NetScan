use std::fs::{self, File};
use std::io::{self, Write};
use async_std::task;
use async_std::net::TcpStream;
use futures::stream::{self, StreamExt};
use serde_json::json;
use async_tls::TlsConnector;
use http_types::Request;
use clap::Parser;

const MAX_CONCURRENT_SCANS: usize = 100;

#[derive(Debug)]
struct ScanResult {
    port: u16,
    status: String,
    headers: Option<String>,
    ssl_certificate: Option<String>,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Target address to scan
    #[clap(short, long)]
    target: String,

    /// Comma-separated list of ports to scan
    #[clap(short, long)]
    ports: String,
}

async fn scan_port(address: &str, port: u16) -> ScanResult {
    let target = format!("{}:{}", address, port);
    match TcpStream::connect(&target).await {
        Ok(stream) => {
            // Attempt SSL handshake if the port is commonly used for SSL
            let ssl_certificate = if port == 443 {
                let connector = TlsConnector::default();
                match connector.connect(address, stream).await {
                    Ok(_) => Some("Valid SSL certificate".to_string()),
                    Err(_) => Some("Failed SSL certificate check".to_string()),
                }
            } else {
                None
            };

            // Fetch HTTP headers if the port is 80 or 443
            let headers = if port == 80 || port == 443 {
                let url = format!("http://{}", address);
                match fetch_http_headers(&url).await {
                    Ok(headers) => Some(headers),
                    Err(_) => Some("Failed to fetch headers".to_string()),
                }
            } else {
                None
            };

            ScanResult {
                port,
                status: "Open".to_string(),
                headers,
                ssl_certificate,
            }
        }
        Err(_) => ScanResult {
            port,
            status: "Closed".to_string(),
            headers: None,
            ssl_certificate: None,
        },
    }
}

async fn fetch_http_headers(url: &str) -> Result<String, http_types::Error> {
    let req = Request::new(http_types::Method::Get, url.parse::<http_types::Url>().unwrap());
    let stream = TcpStream::connect("example.com:80").await?;
    let response = async_h1::connect(stream, req).await?;
    let headers = response
        .header_names()
        .map(|name| {
            let value = response.header(name).unwrap();
            format!("{}: {}", name, value)
        })
        .collect::<Vec<String>>()
        .join("\n");
    Ok(headers)
}

async fn scan_ports(address: &str, ports: Vec<u16>) -> Vec<ScanResult> {
    stream::iter(ports)
        .map(|port| scan_port(address, port))
        .buffer_unordered(MAX_CONCURRENT_SCANS)
        .collect()
        .await
}

fn save_report_csv(results: &[ScanResult], filename: &str) -> io::Result<()> {
    let mut file = File::create(filename)?;
    writeln!(file, "port,status,headers,ssl_certificate")?;
    for result in results {
        writeln!(
            file,
            "{},{},'{}','{}'",
            result.port,
            result.status,
            result.headers.clone().unwrap_or_default(),
            result.ssl_certificate.clone().unwrap_or_default()
        )?;
    }
    Ok(())
}

fn save_report_json(results: &[ScanResult], filename: &str) -> io::Result<()> {
    let json_results: Vec<_> = results
        .iter()
        .map(|result| {
            json!({
                "port": result.port,
                "status": result.status,
                "headers": result.headers,
                "ssl_certificate": result.ssl_certificate
            })
        })
        .collect();
    let json_data = serde_json::to_string_pretty(&json_results)?;
    fs::write(filename, json_data)
}

fn parse_ports(input: &str) -> Vec<u16> {
    input
        .split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .collect()
}

fn main() {
    loop {
        println!("Enter the target address (or type 'exit' to quit):");
        let mut target = String::new();
        io::stdin().read_line(&mut target).expect("Failed to read input");
        let target = target.trim();
        
        if target.eq_ignore_ascii_case("exit") {
            break;
        }

        println!("Enter comma-separated ports to scan (e.g., 80,443,8080):");
        let mut ports_input = String::new();
        io::stdin().read_line(&mut ports_input).expect("Failed to read input");
        let ports = parse_ports(&ports_input);

        if ports.is_empty() {
            println!("No valid ports provided.");
            continue;
        }

        let results = task::block_on(scan_ports(target, ports));

        for result in &results {
            println!("Port {}: {}", result.port, result.status);
            if let Some(headers) = &result.headers {
                println!("Headers: {}", headers);
            }
            if let Some(ssl_certificate) = &result.ssl_certificate {
                println!("SSL Certificate: {}", ssl_certificate);
            }
        }

        // Save reports
        if let Err(e) = save_report_csv(&results, "scan_report.csv") {
            eprintln!("Error saving CSV report: {}", e);
        } else {
            println!("CSV report saved as scan_report.csv");
        }

        if let Err(e) = save_report_json(&results, "scan_report.json") {
            eprintln!("Error saving JSON report: {}", e);
        } else {
            println!("JSON report saved as scan_report.json");
        }
    }
}
