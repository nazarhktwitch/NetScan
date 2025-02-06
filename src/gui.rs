use eframe::egui;
use async_std::task;
use async_std::net::TcpStream;
use futures::stream::{self, StreamExt};
use serde_json::json;
use async_tls::TlsConnector;
use http_types::Request;
use std::fs::{self, File};
use std::io::{self, Write};
use serde::{Deserialize, Serialize};
use chrono::Local;
use log::{info, error};
use async_std::future::timeout;
use std::time::Duration;

const DEFAULT_MAX_CONCURRENT_SCANS: usize = 100;
const DEFAULT_PORTS: &str = "80";

#[derive(Serialize, Deserialize)]
struct Config {
    max_concurrent_scans: usize,
    save_csv: bool,
    save_json: bool,
    last_target: String,
    last_ports: String,
    enable_timeouts: bool,
    timeout_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_concurrent_scans: DEFAULT_MAX_CONCURRENT_SCANS,
            save_csv: false,
            save_json: false,
            last_target: String::new(),
            last_ports: String::new(),
            enable_timeouts: true,
            timeout_seconds: 5,
        }
    }
}

#[derive(Debug)]
struct ScanResult {
    port: u16,
    status: String,
    headers: Option<String>,
    ssl_certificate: Option<String>,
}

pub struct PortScannerApp {
    target: String,
    ports: String,
    results: Vec<ScanResult>,
    error_message: Option<String>,
    save_csv: bool,
    save_json: bool,
    max_concurrent_scans: usize,
    enable_timeouts: bool,
    timeout_seconds: u64,
}

impl Default for PortScannerApp {
    fn default() -> Self {
        Self::create_logs_directory();

        let config = match fs::read_to_string("config.json") {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(config) => config,
                Err(e) => {
                    error!("Failed to parse config.json: {}", e);
                    Config::default()
                }
            },
            Err(e) => {
                error!("Failed to read config.json: {}", e);
                Config::default()
            }
        };

        let target = if config.last_target.is_empty() {
            "http://localhost".to_string()
        } else {
            config.last_target.clone()
        };

        let ports = if config.last_ports.is_empty() {
            DEFAULT_PORTS.to_string()
        } else {
            config.last_ports.clone()
        };

        Self {
            target,
            ports,
            results: Vec::new(),
            error_message: None,
            save_csv: config.save_csv,
            save_json: config.save_json,
            max_concurrent_scans: config.max_concurrent_scans,
            enable_timeouts: config.enable_timeouts,
            timeout_seconds: config.timeout_seconds,
        }
    }
}

impl PortScannerApp {
    fn create_logs_directory() {
        if !std::path::Path::new("logs").exists() {
            if let Err(e) = fs::create_dir("logs") {
                error!("Failed to create logs directory: {}", e);
            }
        }
    }
    fn save_config(&self) {
        let config = Config {
            max_concurrent_scans: self.max_concurrent_scans,
            save_csv: self.save_csv,
            save_json: self.save_json,
            last_target: self.target.clone(),
            last_ports: self.ports.clone(),
            enable_timeouts: self.enable_timeouts,
            timeout_seconds: self.timeout_seconds,
        };

        if let Err(e) = fs::write(
            "config.json",
            serde_json::to_string_pretty(&config).unwrap(),
        ) {
            error!("Failed to save config: {}", e);
        }
    }

    fn save_log(&self, message: &str) {
        let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S");
        let filename = format!("logs/scan_{}.log", timestamp);
        if let Err(e) = fs::write(&filename, message) {
            error!("Failed to save log: {}", e);
        }
    }

    async fn scan_ports(&mut self) {
        let ports = self.parse_ports();
        if ports.is_empty() {
            self.error_message = Some("No valid ports provided.".to_string());
            return;
        }

        info!("Starting scan for {} with ports {:?}", self.target, ports);
        self.results = Self::perform_scan(&self.target, ports, self.max_concurrent_scans, self.enable_timeouts, self.timeout_seconds).await;
        self.error_message = None;

        self.log_results();
        self.save_reports().await;
    }

    fn log_results(&self) {
        let log_message = format!(
            "Scan Results for {}\n{}\n",
            self.target,
            self.results
                .iter()
                .map(|r| format!(
                    "Port {}: {}\nHeaders: {}\nSSL: {}\n",
                    r.port,
                    r.status,
                    r.headers.as_deref().unwrap_or("None"),
                    r.ssl_certificate.as_deref().unwrap_or("None")
                ))
                .collect::<Vec<_>>()
                .join("\n")
        );
        self.save_log(&log_message);
    }

    async fn save_reports(&mut self) {
        if self.save_csv {
            if let Err(e) = self.save_report_csv("scan_report.csv") {
                self.error_message = Some(format!("Error saving CSV report: {}", e));
            }
        }

        if self.save_json {
            if let Err(e) = self.save_report_json("scan_report.json") {
                self.error_message = Some(format!("Error saving JSON report: {}", e));
            }
        }
    }

    async fn perform_scan(address: &str, ports: Vec<u16>, max_concurrent: usize, enable_timeouts: bool, timeout_seconds: u64) -> Vec<ScanResult> {
        stream::iter(ports)
            .map(|port| Self::scan_port(address, port, enable_timeouts, timeout_seconds))
            .buffer_unordered(max_concurrent)
            .collect()
            .await
    }

    async fn scan_port(address: &str, port: u16, enable_timeouts: bool, timeout_seconds: u64) -> ScanResult {
        let clean_address = Self::clean_address(address);
        info!("Scanning {}:{}", clean_address, port);

        let stream = match Self::connect_to_port(&clean_address, port, enable_timeouts, timeout_seconds).await {
            Some(stream) => stream,
            None => return ScanResult {
                port,
                status: "Closed".to_string(),
                headers: None,
                ssl_certificate: None,
            },
        };

        let ssl_certificate = Self::check_ssl_certificate(&clean_address, port, stream.clone(), enable_timeouts, timeout_seconds).await;
        let headers = Self::fetch_headers_if_needed(&clean_address, port, enable_timeouts, timeout_seconds).await;

        ScanResult {
            port,
            status: "Open".to_string(),
            headers,
            ssl_certificate,
        }
    }

    fn clean_address(address: &str) -> String {
        let without_http = address.replace("http://", "");
        let without_https = without_http.replace("https://", "");
        without_https.split('/').next().unwrap_or(address).to_string()
    }

    async fn connect_to_port(clean_address: &str, port: u16, enable_timeouts: bool, timeout_seconds: u64) -> Option<TcpStream> {
        let connect_future = TcpStream::connect(format!("{}:{}", clean_address, port));
        if enable_timeouts {
            match timeout(Duration::from_secs(timeout_seconds), connect_future).await {
                Ok(Ok(stream)) => Some(stream),
                Ok(Err(e)) => {
                    info!("Port {} closed: {}", port, e);
                    None
                }
                Err(_) => {
                    info!("Port {} timeout", port);
                    None
                }
            }
        } else {
            match connect_future.await {
                Ok(stream) => Some(stream),
                Err(e) => {
                    info!("Port {} closed: {}", port, e);
                    None
                }
            }
        }
    }

    async fn check_ssl_certificate(clean_address: &str, port: u16, stream: TcpStream, enable_timeouts: bool, timeout_seconds: u64) -> Option<String> {
        if port == 443 {
            let connector = TlsConnector::default();
            let ssl_future = connector.connect(clean_address, stream);
            if enable_timeouts {
                match timeout(Duration::from_secs(timeout_seconds), ssl_future).await {
                    Ok(Ok(_)) => Some("Valid SSL certificate".to_string()),
                    Ok(Err(e)) => Some(format!("SSL Error: {}", e)),
                    Err(_) => Some("SSL check timeout".to_string()),
                }
            } else {
                match ssl_future.await {
                    Ok(_) => Some("Valid SSL certificate".to_string()),
                    Err(e) => Some(format!("SSL Error: {}", e)),
                }
            }
        } else {
            None
        }
    }

    async fn fetch_headers_if_needed(clean_address: &str, port: u16, enable_timeouts: bool, timeout_seconds: u64) -> Option<String> {
        if port == 80 || port == 443 {
            let protocol = if port == 443 { "https" } else { "http" };
            let url = format!("{}://{}", protocol, clean_address);
            let headers_future = Self::fetch_http_headers(&url);
            if enable_timeouts {
                match timeout(Duration::from_secs(timeout_seconds), headers_future).await {
                    Ok(Ok(headers)) => Some(headers),
                    Ok(Err(e)) => Some(format!("Headers Error: {}", e)),
                    Err(_) => Some("Headers fetch timeout".to_string()),
                }
            } else {
                match headers_future.await {
                    Ok(headers) => Some(headers),
                    Err(e) => Some(format!("Headers Error: {}", e)),
                }
            }
        } else {
            None
        }
    }
    
    async fn fetch_http_headers(url: &str) -> Result<String, http_types::Error> {
        let parsed_url = url.parse::<http_types::Url>().unwrap();
        let host = match parsed_url.host_str() {
            Some(host) => host,
            None => return Err(http_types::Error::from_str(http_types::StatusCode::BadRequest, "Invalid URL: missing host")),
        };
        let port = parsed_url.port_or_known_default().unwrap_or(80);
        
        info!("Fetching headers for {}:{}", host, port);
    
        let mut req = Request::new(http_types::Method::Get, parsed_url.clone());
        req.insert_header("Host", host);
        
        let stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
        let response = async_h1::connect(stream, req).await?;
        
        Ok(response
            .header_names()
            .map(|name| format!("{}: {}", name, response.header(name).unwrap()))
            .collect::<Vec<_>>()
            .join("\n"))
    }

    fn parse_ports(&self) -> Vec<u16> {
        self.ports
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect()
    }

    fn save_report_csv(&self, filename: &str) -> io::Result<()> {
        let mut file = File::create(filename)?;
        writeln!(file, "port,status,headers,ssl_certificate")?;
        for result in &self.results {
            let headers = result.headers.as_deref().unwrap_or("").replace(",", ";");
            let ssl = result.ssl_certificate.as_deref().unwrap_or("").replace(",", ";");
            writeln!(
                file,
                "{},{},\"{}\",\"{}\"",
                result.port, result.status, headers, ssl
            )?;
        }
        Ok(())
    }

    fn save_report_json(&self, filename: &str) -> io::Result<()> {
        let json_results: Vec<_> = self
            .results
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
        fs::write(filename, serde_json::to_string_pretty(&json_results)?)
    }
}

impl eframe::App for PortScannerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Port Scanner");

            ui.horizontal(|ui| {
                ui.label("Target:");
                ui.text_edit_singleline(&mut self.target);
            });

            ui.horizontal(|ui| {
                ui.label("Ports (comma-separated):");
                ui.text_edit_singleline(&mut self.ports);
            });

            ui.horizontal(|ui| {
                ui.label("Max concurrent scans:");
                ui.add(egui::DragValue::new(&mut self.max_concurrent_scans)
                    .range(1..=1000));
            });

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.enable_timeouts, "Enable timeouts");
                if self.enable_timeouts {
                    ui.add(egui::DragValue::new(&mut self.timeout_seconds)
                        .range(1..=30)
                        .prefix("Timeout: ")
                        .suffix(" sec"));
                }
            });

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.save_csv, "Save CSV");
                ui.checkbox(&mut self.save_json, "Save JSON");
            });

            if ui.button("Scan").clicked() {
                let target = if !self.target.starts_with("http://") && !self.target.starts_with("https://") {
                    format!("http://{}", self.target)
                } else {
                    self.target.clone()
                };
                let ports = self.ports.clone();
                let save_csv = self.save_csv;
                let save_json = self.save_json;
                let mut app = PortScannerApp::default();
                app.enable_timeouts = self.enable_timeouts;
                app.timeout_seconds = self.timeout_seconds;
                app.target = target;
                app.ports = ports;
                app.save_csv = save_csv;
                app.save_json = save_json;
                app.max_concurrent_scans = self.max_concurrent_scans;
                task::block_on(app.scan_ports());
                self.results = app.results;
                self.error_message = app.error_message;
                self.save_config();
            }

            if !self.results.is_empty() {
                ui.heading("Results:");
                for result in &self.results {
                    ui.label(format!("Port {}: {}", result.port, result.status));
                    if let Some(headers) = &result.headers {
                        ui.label(format!("Headers: {}", headers));
                    }
                    if let Some(ssl_certificate) = &result.ssl_certificate {
                        ui.label(format!("SSL Certificate: {}", ssl_certificate));
                    }
                }
            }

            if let Some(error) = &self.error_message {
                ui.colored_label(egui::Color32::RED, error);
            }
        });
    }
}
