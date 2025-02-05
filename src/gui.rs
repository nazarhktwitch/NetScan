use eframe::egui;
use async_std::task;
use async_std::net::TcpStream;
use futures::stream::{self, StreamExt};
use serde_json::json;
use async_tls::TlsConnector;
use http_types::Request;
use std::fs::{self, File};
use std::io::{self, Write};

const MAX_CONCURRENT_SCANS: usize = 100;

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
}

impl Default for PortScannerApp {
    fn default() -> Self {
        Self {
            target: String::new(),
            ports: String::new(),
            results: Vec::new(),
            error_message: None,
            save_csv: false,
            save_json: false,
        }
    }
}

impl PortScannerApp {
    async fn scan_ports(&mut self) {
        let ports = self.parse_ports();
        if ports.is_empty() {
            self.error_message = Some("No valid ports provided.".to_string());
            return;
        }

        self.results = Self::perform_scan(&self.target, ports).await;
        self.error_message = None;

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

    async fn perform_scan(address: &str, ports: Vec<u16>) -> Vec<ScanResult> {
        stream::iter(ports)
            .map(|port| Self::scan_port(address, port))
            .buffer_unordered(MAX_CONCURRENT_SCANS)
            .collect()
            .await
    }

    async fn scan_port(address: &str, port: u16) -> ScanResult {
        let target = format!("{}:{}", address, port);
        match TcpStream::connect(&target).await {
            Ok(stream) => {
                let ssl_certificate = if port == 443 {
                    let connector = TlsConnector::default();
                    match connector.connect(address, stream).await {
                        Ok(_) => Some("Valid SSL certificate".to_string()),
                        Err(_) => Some("Failed SSL certificate check".to_string()),
                    }
                } else {
                    None
                };

                let headers = if port == 80 || port == 443 {
                    let url = format!("http://{}", address);
                    match Self::fetch_http_headers(&url).await {
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
        let json_data = serde_json::to_string_pretty(&json_results)?;
        fs::write(filename, json_data)?;
        Ok(())
    }
}

impl eframe::App for PortScannerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Port Scanner");

            // Input fields
            ui.horizontal(|ui| {
                ui.label("Target:");
                ui.text_edit_singleline(&mut self.target);
            });

            ui.horizontal(|ui| {
                ui.label("Ports (comma-separated):");
                ui.text_edit_singleline(&mut self.ports);
            });

            // Checkboxes for saving reports
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.save_csv, "Save CSV");
                ui.checkbox(&mut self.save_json, "Save JSON");
            });

            // Scan button
            if ui.button("Scan").clicked() {
                let target = self.target.clone();
                let ports = self.ports.clone();
                let save_csv = self.save_csv;
                let save_json = self.save_json;
                let future = async move {
                    let mut app = PortScannerApp::default();
                    app.target = target;
                    app.ports = ports;
                    app.save_csv = save_csv;
                    app.save_json = save_json;
                    app.scan_ports().await;
                    app
                };
                let app = task::block_on(future);
                self.results = app.results;
                self.error_message = app.error_message;
            }

            // Display results
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

            // Display error message
            if let Some(error) = &self.error_message {
                ui.colored_label(egui::Color32::RED, error);
            }
        });
    }
}