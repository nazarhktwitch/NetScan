# NetScan

NetScan is a SIMPLIEST tool for port scanning. It allows you to scan ports on remote addresses, check their status (open/closed). The scan results can be saved in CSV or JSON format.

## Features

- **Port Scanning**: Check the status of ports on a remote address.
- **Reports**: Generate reports in CSV and JSON formats.

## Requirements

- Rust (version 1.50 or higher)
- Dependencies:
  - async-std
  - async-tls
  - serde
  - serde_json
  - http-types

## Installation

You can download [pre-built version](https://github.com/nazarhktwitch/NetScan/releases)

1. Clone this repository:

   ```bash
   git clone https://github.com/nazarhktwitch/NetScan
   cd NetScan
   ```

2. Build the project:
   
   ```bash
   cargo build --release
   ```

4. The compiled binary will be available in the `target/debug/` directory.

## Usage

1. Run the program
2. Enter the target address (USE HTTP/HTTPS PREFIX!) (e.g., `https://example.com`).
3. Enter a comma-separated list of ports to scan (e.g., `80,443,8080`).

   - The program will scan each specified port and check if it's open, along with verifying SSL certificates for port 443 and fetching HTTP headers for ports 80 and 443.

4. After the scan completes, the results will be displayed, and reports will be saved in both CSV and JSON formats.

   - The CSV report will be saved as `scan_report.csv`.
   - The JSON report will be saved as `scan_report.json`.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/nazarhktwitch/NetScan/blob/main/LICENSE) file for details.
