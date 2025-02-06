mod gui;

use env_logger::{Builder, Target};
use log::LevelFilter;
use std::fs::File;
use chrono::Local;
use std::io::Write;

const SHOW_CONSOLE: bool = false;

#[cfg(target_os = "windows")]
extern crate winapi;

#[cfg(target_os = "windows")]
use winapi::um::wincon::FreeConsole;

fn setup_logger() -> Result<(), Box<dyn std::error::Error>> {
    // Create logs directory if it doesn't exist
    std::fs::create_dir_all("logs")?;

    let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S");
    let log_file = File::create(format!("logs/netscan_{}.log", timestamp))?;

    Builder::new()
        .target(Target::Pipe(Box::new(log_file)))
        .filter_level(LevelFilter::Info)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )?;
            Ok(())
        })
        .init();

    Ok(())
}

fn main() {
    // Initialize logging first
    if let Err(e) = setup_logger() {
        eprintln!("Failed to setup logger: {}", e);
    }

    #[cfg(target_os = "windows")]
    if !SHOW_CONSOLE {
        unsafe {
            FreeConsole();
        }
    }

    let options = eframe::NativeOptions::default();
    if let Err(e) = eframe::run_native(
        "Port Scanner",
        options,
        Box::new(|_cc| Ok(Box::new(gui::PortScannerApp::default()))),
    ) {
        log::error!("Application error: {}", e);
    }
}
