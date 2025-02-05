mod gui;

#[cfg(target_os = "windows")]
extern crate winapi;

#[cfg(target_os = "windows")]
use winapi::um::wincon::FreeConsole;

fn main() {
    #[cfg(target_os = "windows")]
    unsafe {
        FreeConsole();
    }

    let options = eframe::NativeOptions::default();
    if let Err(e) = eframe::run_native(
        "Port Scanner",
        options,
        Box::new(|_cc| Ok(Box::new(gui::PortScannerApp::default()))),
    ) {
        eprintln!("Error: {}", e);
    }
}
