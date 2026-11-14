#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

mod cli;
mod gui;
mod ops;

use ops::InstallMode;

fn has_graphical_display() -> bool {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        true
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
    }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let force_cli = args.iter().any(|a| a == "--cli" || a == "--headless");
    let force_gui = args.iter().any(|a| a == "--gui");
    let auto_yes = args.iter().any(|a| a == "--yes" || a == "-y");
    let force_console = args.iter().any(|a| a == "--console");

    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Aegis-Guard v1.2.0 Cross-Platform GTK Installer");
        println!("Usage: aegis-installer [--gui | --cli] [--desktop | --console] [--yes]");
        return Ok(());
    }

    if !force_cli && (force_gui || has_graphical_display()) {
        let mode = if force_console {
            InstallMode::Console
        } else {
            InstallMode::Desktop
        };
        gui::run_gui(mode)
    } else {
        cli::run_cli(auto_yes, force_console)
    }
}
