use std::io::{self, Write};
use std::sync::mpsc;

use crate::ops::{detect_environment, run_install, InstallConfig, InstallMode, ProgressMsg};

pub fn run_cli(auto_yes: bool, force_console: bool) -> anyhow::Result<()> {
    let env_info = detect_environment();
    println!("================================================");
    println!("       AEGIS-GUARD INSTALLER v1.2.0 (CLI)       ");
    println!("================================================");
    println!(
        "Platform: {} ({}) | Target: {}",
        env_info.os,
        env_info.arch,
        env_info.default_install_dir.display()
    );

    if !auto_yes {
        print!("Proceed with installation? [Y/n]: ");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        if line.trim().eq_ignore_ascii_case("n") {
            println!("Installation cancelled.");
            return Ok(());
        }
    }

    let mode = if force_console || !env_info.has_cargo {
        InstallMode::Console
    } else {
        InstallMode::Desktop
    };

    let cfg = InstallConfig {
        mode,
        install_dir: env_info.default_install_dir,
        create_shortcuts: true,
        setup_services: env_info.is_elevated,
        configure_firewall: env_info.is_elevated,
    };

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || run_install(cfg, tx));

    let mut ok = false;
    while let Ok(msg) = rx.recv() {
        match msg {
            ProgressMsg::Step { index, total, title } => {
                println!("\n[{}/{}] {}", index, total, title);
            }
            ProgressMsg::Log(line) => println!("  {}", line),
            ProgressMsg::Finished {
                success, summary, ..
            } => {
                ok = success;
                println!("\n{}", summary);
                break;
            }
        }
    }

    if !ok {
        anyhow::bail!("Installation failed");
    }
    Ok(())
}
