// installer/src/main.rs — Aegis-Guard interactive installer
// by Vladimir Unknown
//
// TUI wizard that:
//   1. Detects current OS
//   2. Shows a selection menu (Linux / Windows / macOS)
//   3. Checks prerequisites
//   4. Installs dependencies
//   5. Builds the project
//   6. Sets up system services

use std::io::{self, Write};
use std::process::{Command, Stdio};

// ── ANSI colours ─────────────────────────────────────────────────────────────
const RESET:  &str = "\x1b[0m";
const BOLD:   &str = "\x1b[1m";
const RED:    &str = "\x1b[31m";
const GREEN:  &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN:   &str = "\x1b[36m";
const VIOLET: &str = "\x1b[35m";
const DIM:    &str = "\x1b[2m";

#[derive(Debug, Clone, PartialEq)]
enum Platform { Linux, Windows, MacOs }

#[derive(Debug, Clone, PartialEq)]
enum InstallMode {
    Full,       // Linux: engine + dashboard + network observer
    DashOnly,   // Windows / macOS: dashboard + entropy only
}

struct Config {
    platform: Platform,
    mode:     InstallMode,
    data_dir: String,
}

fn main() -> anyhow::Result<()> {
    clear_screen();
    print_banner();

    let detected = detect_platform();
    let platform = platform_menu(&detected)?;
    let mode     = match platform {
        Platform::Linux   => InstallMode::Full,
        _                 => InstallMode::DashOnly,
    };

    print_platform_note(&platform, &mode);
    confirm_proceed()?;

    let data_dir = ask_data_dir(&platform)?;

    let cfg = Config { platform, mode, data_dir };

    // ── Steps ────────────────────────────────────────────────────────────────
    run_steps(&cfg)?;

    print_success(&cfg);
    Ok(())
}

// ── Banner ────────────────────────────────────────────────────────────────────

fn print_banner() {
    println!("{}{}", VIOLET, BOLD);
    println!("  ╔═══════════════════════════════════════════╗");
    println!("  ║     AEGIS-GUARD  INSTALLER  v0.1.0        ║");
    println!("  ║     by Vladimir Unknown                   ║");
    println!("  ║     Endpoint Security Suite               ║");
    println!("  ╚═══════════════════════════════════════════╝");
    println!("{}", RESET);
}

// ── Platform detection ────────────────────────────────────────────────────────

fn detect_platform() -> Platform {
    if cfg!(target_os = "linux")   { Platform::Linux   }
    else if cfg!(target_os = "windows") { Platform::Windows }
    else                           { Platform::MacOs   }
}

fn platform_menu(detected: &Platform) -> anyhow::Result<Platform> {
    let detected_label = match detected {
        Platform::Linux   => "Linux",
        Platform::Windows => "Windows",
        Platform::MacOs   => "macOS",
    };

    println!("{CYAN}Detected OS:{RESET} {BOLD}{}{RESET}\n", detected_label);
    println!("{BOLD}Select target platform:{RESET}");
    println!("  {DIM}(Press Enter to use detected platform){RESET}\n");
    println!("  {VIOLET}[1]{RESET} Linux   — Full install (engine + network observer + dashboard)");
    println!("  {VIOLET}[2]{RESET} Windows — Dashboard + entropy scanner only");
    println!("  {VIOLET}[3]{RESET} macOS   — Dashboard + entropy scanner only");
    println!();
    print!("{BOLD}Choice [{DIM}1-3, Enter = auto{RESET}{BOLD}]:{RESET} ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice = input.trim();

    Ok(match choice {
        "1"  => Platform::Linux,
        "2"  => Platform::Windows,
        "3"  => Platform::MacOs,
        ""   => detected.clone(),
        _    => {
            eprintln!("{RED}Invalid choice — using detected platform.{RESET}");
            detected.clone()
        }
    })
}

fn print_platform_note(platform: &Platform, mode: &InstallMode) {
    println!();
    match mode {
        InstallMode::Full => {
            step_info("Linux full install — all components:");
            println!("    {GREEN}✓{RESET} Process Engine  (PAR + PATH + ARG + ENV + BEH rules)");
            println!("    {GREEN}✓{RESET} Network Observer (NET-001..005 via /proc/net)");
            println!("    {GREEN}✓{RESET} Tauri Dashboard (all 7 panel views)");
            println!("    {GREEN}✓{RESET} Threat Intelligence + Canary + Self-Protect");
            println!("    {GREEN}✓{RESET} Active Defense (Kill · Quarantine · Whitelist)");
        }
        InstallMode::DashOnly => {
            let os = match platform {
                Platform::Windows => "Windows",
                Platform::MacOs   => "macOS",
                _                 => "non-Linux",
            };
            step_info(&format!("{} limited install (no kernel-level process monitoring):", os));
            println!("    {GREEN}✓{RESET} Tauri Dashboard");
            println!("    {GREEN}✓{RESET} Entropy file scanner");
            println!("    {GREEN}✓{RESET} Threat Intelligence feed lookup");
            println!("    {GREEN}✓{RESET} Canary token manager");
            println!("    {YELLOW}—{RESET} Process Engine (Linux /proc only — skipped)");
            println!("    {YELLOW}—{RESET} Network Observer (Linux /proc/net only — skipped)");
            println!("    {YELLOW}—{RESET} Active Defense (Linux namespaces only — skipped)");
        }
    }
    println!();
}

fn confirm_proceed() -> anyhow::Result<()> {
    print!("{BOLD}Proceed with installation? [Y/n]:{RESET} ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice = input.trim().to_lowercase();
    if choice == "n" || choice == "no" {
        println!("{YELLOW}Installation cancelled.{RESET}");
        std::process::exit(0);
    }
    Ok(())
}

fn ask_data_dir(platform: &Platform) -> anyhow::Result<String> {
    let default = match platform {
        Platform::Linux   => "/var/lib/aegis".to_string(),
        Platform::Windows => format!("{}\\AegisGuard",
            std::env::var("APPDATA").unwrap_or_else(|_| "C:\\ProgramData".into())),
        Platform::MacOs   => format!("{}/Library/Application Support/AegisGuard",
            std::env::var("HOME").unwrap_or_else(|_| "~".into())),
    };

    println!();
    print!("{BOLD}Data directory [{DIM}{}{RESET}{BOLD}]:{RESET} ", default);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice = input.trim().to_string();
    Ok(if choice.is_empty() { default } else { choice })
}

// ── Step runner ───────────────────────────────────────────────────────────────

fn run_steps(cfg: &Config) -> anyhow::Result<()> {
    println!();
    println!("{BOLD}━━━ Installation Steps ━━━{RESET}\n");

    // Step 1: Prerequisites
    step("Checking prerequisites");
    check_prerequisites(cfg)?;
    step_ok("Prerequisites OK");

    // Step 2: Node.js deps
    step("Installing Node.js dependencies");
    install_npm(cfg)?;
    step_ok("Node.js deps installed");

    // Step 3: Rust build
    step("Building Rust workspace");
    build_rust(cfg)?;
    step_ok("Rust build complete");

    // Step 4: Go build (Linux full only)
    if cfg.mode == InstallMode::Full {
        step("Building Go network observer");
        build_go(cfg)?;
        step_ok("Network observer built");
    }

    // Step 5: System setup
    step("Setting up system directories and services");
    setup_system(cfg)?;
    step_ok("System setup complete");

    Ok(())
}

// ── Step implementations ──────────────────────────────────────────────────────

fn check_prerequisites(cfg: &Config) -> anyhow::Result<()> {
    // Rust / Cargo
    check_tool("rustc", &["--version"], "Rust not found. Install: https://rustup.rs")?;
    check_tool("cargo", &["--version"], "Cargo not found. Install: https://rustup.rs")?;

    // Node.js
    check_tool("node", &["--version"], "Node.js not found. Install: https://nodejs.org")?;
    check_tool("npm",  &["--version"], "npm not found. Install: https://nodejs.org")?;

    // Go (Linux full only)
    if cfg.mode == InstallMode::Full {
        check_tool("go", &["version"],
            "Go not found. Install: https://go.dev/dl — needed for network observer")?;
    }

    // Linux-specific: check system libraries for WebKit/GTK
    if cfg.platform == Platform::Linux {
        check_lib("libwebkit2gtk-4.1")?;
    }

    Ok(())
}

fn check_tool(bin: &str, args: &[&str], hint: &str) -> anyhow::Result<()> {
    print!("    {DIM}checking {bin}…{RESET} ");
    io::stdout().flush()?;

    match Command::new(bin).args(args).output() {
        Ok(out) if out.status.success() => {
            let ver = String::from_utf8_lossy(&out.stdout);
            let ver = ver.lines().next().unwrap_or("").trim();
            println!("{GREEN}✓{RESET} {DIM}{}{RESET}", ver);
            Ok(())
        }
        _ => {
            println!("{RED}✗ NOT FOUND{RESET}");
            println!("    {YELLOW}→ {}{RESET}", hint);
            anyhow::bail!("{} not found", bin)
        }
    }
}

fn check_lib(name: &str) -> anyhow::Result<()> {
    print!("    {DIM}checking {name}…{RESET} ");
    io::stdout().flush()?;
    let ok = Command::new("pkg-config")
        .args(["--exists", name])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if ok {
        println!("{GREEN}✓{RESET}");
        Ok(())
    } else {
        println!("{YELLOW}⚠ not found (may still work){RESET}");
        println!("    {DIM}sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev{RESET}");
        Ok(()) // warn but don't fail
    }
}

fn install_npm(_cfg: &Config) -> anyhow::Result<()> {
    let tauri_dir = tauri_app_dir();
    println!("    {DIM}cd {}/tauri-app && npm install{RESET}", project_root());
    run_cmd("npm", &["install"], Some(&tauri_dir))?;
    Ok(())
}

fn build_rust(cfg: &Config) -> anyhow::Result<()> {
    let root = project_root();

    // Always build dashboard
    println!("    {DIM}cargo build --release (workspace){RESET}");

    let mut args = vec!["build", "--release"];

    // On non-Linux, skip process-engine and active-defense
    // (they have Linux-only deps)
    if cfg.platform != Platform::Linux {
        args.extend(&[
            "--workspace",
            "--exclude", "process-engine",
            "--exclude", "active-defense",
            "--exclude", "self-protect",
        ]);
    } else {
        args.push("--workspace");
    }

    run_cmd_stream("cargo", &args, Some(&root))?;
    Ok(())
}

fn build_go(_cfg: &Config) -> anyhow::Result<()> {
    let observer_dir = format!("{}/network-observer", project_root());
    let out          = format!("{}/target/aegis-network-observer", project_root());
    println!("    {DIM}go build → {}{RESET}", out);
    run_cmd("go", &["build", "-o", &out, "./cmd/observer"],
            Some(&observer_dir))?;
    Ok(())
}

fn setup_system(cfg: &Config) -> anyhow::Result<()> {
    match cfg.platform {
        Platform::Linux => setup_linux(cfg),
        Platform::Windows => setup_windows(cfg),
        Platform::MacOs => setup_macos(cfg),
    }
}

fn setup_linux(cfg: &Config) -> anyhow::Result<()> {
    let data  = &cfg.data_dir;
    let sock  = "/run/aegis";

    println!("    {DIM}creating directories…{RESET}");

    // Create dirs (may need sudo)
    for dir in &[data, sock, &format!("{}/quarantine", data),
                 &format!("{}/canaries", data)] {
        let r = Command::new("sudo")
            .args(["mkdir", "-p", dir])
            .status();
        match r {
            Ok(s) if s.success() => {}
            _ => {
                std::fs::create_dir_all(dir).ok();
            }
        }
    }

    // systemd unit
    println!("    {DIM}installing systemd service…{RESET}");
    let unit = format!(
        "[Unit]\nDescription=Aegis-Guard Process Engine — by Vladimir Unknown\nAfter=network.target\n\n\
         [Service]\nType=simple\nExecStart={root}/target/release/aegis-process-engine\n\
         Restart=on-failure\nEnvironment=AEGIS_LOG=info\nEnvironment=AEGIS_SOCKET=/run/aegis/proc.sock\n\
         User=root\n\n[Install]\nWantedBy=multi-user.target\n",
        root = project_root()
    );

    std::fs::write("/tmp/aegis-process-engine.service", &unit).ok();
    Command::new("sudo")
        .args(["cp", "/tmp/aegis-process-engine.service",
               "/etc/systemd/system/aegis-process-engine.service"])
        .status().ok();
    Command::new("sudo").args(["systemctl", "daemon-reload"]).status().ok();

    println!("    {DIM}systemd unit installed{RESET}");
    Ok(())
}

fn setup_windows(cfg: &Config) -> anyhow::Result<()> {
    std::fs::create_dir_all(&cfg.data_dir)?;
    println!("    {DIM}data directory created: {}{RESET}", cfg.data_dir);
    println!("    {YELLOW}⚠  Windows: process engine not available (Linux only){RESET}");
    println!("    {DIM}Run dashboard: cd tauri-app && cargo tauri dev{RESET}");
    Ok(())
}

fn setup_macos(cfg: &Config) -> anyhow::Result<()> {
    std::fs::create_dir_all(&cfg.data_dir)?;
    println!("    {DIM}data directory created: {}{RESET}", cfg.data_dir);
    println!("    {YELLOW}⚠  macOS: process engine not available (Linux only){RESET}");
    println!("    {DIM}Run dashboard: cd tauri-app && cargo tauri dev{RESET}");
    Ok(())
}

// ── Success screen ─────────────────────────────────────────────────────────────

fn print_success(cfg: &Config) {
    println!();
    println!("{GREEN}{BOLD}━━━ Installation Complete ━━━{RESET}\n");

    match cfg.mode {
        InstallMode::Full => {
            println!("{BOLD}Start Aegis-Guard:{RESET}\n");
            println!("  {VIOLET}Terminal 1{RESET} — Process Engine");
            println!("  {DIM}sudo AEGIS_LOG=info {}/target/release/aegis-process-engine{RESET}",
                project_root());
            println!();
            println!("  {VIOLET}Terminal 2{RESET} — Network Observer");
            println!("  {DIM}sudo AEGIS_LOG=info {}/target/aegis-network-observer{RESET}",
                project_root());
            println!();
            println!("  {VIOLET}Terminal 3{RESET} — Dashboard");
            println!("  {DIM}cd {}/tauri-app && AEGIS_NET=1 cargo tauri dev{RESET}",
                project_root());
            println!();
            println!("  {DIM}Or as a service:{RESET}");
            println!("  {DIM}sudo systemctl start aegis-process-engine{RESET}");
        }
        InstallMode::DashOnly => {
            println!("{BOLD}Start Aegis-Guard Dashboard:{RESET}\n");
            println!("  {DIM}cd {}/tauri-app && cargo tauri dev{RESET}", project_root());
        }
    }

    println!();
    println!("{DIM}Data directory: {}{RESET}", cfg.data_dir);
    println!("{DIM}Documentation:  {}/README.md{RESET}", project_root());
    println!();
    println!("{VIOLET}{BOLD}Aegis-Guard — by Vladimir Unknown{RESET}");
    println!();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn step(msg: &str) {
    println!("{CYAN}  ◈  {BOLD}{}{RESET}", msg);
}

fn step_ok(msg: &str) {
    println!("{GREEN}  ✓  {}{RESET}\n", msg);
}

fn step_info(msg: &str) {
    println!("{CYAN}  ℹ  {}{RESET}", msg);
}

fn clear_screen() {
    print!("\x1b[2J\x1b[H");
    io::stdout().flush().ok();
}

fn project_root() -> String {
    // Find the repo root by walking up from executable location
    let exe = std::env::current_exe().unwrap_or_default();
    // If running from target/debug or target/release, go up two levels
    let mut path = exe.parent().unwrap_or(std::path::Path::new("."))
        .to_path_buf();
    if path.ends_with("debug") || path.ends_with("release") {
        path = path.parent().unwrap_or(&path).to_path_buf(); // target/
        path = path.parent().unwrap_or(&path).to_path_buf(); // root
    }
    path.to_string_lossy().into_owned()
}

fn tauri_app_dir() -> String {
    format!("{}/tauri-app", project_root())
}

fn run_cmd(bin: &str, args: &[&str], cwd: Option<&str>) -> anyhow::Result<()> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    if let Some(dir) = cwd { cmd.current_dir(dir); }
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("{} {:?} failed: {}", bin, args, status);
    }
    Ok(())
}

fn run_cmd_stream(bin: &str, args: &[&str], cwd: Option<&str>) -> anyhow::Result<()> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
       .stdout(Stdio::inherit())
       .stderr(Stdio::inherit());
    if let Some(dir) = cwd { cmd.current_dir(dir); }
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("{} failed with status {}", bin, status);
    }
    Ok(())
}
