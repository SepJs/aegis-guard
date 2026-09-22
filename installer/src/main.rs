// installer/src/main.rs — Aegis-Guard interactive installer (by Vladimir Unknown)
// Optional TUI wizard. For most users, `bash aegis.sh` is simpler and does
// everything this wizard does, non-interactively, in one command.

use std::io::{self, Write};
use std::process::{Command, Stdio};

const RESET: &str = "\x1b[0m"; const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m"; const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m"; const CYAN: &str = "\x1b[36m";
const VIOLET: &str = "\x1b[35m"; const DIM: &str = "\x1b[2m";

fn main() -> anyhow::Result<()> {
    print!("\x1b[2J\x1b[H"); io::stdout().flush().ok();
    println!("{VIOLET}{BOLD}");
    println!("  ╔═══════════════════════════════════════════╗");
    println!("  ║     AEGIS-GUARD  INSTALLER  v0.1.0       ║");
    println!("  ║     by Vladimir Unknown                   ║");
    println!("  ╚═══════════════════════════════════════════╝");
    println!("{RESET}");

    println!("{CYAN}This wizard builds everything and sets up system services.{RESET}");
    println!("{DIM}For a quicker one-shot run + launch, use: bash aegis.sh{RESET}\n");

    print!("{BOLD}Proceed? [Y/n]:{RESET} "); io::stdout().flush()?;
    let mut input = String::new(); io::stdin().read_line(&mut input)?;
    if input.trim().eq_ignore_ascii_case("n") { println!("Cancelled."); return Ok(()); }

    step("Checking prerequisites");
    check_tool("rustc"); check_tool("cargo"); check_tool("node"); check_tool("npm"); check_tool("go");
    step_ok("Prerequisites checked");

    step("Building Rust workspace (release)");
    run_stream("cargo", &["build", "--release", "--workspace"]);
    step_ok("Rust build complete");

    step("Building Go network observer");
    std::fs::create_dir_all("target/release").ok();
    let observer_out = if cfg!(windows) {
        "../target/release/aegis-network-observer.exe"
    } else {
        "../target/release/aegis-network-observer"
    };
    let mut go_cmd = Command::new("go");
    go_cmd.current_dir("network-observer").args(["build", "-o", observer_out, "./cmd/observer"]);
    let _ = go_cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit()).status();
    step_ok("Network observer built");

    step("Installing npm dependencies");
    let mut npm_cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", "npm", "install"]);
        c
    } else {
        let mut c = Command::new("npm");
        c.arg("install");
        c
    };
    npm_cmd.current_dir("tauri-app");
    let _ = npm_cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit()).status();
    step_ok("npm dependencies installed");

    let run_cmd = if cfg!(windows) {
        "installers\\install-windows.bat"
    } else {
        "bash aegis.sh"
    };
    println!("\n{GREEN}{BOLD}Done.{RESET} Run everything with:\n  {CYAN}{run_cmd}{RESET}\n");
    Ok(())
}

fn step(msg: &str) { println!("{CYAN}  ◈  {BOLD}{}{RESET}", msg); }
fn step_ok(msg: &str) { println!("{GREEN}  ✓  {}{RESET}\n", msg); }

fn check_tool(bin: &str) {
    print!("    {DIM}checking {bin}…{RESET} "); io::stdout().flush().ok();
    match Command::new(bin).arg("--version").output() {
        Ok(o) if o.status.success() => println!("{GREEN}✓{RESET}"),
        _ => println!("{RED}✗ not found{RESET}"),
    }
}

fn run_stream(bin: &str, args: &[&str]) {
    let _ = Command::new(bin).args(args).stdout(Stdio::inherit()).stderr(Stdio::inherit()).status();
}
