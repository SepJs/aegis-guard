use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InstallMode {
    Desktop,
    Console,
}

#[derive(Clone, Debug)]
pub struct EnvInfo {
    pub os: String,
    pub arch: String,
    pub distro_family: String,
    pub is_elevated: bool,
    pub has_node: bool,
    pub node_version: String,
    pub has_cargo: bool,
    pub rust_version: String,
    pub has_go: bool,
    pub go_version: String,
    pub has_git: bool,
    pub local_repo: Option<PathBuf>,
    pub default_install_dir: PathBuf,
}

#[derive(Clone, Debug)]
pub struct InstallConfig {
    pub mode: InstallMode,
    pub install_dir: PathBuf,
    pub create_shortcuts: bool,
    pub setup_services: bool,
    pub configure_firewall: bool,
}

#[derive(Clone, Debug)]
pub enum ProgressMsg {
    Step {
        index: usize,
        total: usize,
        title: String,
    },
    Log(String),
    Finished {
        success: bool,
        summary: String,
        launch_target: Option<PathBuf>,
    },
}

pub fn detect_environment() -> EnvInfo {
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let distro_family = detect_distro_family();
    let is_elevated = check_elevated();

    let (has_node, node_version) = probe_tool("node", &["--version"]);
    let (has_cargo, rust_version) = probe_cargo();
    let (has_go, go_version) = probe_tool("go", &["version"]);
    let (has_git, _) = probe_tool("git", &["--version"]);
    let local_repo = find_local_repo();

    let default_install_dir = if let Some(ref repo) = local_repo {
        repo.clone()
    } else if cfg!(windows) {
        if is_elevated {
            PathBuf::from(r"C:\Program Files\Aegis-Guard")
        } else {
            std::env::var("LOCALAPPDATA")
                .map(|p| PathBuf::from(p).join("Aegis-Guard"))
                .unwrap_or_else(|_| PathBuf::from(r"C:\Aegis-Guard"))
        }
    } else if cfg!(target_os = "macos") {
        std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(".local/share/aegis-guard"))
            .unwrap_or_else(|_| PathBuf::from("/opt/aegis-guard"))
    } else if is_elevated {
        PathBuf::from("/opt/aegis-guard")
    } else {
        std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(".local/share/aegis-guard"))
            .unwrap_or_else(|_| PathBuf::from("/tmp/aegis-guard"))
    };

    EnvInfo {
        os,
        arch,
        distro_family,
        is_elevated,
        has_node,
        node_version,
        has_cargo,
        rust_version,
        has_go,
        go_version,
        has_git,
        local_repo,
        default_install_dir,
    }
}

fn detect_distro_family() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(raw) = std::fs::read_to_string("/etc/os-release") {
            let lower = raw.to_lowercase();
            if lower.contains("ubuntu") || lower.contains("debian") || lower.contains("mint") || lower.contains("pop") {
                return "debian".into();
            }
            if lower.contains("fedora") || lower.contains("rhel") || lower.contains("centos") || lower.contains("rocky") {
                return "fedora".into();
            }
            if lower.contains("arch") || lower.contains("manjaro") || lower.contains("endeavour") {
                return "arch".into();
            }
            if lower.contains("suse") {
                return "suse".into();
            }
            if lower.contains("alpine") {
                return "alpine".into();
            }
        }
        "linux".into()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::consts::OS.into()
    }
}

fn check_elevated() -> bool {
    #[cfg(unix)]
    {
        Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim() == "0")
            .unwrap_or(false)
    }
    #[cfg(windows)]
    {
        Command::new("net")
            .arg("session")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

fn probe_tool(bin: &str, args: &[&str]) -> (bool, String) {
    match Command::new(bin).args(args).output() {
        Ok(o) if o.status.success() => {
            let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
            (true, out)
        }
        _ => (false, String::new()),
    }
}

fn resolve_real_home() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            let trimmed = sudo_user.trim();
            if !trimmed.is_empty() && trimmed != "root" {
                let candidate = PathBuf::from("/home").join(trimmed);
                if candidate.is_dir() {
                    return Some(candidate);
                }
                if cfg!(target_os = "macos") {
                    let mac_candidate = PathBuf::from("/Users").join(trimmed);
                    if mac_candidate.is_dir() {
                        return Some(mac_candidate);
                    }
                }
            }
        }
        std::env::var("HOME").ok().map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").ok().map(PathBuf::from)
    }
}

fn cargo_bin_path() -> PathBuf {
    if let Some(home) = resolve_real_home() {
        let p = home.join(".cargo/bin/cargo");
        if p.exists() {
            return p;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(home).join(".cargo/bin/cargo");
        if p.exists() {
            return p;
        }
    }
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        let p = PathBuf::from(userprofile).join(r".cargo\bin\cargo.exe");
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("cargo")
}

fn probe_cargo() -> (bool, String) {
    let bin = cargo_bin_path();
    match Command::new(&bin).arg("--version").output() {
        Ok(o) if o.status.success() => (
            true,
            String::from_utf8_lossy(&o.stdout).trim().to_string(),
        ),
        _ => (false, String::new()),
    }
}

fn find_local_repo() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.clone());
        if let Some(p) = cwd.parent() {
            candidates.push(p.to_path_buf());
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut cur = exe.parent().map(|p| p.to_path_buf());
        for _ in 0..4 {
            if let Some(dir) = cur {
                candidates.push(dir.clone());
                cur = dir.parent().map(|p| p.to_path_buf());
            }
        }
    }
    for dir in candidates {
        if dir.join("package.json").is_file() && dir.join("tauri-app").is_dir() {
            return Some(dir);
        }
    }
    None
}

fn emit_step(tx: &Sender<ProgressMsg>, idx: usize, total: usize, title: &str) {
    let _ = tx.send(ProgressMsg::Step {
        index: idx,
        total,
        title: title.to_string(),
    });
    let _ = tx.send(ProgressMsg::Log(format!("\n=== [{}/{}] {} ===", idx, total, title)));
}

fn emit_log(tx: &Sender<ProgressMsg>, msg: impl Into<String>) {
    let _ = tx.send(ProgressMsg::Log(msg.into()));
}

fn run_cmd_stream(
    tx: &Sender<ProgressMsg>,
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    envs: &[(&str, &str)],
) -> anyhow::Result<()> {
    emit_log(tx, format!("$ {} {}", program, args.join(" ")));
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let tx_out = tx.clone();
    let t_out = std::thread::spawn(move || {
        if let Some(out) = stdout {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                let _ = tx_out.send(ProgressMsg::Log(line));
            }
        }
    });

    let tx_err = tx.clone();
    let t_err = std::thread::spawn(move || {
        if let Some(err) = stderr {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                let _ = tx_err.send(ProgressMsg::Log(line));
            }
        }
    });

    let status = child.wait()?;
    let _ = t_out.join();
    let _ = t_err.join();

    if !status.success() {
        anyhow::bail!("Command `{}` exited with status {}", program, status);
    }
    Ok(())
}

pub fn run_install(cfg: InstallConfig, tx: Sender<ProgressMsg>) {
    let total = 6usize;
    let env_info = detect_environment();

    // Step 1: Prepare target repository / source directory
    emit_step(&tx, 1, total, "Preparing Aegis-Guard workspace");
    let source_dir = if let Some(ref local) = env_info.local_repo {
        if cfg.install_dir == *local {
            emit_log(&tx, format!("Using local repository: {}", local.display()));
            local.clone()
        } else {
            if let Err(e) = std::fs::create_dir_all(&cfg.install_dir) {
                let _ = tx.send(ProgressMsg::Finished {
                    success: false,
                    summary: format!("Cannot create {}: {}. Choose a writable directory or run elevated.", cfg.install_dir.display(), e),
                    launch_target: None,
                });
                return;
            }
            if local.join(".git").exists() && !cfg.install_dir.join("package.json").exists() {
                emit_log(&tx, format!("Copying source tree into {}", cfg.install_dir.display()));
                copy_project_tree(local, &cfg.install_dir, &tx);
            }
            if cfg.install_dir.join("package.json").exists() {
                cfg.install_dir.clone()
            } else {
                local.clone()
            }
        }
    } else {
        if !env_info.has_git {
            let _ = tx.send(ProgressMsg::Finished {
                success: false,
                summary: "Git is required to fetch Aegis-Guard source files.".into(),
                launch_target: None,
            });
            return;
        }
        if let Some(parent) = cfg.install_dir.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if cfg.install_dir.join(".git").exists() {
            let _ = run_cmd_stream(&tx, "git", &["-C", &cfg.install_dir.to_string_lossy(), "pull", "--ff-only"], None, &[]);
        } else {
            let _ = std::fs::remove_dir_all(&cfg.install_dir);
            if let Err(e) = run_cmd_stream(
                &tx,
                "git",
                &["clone", "--depth", "1", "https://github.com/SepJs/aegis-guard.git", &cfg.install_dir.to_string_lossy()],
                None,
                &[],
            ) {
                let _ = tx.send(ProgressMsg::Finished {
                    success: false,
                    summary: format!("Repository clone failed: {}", e),
                    launch_target: None,
                });
                return;
            }
        }
        cfg.install_dir.clone()
    };

    // Step 2: Check runtime prerequisites
    emit_step(&tx, 2, total, "Verifying Node.js, Rust, and Go toolchains");
    if !env_info.has_node {
        let _ = tx.send(ProgressMsg::Finished {
            success: false,
            summary: "Node.js 20+ not found on PATH. Install Node.js first (https://nodejs.org) and retry.".into(),
            launch_target: None,
        });
        return;
    }
    emit_log(&tx, format!("Node.js detected: {}", env_info.node_version));
    emit_log(
        &tx,
        if env_info.has_cargo {
            format!("Rust detected: {}", env_info.rust_version)
        } else {
            "Rust not detected — native Rust build skipped (console engine will run).".into()
        },
    );
    emit_log(
        &tx,
        if env_info.has_go {
            format!("Go detected: {}", env_info.go_version)
        } else {
            "Go not detected — optional raw-socket packet observer skipped.".into()
        },
    );

    // Step 3: Build frontend SPA & install Node dependencies
    emit_step(&tx, 3, total, "Installing npm dependencies & building dashboard UI");
    let npm_prog = if cfg!(windows) { "cmd" } else { "npm" };
    let npm_install_args: &[&str] = if cfg!(windows) {
        &["/C", "npm", "install", "--no-audit", "--no-fund"]
    } else {
        &["install", "--no-audit", "--no-fund"]
    };
    if let Err(e) = run_cmd_stream(&tx, npm_prog, npm_install_args, Some(&source_dir), &[]) {
        let _ = tx.send(ProgressMsg::Finished {
            success: false,
            summary: format!("npm install failed: {}", e),
            launch_target: None,
        });
        return;
    }
    let npm_build_args: &[&str] = if cfg!(windows) {
        &["/C", "npm", "run", "build"]
    } else {
        &["run", "build"]
    };
    if let Err(e) = run_cmd_stream(&tx, npm_prog, npm_build_args, Some(&source_dir), &[]) {
        let _ = tx.send(ProgressMsg::Finished {
            success: false,
            summary: format!("Frontend build failed: {}", e),
            launch_target: None,
        });
        return;
    }

    // Step 4: Build Go packet observer (optional)
    emit_step(&tx, 4, total, "Building Go network packet observer");
    let observer_dir = source_dir.join("network-observer");
    let target_dir = source_dir.join("target");
    let _ = std::fs::create_dir_all(&target_dir);
    let observer_out = if cfg!(windows) {
        target_dir.join("aegis-network-observer.exe")
    } else {
        target_dir.join("aegis-network-observer")
    };
    if env_info.has_go && observer_dir.is_dir() {
        let out_arg = format!(
            "../target/{}",
            observer_out
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("aegis-network-observer")
        );
        if let Err(e) = run_cmd_stream(
            &tx,
            "go",
            &["build", "-ldflags=-s -w", "-o", &out_arg, "./cmd/observer"],
            Some(&observer_dir),
            &[("CGO_ENABLED", "0")],
        ) {
            emit_log(&tx, format!("Warning: Go observer build skipped ({}).", e));
        }
    } else {
        emit_log(&tx, "Skipping Go observer build.");
    }

    // Step 5: Build Rust engines & native Tauri desktop binary
    emit_step(&tx, 5, total, "Building native Rust engine & desktop application");
    let cargo = cargo_bin_path();
    let cargo_str = cargo.to_string_lossy().to_string();
    if env_info.has_cargo {
        if let Err(e) = run_cmd_stream(&tx, &cargo_str, &["build", "--release", "-p", "process-engine"], Some(&source_dir), &[]) {
            emit_log(&tx, format!("Warning: process-engine build skipped ({}).", e));
        }
        if cfg.mode == InstallMode::Desktop {
            if let Err(e) = run_cmd_stream(&tx, &cargo_str, &["build", "--release", "-p", "aegis-guard"], Some(&source_dir), &[]) {
                emit_log(&tx, format!("Warning: native desktop build error: {}. Console launcher remains active.", e));
            }
        }
    } else {
        emit_log(&tx, "Rust toolchain absent — skipping native binary compilation.");
    }

    // Step 6: Install launchers, shortcuts & data vaults
    emit_step(&tx, 6, total, "Installing binaries, desktop shortcuts & vaults");
    let launch_target = install_launchers_and_shortcuts(&source_dir, &cfg, &env_info, &tx);

    let mode_label = if cfg.mode == InstallMode::Desktop {
        "Desktop + Console"
    } else {
        "Console Web Server"
    };
    let _ = tx.send(ProgressMsg::Finished {
        success: true,
        summary: format!(
            "Aegis-Guard v1.2.0 ({}) installed cleanly into {}.",
            mode_label,
            source_dir.display()
        ),
        launch_target,
    });
}

fn copy_project_tree(src: &Path, dst: &Path, tx: &Sender<ProgressMsg>) {
    let items = [
        "package.json",
        "server.ts",
        "server-security.ts",
        "server-security.test.ts",
        "aegis.sh",
        "Makefile",
        "Cargo.toml",
        "README.md",
        "INSTALLATION.md",
        "crates",
        "tauri-app",
        "network-observer",
        "installers",
        "installer",
        "proto",
        "resources",
    ];
    for name in items {
        let s = src.join(name);
        let d = dst.join(name);
        if s.is_dir() {
            if let Err(e) = copy_dir_filtered(&s, &d) {
                emit_log(tx, format!("Note copying {}: {}", name, e));
            }
        } else if s.is_file() {
            let _ = std::fs::copy(&s, &d);
        }
    }
}

fn copy_dir_filtered(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let fname = entry.file_name();
        let name = fname.to_string_lossy();
        if name == "node_modules" || name == "target" || name == ".git" {
            continue;
        }
        let sp = entry.path();
        let dp = dst.join(&fname);
        if sp.is_dir() {
            copy_dir_filtered(&sp, &dp)?;
        } else {
            std::fs::copy(&sp, &dp)?;
        }
    }
    Ok(())
}

fn find_desktop_bin(source_dir: &Path) -> Option<PathBuf> {
    let names = if cfg!(windows) {
        vec!["Aegis-Guard.exe"]
    } else {
        vec!["Aegis-Guard"]
    };
    for name in names {
        for cand in [
            source_dir.join("target/release").join(name),
            source_dir.join("tauri-app/src-tauri/target/release").join(name),
        ] {
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

fn install_launchers_and_shortcuts(
    source_dir: &Path,
    cfg: &InstallConfig,
    env_info: &EnvInfo,
    tx: &Sender<ProgressMsg>,
) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bin_dir = if env_info.is_elevated {
            let src_str = source_dir.to_string_lossy();
            let _ = Command::new("chmod").args(["-R", "a+rX", src_str.as_ref()]).status();
            PathBuf::from("/usr/local/bin")
        } else {
            resolve_real_home()
                .map(|h| h.join(".local/bin"))
                .unwrap_or_else(|| PathBuf::from("/tmp"))
        };
        let _ = std::fs::create_dir_all(&bin_dir);

        let desktop_bin = find_desktop_bin(source_dir);
        if let Some(ref db) = desktop_bin {
            let dst = bin_dir.join("aegis-guard-bin");
            if std::fs::copy(db, &dst).is_ok() {
                let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755));
                emit_log(&tx, format!("Installed binary: {}", dst.display()));
            }
        }

        let proc_bin = source_dir.join("target/release/aegis-process-engine");
        if proc_bin.is_file() {
            let dst = bin_dir.join("aegis-process-engine");
            if std::fs::copy(&proc_bin, &dst).is_ok() {
                let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755));
                emit_log(&tx, format!("Installed daemon: {}", dst.display()));
            }
        }

        let obs_bin = source_dir.join("target/aegis-network-observer");
        if obs_bin.is_file() {
            let dst = bin_dir.join("aegis-network-observer");
            if std::fs::copy(&obs_bin, &dst).is_ok() {
                let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755));
                emit_log(&tx, format!("Installed observer: {}", dst.display()));
            }
        }

        let cli_wrapper = bin_dir.join("aegis-guard");
        let cli_content = format!(
            "#!/usr/bin/env bash\ncd \"{}\"\nexec bash \"{}/aegis.sh\" \"$@\"\n",
            source_dir.display(),
            source_dir.display()
        );
        if std::fs::write(&cli_wrapper, cli_content).is_ok() {
            let _ = std::fs::set_permissions(&cli_wrapper, std::fs::Permissions::from_mode(0o755));
            emit_log(&tx, format!("Installed CLI wrapper: {}", cli_wrapper.display()));
        }

        let desk_wrapper = bin_dir.join("aegis-guard-desktop");
        let desk_content = format!(
            "#!/usr/bin/env bash\nexport WEBKIT_DISABLE_DMABUF_RENDERER=\"${{WEBKIT_DISABLE_DMABUF_RENDERER:-1}}\"\ncd \"{}\"\nexec bash \"{}/aegis.sh\" --desktop \"$@\"\n",
            source_dir.display(),
            source_dir.display()
        );
        if std::fs::write(&desk_wrapper, desk_content).is_ok() {
            let _ = std::fs::set_permissions(&desk_wrapper, std::fs::Permissions::from_mode(0o755));
        }

        if cfg.create_shortcuts {
            install_unix_desktop_entry(source_dir, &desk_wrapper, env_info.is_elevated, tx);
        }

        if cfg.setup_services && env_info.is_elevated && Path::new("/etc/systemd/system").is_dir() {
            let _ = Command::new("bash")
                .args([source_dir.join("installers/setup-systemd.sh").to_string_lossy().as_ref()])
                .current_dir(source_dir)
                .status();
            emit_log(&tx, "Systemd service definitions refreshed.");
        }

        if cfg.mode == InstallMode::Desktop {
            return Some(desk_wrapper);
        }
        return Some(cli_wrapper);
    }

    #[cfg(windows)]
    {
        if env_info.is_elevated {
            let src_str = source_dir.to_string_lossy();
            let _ = Command::new("icacls")
                .args([src_str.as_ref(), "/grant", "Users:(OI)(CI)M", "/T", "/Q"])
                .status();
            if let Ok(pd) = std::env::var("ProgramData") {
                let data_root = PathBuf::from(pd).join("Aegis-Guard");
                let _ = std::fs::create_dir_all(&data_root);
                let data_str = data_root.to_string_lossy();
                let _ = Command::new("icacls")
                    .args([data_str.as_ref(), "/grant", "Users:(OI)(CI)M", "/T", "/Q"])
                    .status();
            }
        }

        let desktop_bin = find_desktop_bin(source_dir);
        let launcher_cmd = source_dir.join("Aegis-Guard-Desktop.cmd");
        let desktop_cmd_body = if let Some(ref db) = desktop_bin {
            format!(
                "@echo off\r\ncd /d \"{}\"\r\nstart \"\" \"{}\"\r\n",
                source_dir.display(),
                db.display()
            )
        } else {
            format!(
                "@echo off\r\ncd /d \"{}\"\r\nset NODE_ENV=production\r\nstart \"\" /B powershell -NoProfile -Command \"for($i=0;$i -lt 30;$i++){{try{{$c=New-Object Net.Sockets.TcpClient('127.0.0.1',3000);$c.Close();Start-Process 'http://127.0.0.1:3000';break}}catch{{Start-Sleep -Milliseconds 400}}}}\"\r\ncall npm start\r\n",
                source_dir.display()
            )
        };
        let _ = std::fs::write(&launcher_cmd, desktop_cmd_body);
        emit_log(&tx, format!("Created Windows launcher: {}", launcher_cmd.display()));

        if cfg.create_shortcuts {
            let ico_path = source_dir.join("tauri-app\\src-tauri\\icons\\icon.ico");
            let ico_line = if ico_path.is_file() {
                format!("$S.IconLocation = \"{}\"; ", ico_path.display())
            } else {
                String::new()
            };
            let ps_script = format!(
                r#"$Wsh = New-Object -ComObject WScript.Shell; $Desk = [Environment]::GetFolderPath('Desktop'); $S = $Wsh.CreateShortcut("$Desk\Aegis-Guard.lnk"); $S.TargetPath = "{}"; $S.WorkingDirectory = "{}"; {}$S.Save()"#,
                launcher_cmd.display(),
                source_dir.display(),
                ico_line
            );
            let _ = Command::new("powershell")
                .args(["-NoProfile", "-Command", ps_script.as_str()])
                .status();
            emit_log(&tx, "Created Windows Desktop shortcut.");
        }

        if cfg.configure_firewall && env_info.is_elevated {
            let _ = Command::new("netsh")
                .args(["advfirewall", "firewall", "add", "rule", "name=Aegis-Guard IPC", "dir=in", "action=allow", "protocol=TCP", "localport=50053-50054", "remoteip=127.0.0.1"])
                .status();
            emit_log(&tx, "Configured loopback Windows Firewall IPC rule.");
        }

        return desktop_bin.or(Some(launcher_cmd));
    }
}

#[cfg(unix)]
fn install_unix_desktop_entry(
    source_dir: &Path,
    exec_path: &Path,
    is_elevated: bool,
    tx: &Sender<ProgressMsg>,
) {
    use std::os::unix::fs::PermissionsExt;
    let icon_src = source_dir.join("tauri-app/src-tauri/icons/icon.png");
    let mut targets = Vec::new();
    if is_elevated {
        targets.push((
            PathBuf::from("/usr/share/applications"),
            PathBuf::from("/usr/share/icons/hicolor/128x128/apps"),
        ));
    }
    if let Some(real_home) = resolve_real_home() {
        targets.push((
            real_home.join(".local/share/applications"),
            real_home.join(".local/share/icons"),
        ));
    }

    for (app_dir, icon_dir) in targets {
        let _ = std::fs::create_dir_all(&app_dir);
        let _ = std::fs::create_dir_all(&icon_dir);

        let icon_dst = icon_dir.join("aegis-guard.png");
        if icon_src.is_file() {
            let _ = std::fs::copy(&icon_src, &icon_dst);
        }

        let desktop_file = app_dir.join("aegis-guard.desktop");
        let content = format!(
            "[Desktop Entry]\nType=Application\nName=Aegis-Guard\nComment=Endpoint Security & Network IDS Suite\nExec={}\nIcon={}\nTerminal=false\nCategories=System;Security;\nStartupNotify=true\n",
            exec_path.display(),
            icon_dst.display()
        );
        if std::fs::write(&desktop_file, content).is_ok() {
            let _ = std::fs::set_permissions(&desktop_file, std::fs::Permissions::from_mode(0o755));
            if is_elevated && app_dir.starts_with("/home/") {
                if let Ok(su) = std::env::var("SUDO_USER") {
                    let owner = format!("{su}:{su}");
                    let desk = desktop_file.to_string_lossy();
                    let _ = Command::new("chown")
                        .args([owner.as_str(), desk.as_ref()])
                        .status();
                }
            }
            let _ = Command::new("update-desktop-database").arg(&app_dir).status();
            emit_log(&tx, format!("Installed application launcher: {}", desktop_file.display()));
        }
    }
}

pub fn run_uninstall(install_dir: PathBuf, tx: Sender<ProgressMsg>) {
    emit_step(&tx, 1, 2, "Removing Aegis-Guard launchers and shortcuts");
    #[cfg(unix)]
    {
        let _ = Command::new("systemctl")
            .args(["stop", "aegis-process-engine", "aegis-network-observer"])
            .status();
        let mut bins = vec![
            PathBuf::from("/usr/local/bin/aegis-guard"),
            PathBuf::from("/usr/local/bin/aegis-guard-desktop"),
            PathBuf::from("/usr/local/bin/aegis-guard-bin"),
            PathBuf::from("/usr/local/bin/aegis-process-engine"),
            PathBuf::from("/usr/local/bin/aegis-network-observer"),
            PathBuf::from("/usr/share/applications/aegis-guard.desktop"),
        ];
        if let Ok(home) = std::env::var("HOME") {
            let h = PathBuf::from(home);
            bins.push(h.join(".local/bin/aegis-guard"));
            bins.push(h.join(".local/bin/aegis-guard-desktop"));
            bins.push(h.join(".local/bin/aegis-guard-bin"));
            bins.push(h.join(".local/share/applications/aegis-guard.desktop"));
        }
        for b in bins {
            if b.exists() {
                let _ = std::fs::remove_file(&b);
                emit_log(&tx, format!("Removed {}", b.display()));
            }
        }
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill").args(["/IM", "Aegis-Guard.exe", "/F"]).status();
        let _ = Command::new("taskkill").args(["/IM", "aegis-process-engine.exe", "/F"]).status();
        let _ = Command::new("taskkill").args(["/IM", "aegis-network-observer.exe", "/F"]).status();
    }
    emit_step(&tx, 2, 2, "Uninstall complete");
    emit_log(&tx, format!("Preserved user data; source at {} left untouched unless manually removed.", install_dir.display()));
    let _ = tx.send(ProgressMsg::Finished {
        success: true,
        summary: "Aegis-Guard launchers and desktop shortcuts removed.".into(),
        launch_target: None,
    });
}

pub fn launch_installed_app(target: Option<PathBuf>, install_dir: &Path) {
    if let Some(ref bin) = target {
        if bin.is_file() {
            #[cfg(unix)]
            {
                let _ = Command::new("bash")
                    .arg(bin)
                    .env("WEBKIT_DISABLE_DMABUF_RENDERER", "1")
                    .spawn();
                return;
            }
            #[cfg(windows)]
            {
                if bin.extension().and_then(|s| s.to_str()) == Some("cmd") {
                    let bin_str = bin.to_string_lossy();
                    let _ = Command::new("cmd").args(["/C", "start", "", bin_str.as_ref()]).spawn();
                } else {
                    let _ = Command::new(bin).spawn();
                }
                return;
            }
        }
    }

    #[cfg(unix)]
    {
        let script = install_dir.join("aegis.sh");
        if script.is_file() {
            let _ = Command::new("bash")
                .args([script.to_string_lossy().as_ref(), "--desktop", "--open"])
                .current_dir(install_dir)
                .spawn();
        }
    }
    #[cfg(windows)]
    {
        let cmd = install_dir.join("Aegis-Guard-Desktop.cmd");
        if cmd.is_file() {
            let cmd_str = cmd.to_string_lossy();
            let _ = Command::new("cmd").args(["/C", "start", "", cmd_str.as_ref()]).spawn();
        }
    }
}
