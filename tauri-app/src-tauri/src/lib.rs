mod commands;
mod ipc_bridge;
mod net_bridge;
mod phase5_bridge;
mod state;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{Emitter, Manager};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use active_defense::ResponseEngine;
use journal::Journal;
use state::{
    AppState, AutoPruneConfig, MalwareScanResult, NetDefenseConfig, PacketInspectorConfig,
    SystemSettings,
};

fn resolve_writable_data_dir(app: &tauri::App) -> PathBuf {
    let mut candidates = Vec::new();
    if let Ok(custom) = std::env::var("AEGIS_DATA_DIR") {
        candidates.push(PathBuf::from(custom));
    }
    if let Ok(dir) = app.path().app_data_dir() {
        candidates.push(dir);
    }
    #[cfg(not(windows))]
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(PathBuf::from(home).join(".local/share/aegis-guard"));
    }
    #[cfg(windows)]
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        candidates.push(PathBuf::from(local).join("Aegis-Guard"));
    }
    candidates.push(std::env::temp_dir().join("aegis-guard-data"));

    for c in candidates {
        if std::fs::create_dir_all(&c).is_ok() {
            return c;
        }
    }
    std::env::temp_dir()
}

fn ensure_socket_dir_permissions(socket_path: &str) -> String {
    if socket_path.contains(':') || cfg!(windows) {
        return socket_path.to_string();
    }
    let dir = std::path::Path::new(socket_path)
        .parent()
        .unwrap_or(std::path::Path::new("/run/aegis"));

    if !dir.exists() && std::fs::create_dir_all(dir).is_err() {
        let fallback = std::env::var("XDG_RUNTIME_DIR")
            .map(|r| PathBuf::from(r).join("aegis-proc.sock"))
            .unwrap_or_else(|_| std::env::temp_dir().join("aegis-proc.sock"));
        warn!(
            "Cannot access {}, using user socket fallback {}",
            dir.display(),
            fallback.display()
        );
        return fallback.to_string_lossy().to_string();
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o1777));
    }
    socket_path.to_string()
}

pub fn run() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("AEGIS_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .try_init();

    info!("Aegis-Guard Tauri desktop runtime starting");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let data_dir = resolve_writable_data_dir(app);
            info!(data_dir = %data_dir.display(), "Using persistent vault directory");

            let journal = Journal::open(data_dir.join("journal.db")).or_else(|e| {
                warn!("Primary journal open failed ({}), falling back to temp vault", e);
                let fb = std::env::temp_dir().join("aegis-guard-journal.db");
                Journal::open(fb)
            })?;

            let engine = ResponseEngine::new(&data_dir).or_else(|e| {
                warn!("Primary ResponseEngine init failed ({}), falling back to temp vault", e);
                let fb = std::env::temp_dir().join("aegis-guard-engine");
                let _ = std::fs::create_dir_all(&fb);
                ResponseEngine::new(&fb)
            })?;

            let settings: SystemSettings = AppState::load_persisted(&data_dir, "system_settings.json");
            let packet_config: PacketInspectorConfig =
                AppState::load_persisted(&data_dir, "packet_inspector_config.json");
            let prune_config: AutoPruneConfig =
                AppState::load_persisted(&data_dir, "auto_prune_config.json");
            let net_config: NetDefenseConfig =
                AppState::load_persisted(&data_dir, "net_defense_config.json");
            let malware_results: Vec<MalwareScanResult> =
                AppState::load_persisted(&data_dir, "malware_results.json");
            let blocked_set: HashSet<String> = net_config.blocked_ip_list.iter().cloned().collect();

            let state = Arc::new(AppState {
                journal: Mutex::new(journal),
                response_engine: engine,
                data_dir: data_dir.clone(),
                settings: Mutex::new(settings),
                packet_config: Mutex::new(packet_config),
                prune_config: Mutex::new(prune_config),
                net_config: Mutex::new(net_config),
                blocked_ips: Mutex::new(blocked_set),
                malware_results: Mutex::new(malware_results),
                auto_remediation: Mutex::new(true),
                files_scanned: Mutex::new(0),
                threats_blocked: Mutex::new(0),
                last_pruned_ts: Mutex::new(None),
                packets_inspected: Mutex::new(0),
            });
            app.manage(state.clone());

            let raw_socket = std::env::var("AEGIS_SOCKET")
                .unwrap_or_else(|_| ipc::DEFAULT_SOCKET_PATH.to_string());
            let socket = ensure_socket_dir_permissions(&raw_socket);

            let app1 = app.handle().clone();
            let st1 = state.clone();
            tauri::async_runtime::spawn(ipc_bridge::run(socket, st1, app1));

            let app2 = app.handle().clone();
            let st2 = state.clone();
            tauri::async_runtime::spawn(net_bridge::run(st2, app2));

            let st5 = state.clone();
            let app5 = app.handle().clone();
            let dir5 = data_dir.clone();
            tauri::async_runtime::spawn(async move {
                phase5_bridge::start(st5, app5, dir5).await;
            });

            // Built-in standalone live telemetry emitter so the desktop UI always
            // displays real OS processes, CPU/RAM metrics & network counters even without systemd daemons.
            let app_live = app.handle().clone();
            let st_live = state.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
                    let inspect_on = st_live
                        .settings
                        .lock()
                        .map(|s| s.process_inspection_enabled)
                        .unwrap_or(true);
                    let net_on = st_live
                        .settings
                        .lock()
                        .map(|s| s.net_admin_enabled)
                        .unwrap_or(true);

                    if inspect_on {
                        if let Ok((tree, metrics)) =
                            tokio::task::spawn_blocking(commands::collect_host_snapshot).await
                        {
                            let _ = app_live.emit(
                                "proc-snapshot",
                                &serde_json::json!({ "tree": tree, "metrics": metrics }),
                            );
                        }
                    }

                    if net_on {
                        let blocked = st_live
                            .blocked_ips
                            .lock()
                            .map(|b| b.clone())
                            .unwrap_or_default();
                        let pkt_cfg = st_live
                            .packet_config
                            .lock()
                            .map(|c| c.clone())
                            .unwrap_or_default();
                        let pkts = st_live
                            .packets_inspected
                            .lock()
                            .map(|mut p| {
                                *p += 1;
                                *p
                            })
                            .unwrap_or(1);
                        let go_up = tokio::time::timeout(
                            std::time::Duration::from_millis(80),
                            tokio::net::TcpStream::connect("127.0.0.1:50053"),
                        )
                        .await
                        .map(|r| r.is_ok())
                        .unwrap_or(false);

                        if let Ok((conns, net_dev)) = tokio::task::spawn_blocking(move || {
                            let c = commands::collect_connections(&blocked);
                            let n = commands::collect_network_metrics();
                            (c, n)
                        })
                        .await
                        {
                            let pkt = commands::build_packet_inspection_snapshot(
                                &pkt_cfg, &conns, &net_dev, pkts, go_up,
                            );
                            let _ = app_live.emit(
                                "net-update",
                                &serde_json::json!({ "connections": conns, "netDev": net_dev }),
                            );
                            let _ = app_live.emit("packet-inspection", &pkt);
                        }
                    }
                }
            });

            let app_u = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(12)).await;
                loop {
                    if let Ok(i) = updater::check_update().await {
                        if i.update_available {
                            let _ = app_u.emit("update-available", &i);
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(86400)).await;
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_incidents,
            commands::list_debug_log,
            commands::resolve_incident,
            commands::count_open,
            commands::export_markdown,
            commands::export_json,
            commands::scan_entropy,
            commands::check_update,
            commands::set_auto_update,
            commands::apply_update,
            commands::generate_challenge,
            commands::execute_action,
            commands::list_audit_log,
            commands::verify_audit_chain,
            commands::list_whitelist,
            commands::remove_from_whitelist,
            commands::get_ioc_stats,
            commands::check_ioc_manual,
            commands::list_canaries,
            commands::create_canary,
            commands::delete_canary,
            commands::get_behavioral_stats,
            commands::trust_user_app,
            commands::remove_user_app_safeguard,
            commands::list_user_apps,
            commands::list_user_whitelisted_apps,
            commands::remove_user_whitelisted_app,
            commands::list_processes,
            commands::get_system_metrics,
            commands::get_network_metrics,
            commands::get_packet_inspection,
            commands::set_packet_inspector_config,
            commands::get_system_settings,
            commands::update_system_settings,
            commands::get_runtime_info,
            commands::isolate_to_sandbox,
            commands::simulate_network_attack,
            commands::block_ip_address,
            commands::unblock_ip_address,
            commands::block_remote_ip,
            commands::unblock_remote_ip,
            commands::list_network_connections,
            commands::list_dns_queries,
            commands::list_network_attacks,
            commands::get_network_defense_config,
            commands::update_network_defense_config,
            commands::terminate_network_connection,
            commands::list_telemetry,
            commands::evaluate_command,
            commands::simulate_movement_scenario,
            commands::list_sandbox_reports,
            commands::launch_sandbox_jail,
            commands::terminate_sandbox_jail,
            commands::send_target_to_sandbox,
            commands::list_virus_signatures,
            commands::list_malware_results,
            commands::get_av_stats,
            commands::scan_malware_target,
            commands::scan_directory_malware,
            commands::quick_system_av_scan,
            commands::test_malware_sample,
            commands::quarantine_malware,
            commands::quarantine_malware_file,
            commands::confirm_malware_quarantine,
            commands::set_auto_remediation,
            commands::get_storage_stats,
            commands::prune_logs,
            commands::get_auto_prune_config,
            commands::update_auto_prune_config,
            commands::list_temp_artifacts,
            commands::trigger_canary_test,
        ])
        .run(tauri::generate_context!())
        .expect("error running Tauri application");
}
