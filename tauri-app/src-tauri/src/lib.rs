// lib.rs — Aegis-Guard Tauri backend (Phase 3: + network observer bridge)

mod commands;
mod ipc_bridge;
mod net_bridge;
mod state;

use std::sync::{Arc, Mutex};
use tauri::Manager;
use tracing::info;
use tracing_subscriber::EnvFilter;
use journal::Journal;
use state::AppState;

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("AEGIS_LOG")
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    info!("Aegis-Guard Tauri backend starting — Phase 3");

    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app.path().app_data_dir()
                .expect("no app data dir");
            std::fs::create_dir_all(&data_dir)?;

            let db_path = data_dir.join("journal.db");
            info!(path = %db_path.display(), "opening journal");

            let journal = Journal::open(&db_path)
                .expect("failed to open journal database");

            let state = Arc::new(AppState {
                journal: Mutex::new(journal),
            });

            app.manage(state.clone());

            // ── IPC bridge — reads process-engine Unix socket ──────────────
            let socket_path = std::env::var("AEGIS_SOCKET")
                .unwrap_or_else(|_| ipc::DEFAULT_SOCKET_PATH.to_string());

            let app1 = app.handle().clone();
            let st1  = state.clone();
            tokio::spawn(ipc_bridge::run(socket_path, st1, app1));

            // ── Net bridge — connects to network-observer TCP bridge ────────
            // Only spawns if AEGIS_NET=1 is set (observer may not be running)
            if std::env::var("AEGIS_NET").as_deref() == Ok("1") {
                let app2 = app.handle().clone();
                let st2  = state.clone();
                tokio::spawn(net_bridge::run(st2, app2));
                info!("network observer bridge enabled (port 50053)");
            } else {
                info!("network observer bridge disabled (set AEGIS_NET=1 to enable)");
            }

            // ── Background update checker ──────────────────────────────────
            let app3 = app.handle().clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                loop {
                    match updater::check_update().await {
                        Ok(info) if info.update_available => {
                            info!(latest = %info.latest_version, "update available");
                            let _ = app3.emit("update-available", &info);
                        }
                        Ok(_)  => info!("up to date"),
                        Err(e) => tracing::warn!("update check failed: {e}"),
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
        ])
        .run(tauri::generate_context!())
        .expect("error running Tauri application");
}
