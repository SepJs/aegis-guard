// lib.rs — Aegis-Guard Tauri backend (Phase 5: full stack)

mod commands;
mod ipc_bridge;
mod net_bridge;
mod phase5_bridge;
mod state;

use std::sync::{Arc, Mutex};
use tauri::{Emitter, Manager};
use tracing::info;
use tracing_subscriber::EnvFilter;

use active_defense::ResponseEngine;
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

    info!("Aegis-Guard Tauri backend starting — Phase 5 (Full Stack)");

    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app.path().app_data_dir()
                .expect("no app data dir");
            std::fs::create_dir_all(&data_dir)?;

            let journal = Journal::open(data_dir.join("journal.db"))
                .expect("failed to open journal");
            let engine  = ResponseEngine::new(&data_dir)
                .expect("failed to init response engine");

            let state = Arc::new(AppState {
                journal:         Mutex::new(journal),
                response_engine: engine,
            });
            app.manage(state.clone());

            // ── Phase 1-2: Process engine IPC ─────────────────────────────────
            let socket = std::env::var("AEGIS_SOCKET")
                .unwrap_or_else(|_| ipc::DEFAULT_SOCKET_PATH.to_string());
            tokio::spawn(ipc_bridge::run(socket, state.clone(), app.handle().clone()));

            // ── Phase 3: Network observer bridge ──────────────────────────────
            if std::env::var("AEGIS_NET").as_deref() == Ok("1") {
                tokio::spawn(net_bridge::run(state.clone(), app.handle().clone()));
                info!("network observer bridge enabled");
            }

            // ── Phase 5: Behavioral + TI + Self-protect + Canary ─────────────
            let st5   = state.clone();
            let app5  = app.handle().clone();
            let dir5  = data_dir.clone();
            tokio::spawn(async move {
                phase5_bridge::start(st5, app5, dir5).await;
            });

            // ── Update checker ────────────────────────────────────────────────
            let app_u = app.handle().clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
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
            commands::generate_challenge,
            commands::execute_action,
            commands::list_audit_log,
            commands::verify_audit_chain,
            commands::list_whitelist,
            commands::remove_from_whitelist,
            // Phase 5
            commands::get_ioc_stats,
            commands::check_ioc_manual,
            commands::list_canaries,
            commands::create_canary,
            commands::delete_canary,
            commands::get_behavioral_stats,
        ])
        .run(tauri::generate_context!())
        .expect("error running Tauri application");
}
