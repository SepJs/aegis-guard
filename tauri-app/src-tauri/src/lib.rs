// lib.rs — Aegis-Guard Tauri backend (Phase 5: full stack)
//
// On startup, this also self-heals the IPC socket directory permissions
// (mode 1777, like /tmp) so the dashboard — running as a normal user —
// can always bind the socket, regardless of how /run/aegis was created.

mod commands;
mod ipc_bridge;
mod net_bridge;
mod phase5_bridge;
mod state;

use std::sync::{Arc, Mutex};
use tauri::{Emitter, Manager};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use active_defense::ResponseEngine;
use journal::Journal;
use state::AppState;

/// Ensure the socket directory exists and is writable by any local user.
/// Sticky bit (mode 1777) means anyone can create a file here, but only
/// the file's owner can delete/replace it — same model as /tmp.
///
/// If installed via installers/install-linux.sh, a systemd-tmpfiles rule
/// already sets this up correctly on every boot (since /run is a tmpfs and
/// gets wiped on reboot) — in that case this function is a harmless no-op.
/// We only attempt to chmod it ourselves as a fallback for dev-mode runs
/// where that rule isn't installed, and only warn if the permissions are
/// actually insufficient AND we can't fix them (expected when the directory
/// is root-owned, since a normal user can never chmod another owner's
/// directory even when — as in the tmpfiles.d case — it's already correct).
fn ensure_socket_dir_permissions(socket_path: &str) {
    let dir = std::path::Path::new(socket_path).parent().unwrap_or(std::path::Path::new("/run/aegis"));

    if !dir.exists() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            warn!("could not create socket dir {}: {e} (may need sudo mkdir -p {})", dir.display(), dir.display());
            return;
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let already_ok = std::fs::metadata(dir)
            .map(|m| m.permissions().mode() & 0o1777 == 0o1777)
            .unwrap_or(false);

        if already_ok {
            info!(dir = %dir.display(), "socket directory permissions already correct (1777)");
            return;
        }

        let sticky_world_writable = std::fs::Permissions::from_mode(0o1777);
        if let Err(e) = std::fs::set_permissions(dir, sticky_world_writable) {
            warn!(
                "could not set permissions on {}: {e}. If the dashboard shows 'waiting for engine', run: sudo chmod 1777 {}",
                dir.display(), dir.display()
            );
        } else {
            info!(dir = %dir.display(), "socket directory permissions ensured (1777)");
        }
    }
}

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env("AEGIS_LOG").unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .init();

    info!("Aegis-Guard Tauri backend starting — by Vladimir Unknown");

    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app.path().app_data_dir().expect("no app data dir");
            std::fs::create_dir_all(&data_dir)?;

            let journal = Journal::open(data_dir.join("journal.db")).expect("failed to open journal");
            let engine = ResponseEngine::new(&data_dir).expect("failed to init response engine");

            let state = Arc::new(AppState { journal: Mutex::new(journal), response_engine: engine });
            app.manage(state.clone());

            let socket = std::env::var("AEGIS_SOCKET").unwrap_or_else(|_| ipc::DEFAULT_SOCKET_PATH.to_string());
            ensure_socket_dir_permissions(&socket);

            let app1 = app.handle().clone();
            let st1 = state.clone();
            // tauri::async_runtime::spawn (not tokio::spawn) — .setup() runs
            // synchronously, before any Tokio task context exists on this
            // thread. Tauri owns and manages its own internal Tokio runtime;
            // this is the correct way to schedule work onto it from here.
            // (Nested tokio::spawn calls made *inside* these spawned tasks
            // are fine, since by then we're genuinely executing on a Tokio
            // worker thread with proper runtime context.)
            tauri::async_runtime::spawn(ipc_bridge::run(socket, st1, app1));

            if std::env::var("AEGIS_NET").as_deref() == Ok("1") {
                let app2 = app.handle().clone();
                let st2 = state.clone();
                tauri::async_runtime::spawn(net_bridge::run(st2, app2));
                info!("network observer bridge enabled");
            }

            let st5 = state.clone();
            let app5 = app.handle().clone();
            let dir5 = data_dir.clone();
            tauri::async_runtime::spawn(async move { phase5_bridge::start(st5, app5, dir5).await; });

            let app_u = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                loop {
                    if let Ok(i) = updater::check_update().await {
                        if i.update_available { let _ = app_u.emit("update-available", &i); }
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
