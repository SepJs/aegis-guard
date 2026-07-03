// state.rs — shared application state
//
// `journal` stays behind a std::sync::Mutex because Journal wraps a raw
// rusqlite::Connection (not Sync) and its lock is only ever held inside
// synchronous #[tauri::command] fns — never across an .await.
//
// `response_engine` is stored directly with NO Mutex wrapper. ResponseEngine
// is already Send + Sync on its own (its AuditLog and WhitelistStore fields
// each hold their own internal Mutex), and all of its methods take &self.
// Wrapping it in an extra Mutex would force any async command that awaits
// while holding the guard to become non-Send, which is exactly the bug this
// fixes — Tauri's async command futures must be Send, and std::sync::MutexGuard
// is not.

use std::sync::Mutex;

use active_defense::ResponseEngine;
use journal::Journal;

pub struct AppState {
    pub journal:         Mutex<Journal>,
    pub response_engine: ResponseEngine,
}
