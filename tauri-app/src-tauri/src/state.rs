// state.rs — shared application state
//
// `journal` stays behind std::sync::Mutex (Journal wraps a raw
// rusqlite::Connection; lock is only ever held inside sync fns, never
// across an .await).
//
// `response_engine` has NO Mutex wrapper — ResponseEngine is already
// Send + Sync on its own (AuditLog/WhitelistStore each hold an internal
// Mutex), and all its methods take &self. Wrapping it again would force
// any async command awaiting while holding the guard to become non-Send.

use std::sync::Mutex;
use active_defense::ResponseEngine;
use journal::Journal;

pub struct AppState {
    pub journal:         Mutex<Journal>,
    pub response_engine: ResponseEngine,
}
