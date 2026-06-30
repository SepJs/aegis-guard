// state.rs — shared application state (Phase 4: + ResponseEngine)

use std::sync::Mutex;
use active_defense::ResponseEngine;
use journal::Journal;

pub struct AppState {
    pub journal:         Mutex<Journal>,
    pub response_engine: Mutex<ResponseEngine>,
}
