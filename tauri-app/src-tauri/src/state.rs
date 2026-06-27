// state.rs — shared application state
use std::sync::Mutex;
use journal::Journal;

pub struct AppState {
    pub journal: Mutex<Journal>,
}
