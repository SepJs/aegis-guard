//! Aegis-Guard deception layer: canaries, filesystem traps, and TCP honeypots.

pub mod trap;
pub mod honeypot;
pub mod canary;
pub mod models;

pub use models::{DeceptionEvent, TrapKind};
pub use trap::TrapManager;
pub use honeypot::HoneypotManager;
pub use canary::CanaryManager;
