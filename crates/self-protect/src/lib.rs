// self-protect/src/lib.rs — Phase 5: Aegis-Guard self-integrity verification
//
// Protects the security tool itself from being tampered with or disabled:
//
//   1. BINARY INTEGRITY: BLAKE3 hash of own binary on startup, re-checked every 60s
//      If the binary on disk changes while running → tamper alert
//
//   2. PTRACE DETECTION: detect if process-engine is being debugged/traced
//      /proc/self/status TracerPid != 0 → someone is ptrace-attaching
//
//   3. AUDIT LOG INTEGRITY: re-verify BLAKE3 chain on a schedule
//      If chain breaks → journal was tampered with
//
//   4. SOCKET PROTECTION: verify /run/aegis/proc.sock permissions
//      If socket is replaced or permissions changed → alert

pub mod binary;
pub mod ptrace;
pub mod integrity;
pub mod models;

pub use models::{SelfProtectEvent, SelfProtectKind};
pub use integrity::IntegrityMonitor;
