// entropy/src/lib.rs — on-demand Shannon entropy scanner
//
// Design rules (Phase 1):
//   • User-initiated ONLY — no background FS hooks, no inotify
//   • Single file or directory tree (via walkdir + rayon thread pool)
//   • Returns ScanResult per file: entropy score, risk classification,
//     MIME guess, and a human-readable threat label
//   • No kernel modules, no elevated privileges needed

pub mod scan;
pub mod classify;
pub mod models;

pub use models::{FileScanResult, RiskLevel, ScanRequest, ScanSummary};
pub use scan::scan_path;
