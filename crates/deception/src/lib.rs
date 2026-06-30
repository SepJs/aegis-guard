// deception/src/lib.rs — Phase 5: Honeypot processes + trap files
//
// Strategy:
//   TRAP FILES: create bait files in predictable attacker-enumerated locations
//     (/tmp/.ssh_config, /root/.bash_history_bak, ~/.aws/credentials_backup, etc.)
//     Any read/write/exec of these files = immediate high-confidence alert.
//
//   HONEYPOT PROCESS: spawn a fake "sshd" or "apache2" process that accepts
//     connections but immediately closes them and logs the source.
//     Any process attempting to kill/ptrace it = alert.
//
//   CANARY TOKENS: embed unique tokens in files; if they appear in network traffic
//     → data exfiltration detected.

pub mod trap;
pub mod honeypot;
pub mod canary;
pub mod models;

pub use models::{DeceptionEvent, TrapKind};
pub use trap::TrapManager;
pub use honeypot::HoneypotManager;
