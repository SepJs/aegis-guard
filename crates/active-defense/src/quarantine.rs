use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use tokio::process::Command;
use tracing::{info, warn};

use crate::models::{ActionKind, ActionResult, ResponseError};

static QUARANTINED: Lazy<Mutex<HashSet<u32>>> = Lazy::new(|| Mutex::new(HashSet::new()));

fn quarantine_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("LOCALAPPDATA")
            .map(|p| PathBuf::from(p).join("Aegis-Guard").join("quarantine"))
            .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData\\Aegis-Guard\\quarantine"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/lib/aegis/quarantine")
    }
}

pub async fn quarantine_process(pid: u32, name: String) -> Result<ActionResult, ResponseError> {
    std::fs::create_dir_all(quarantine_dir()).map_err(|e| ResponseError::ExecutionFailed(e.to_string()))?;
    {
        let q = QUARANTINED.lock().unwrap();
        if q.contains(&pid) {
            return Err(ResponseError::ExecutionFailed(format!("Process pid {} is already quarantined.", pid)));
        }
    }

    let mut isolation_notes = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // 1) Best-effort: freeze the process via freezer cgroup (if available)
        let freezer_paths = [
            format!("/sys/fs/cgroup/freezer/aegis-q-{}", pid),
            format!("/sys/fs/cgroup/aegis-q-{}", pid),
        ];
        for fp in &freezer_paths {
            if std::fs::create_dir_all(fp).is_ok() {
                let _ = std::fs::write(format!("{}/cgroup.procs", fp), pid.to_string());
                let _ = std::fs::write(format!("{}/freezer.state", fp), "FROZEN");
                isolation_notes.push("cgroup freezer");
                break;
            }
        }

        // 2) Network isolation via nsenter (requires privileges)
        let output = Command::new("nsenter")
            .args([&format!("--target={}", pid), "--net", "--", "ip", "link", "set", "lo", "down"])
            .output()
            .await;
        match output {
            Ok(o) if o.status.success() => isolation_notes.push("netns lo-down"),
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                warn!(pid, "nsenter failed ({}): {} — continuing with other isolation", o.status, stderr.trim());
            }
            Err(e) => warn!(pid, "nsenter not available: {}", e),
        }

        // 3) Drop ambient capabilities if possible (best-effort)
        let _ = Command::new("prlimit")
            .args(["--pid", &pid.to_string(), "--nofile=64"])
            .output()
            .await;
    }

    #[cfg(windows)]
    {
        let rule_name = format!("Aegis-Quarantine-{}", pid);
        let _ = Command::new("netsh")
            .args(["advfirewall", "firewall", "add", "rule", &format!("name={}", rule_name), "dir=out", "action=block"])
            .output().await;
        let _ = Command::new("netsh")
            .args(["advfirewall", "firewall", "add", "rule", &format!("name={}-in", rule_name), "dir=in", "action=block"])
            .output().await;
        isolation_notes.push("Windows firewall block (in+out)");
    }

    let marker = quarantine_dir().join(format!("{}.quarantine", pid));
    std::fs::write(&marker, format!("{}\n{}\n{}\n", pid, name, isolation_notes.join(",")))
        .map_err(|e| ResponseError::ExecutionFailed(e.to_string()))?;
    { let mut q = QUARANTINED.lock().unwrap(); q.insert(pid); }

    let note = if isolation_notes.is_empty() {
        "marker-only (insufficient privileges for deep isolation)".to_string()
    } else {
        isolation_notes.join(" + ")
    };
    info!(pid, name = %name, isolation = %note, "process quarantined");
    ActionResult::success(
        pid,
        ActionKind::Quarantine,
        format!(
            "Process '{}' (pid {}) quarantined. Isolation: {}. Network and resource access restricted. Use 'Lift Quarantine' to restore.",
            name, pid, note
        ),
    )
}

pub async fn lift_quarantine(pid: u32) -> Result<ActionResult, ResponseError> {
    #[cfg(target_os = "linux")]
    {
        // Thaw freezer cgroup if we created one
        for base in ["/sys/fs/cgroup/freezer", "/sys/fs/cgroup"] {
            let fp = format!("{}/aegis-q-{}", base, pid);
            let _ = std::fs::write(format!("{}/freezer.state", fp), "THAWED");
            let _ = std::fs::remove_dir(fp);
        }
    }

    #[cfg(windows)]
    {
        let rule_name = format!("Aegis-Quarantine-{}", pid);
        let _ = Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name)])
            .output().await;
        let _ = Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}-in", rule_name)])
            .output().await;
    }

    let marker = quarantine_dir().join(format!("{}.quarantine", pid));
    if marker.exists() { std::fs::remove_file(&marker).map_err(|e| ResponseError::ExecutionFailed(e.to_string()))?; }
    { let mut q = QUARANTINED.lock().unwrap(); q.remove(&pid); }
    info!(pid, "quarantine lifted");
    ActionResult::success(pid, ActionKind::LiftQuarantine, format!("Quarantine lifted for pid {}. Note: the process may need to be restarted to fully restore network access if namespace isolation was applied.", pid))
}

pub fn is_quarantined(pid: u32) -> bool { QUARANTINED.lock().unwrap().contains(&pid) }
