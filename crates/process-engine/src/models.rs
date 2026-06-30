// models.rs — canonical data structures for Aegis-Guard process engine
// These types are serialised over the Unix socket to the Tauri backend (Week 2).

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Confidence ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::High   => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low    => write!(f, "LOW"),
        }
    }
}

// ── AnomalyDetail ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetail {
    /// Rule identifier e.g. "PAR-001"
    pub rule: String,
    /// Confidence level for this detection
    pub confidence: Confidence,
    /// Human-readable explanation shown in the dashboard
    pub reason: String,
    /// Resolved path of the parent's executable (if available)
    pub parent_exe: Option<String>,
    /// Full ancestor PID chain up to init (PID 1), nearest-first
    pub ancestors: Vec<u32>,
}

// ── ProcEventKind ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcEventKind {
    /// Process appeared in /proc for the first time this session
    Spawned,
    /// Process disappeared from /proc (exited or killed)
    Exited,
    /// Anomalous behaviour detected on an already-tracked process
    Anomaly,
}

// ── ProcInfo ──────────────────────────────────────────────────────────────────
// Internal snapshot — collected from /proc, not sent over the wire directly.

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid:        u32,
    pub ppid:       u32,
    pub name:       String,
    /// Full argv vector parsed from /proc/[pid]/cmdline
    pub cmdline:    Vec<String>,
    /// Resolved symlink of /proc/[pid]/exe — may end in " (deleted)"
    pub exe:        Option<String>,
    /// Current working directory from /proc/[pid]/cwd
    pub cwd:        Option<String>,
    pub uid:        u32,
    pub gid:        u32,
    /// Process start time in jiffies since boot (from /proc/[pid]/stat)
    pub start_time: u64,
}

// ── ProcEvent ─────────────────────────────────────────────────────────────────
// Wire type — serialised as length-prefixed JSON over the Unix socket.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcEvent {
    /// Unique event ID (UUIDv4)
    pub id:         String,
    pub kind:       ProcEventKind,
    pub pid:        u32,
    pub ppid:       u32,
    pub name:       String,
    pub cmdline:    Vec<String>,
    pub exe:        Option<String>,
    pub cwd:        Option<String>,
    pub uid:        u32,
    pub gid:        u32,
    pub start_time: u64,
    /// Present only when kind == Anomaly (and sometimes on Spawned)
    pub anomaly:    Option<AnomalyDetail>,
    /// Unix timestamp in milliseconds (UTC)
    pub ts:         i64,
}

impl ProcEvent {
    pub fn from_proc(info: &ProcInfo, kind: ProcEventKind, anomaly: Option<AnomalyDetail>) -> Self {
        Self {
            id:         Uuid::new_v4().to_string(),
            kind,
            pid:        info.pid,
            ppid:       info.ppid,
            name:       info.name.clone(),
            cmdline:    info.cmdline.clone(),
            exe:        info.exe.clone(),
            cwd:        info.cwd.clone(),
            uid:        info.uid,
            gid:        info.gid,
            start_time: info.start_time,
            anomaly,
            ts:         Utc::now().timestamp_millis(),
        }
    }
}
