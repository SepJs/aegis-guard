use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Confidence { Low, Medium, High }

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::High   => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low    => write!(f, "LOW"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetail {
    pub rule:          String,
    pub confidence:    Confidence,
    pub priority_tier: String,
    pub risk_score:    u8,
    pub reason:        String,
    pub parent_exe:    Option<String>,
    pub ancestors:     Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcEventKind { Spawned, Exited, StateChanged, Anomaly }

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid:         u32,
    pub ppid:        u32,
    pub name:        String,
    pub state:       char,
    pub state_label: String,
    pub cpu_pct:     f32,
    pub cpu_ticks:   u64,
    pub mem_rss_kb:  u64,
    pub threads:     u32,
    pub cmdline:     Vec<String>,
    pub exe:         Option<String>,
    pub cwd:         Option<String>,
    pub uid:         u32,
    pub gid:         u32,
    pub start_time:  u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcEvent {
    pub id:          String,
    pub kind:        ProcEventKind,
    pub pid:         u32,
    pub ppid:        u32,
    pub name:        String,
    pub state:       char,
    pub state_label: String,
    pub cpu_pct:     f32,
    pub mem_rss_kb:  u64,
    pub threads:     u32,
    pub cmdline:     Vec<String>,
    pub exe:         Option<String>,
    pub cwd:         Option<String>,
    pub uid:         u32,
    pub gid:         u32,
    pub start_time:  u64,
    pub anomaly:     Option<AnomalyDetail>,
    pub ts:          i64,
}

impl ProcEvent {
    pub fn from_proc(info: &ProcInfo, kind: ProcEventKind, anomaly: Option<AnomalyDetail>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(), kind,
            pid: info.pid, ppid: info.ppid, name: info.name.clone(),
            state: info.state, state_label: info.state_label.clone(),
            cpu_pct: info.cpu_pct, mem_rss_kb: info.mem_rss_kb, threads: info.threads,
            cmdline: info.cmdline.clone(), exe: info.exe.clone(), cwd: info.cwd.clone(),
            uid: info.uid, gid: info.gid, start_time: info.start_time,
            anomaly, ts: Utc::now().timestamp_millis(),
        }
    }
}
