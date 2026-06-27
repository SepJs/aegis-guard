// journal/src/models.rs — persistent record types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::High   => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low    => write!(f, "low"),
        }
    }
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s {
            "high"   => Self::High,
            "medium" => Self::Medium,
            _        => Self::Low,
        }
    }
}

/// A persisted threat detection — written to `threat_incidents`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIncident {
    /// UUIDv4 primary key
    pub id:         String,
    /// Detection category e.g. "suspicious_parentage"
    pub kind:       String,
    pub severity:   Severity,
    pub pid:        u32,
    pub ppid:       u32,
    /// Process name (comm)
    pub process:    String,
    /// Full argv as JSON array string
    pub cmdline:    Vec<String>,
    pub exe_path:   Option<String>,
    /// Rule that triggered e.g. "PAR-001"
    pub rule:       String,
    /// Confidence level: "high" | "medium" | "low"
    pub confidence: String,
    /// Human-readable explanation
    pub reason:     String,
    /// Ancestor PID chain as JSON array
    pub ancestors:  Vec<u32>,
    pub ts:         DateTime<Utc>,
    /// 0 = open, 1 = resolved by user
    pub resolved:   bool,
    /// BLAKE3 digest of all fields (tamper-evident)
    pub digest:     String,
}

/// A benign / false-positive event written to `debug_log`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugEntry {
    pub id:      String,
    pub rule:    String,
    pub pid:     u32,
    pub process: String,
    pub ts:      DateTime<Utc>,
    /// Why this was flagged but not promoted to a threat
    pub note:    String,
}
