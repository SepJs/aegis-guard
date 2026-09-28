use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity { Critical, High, Medium, Low, Informational }

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Informational => write!(f, "informational"),
        }
    }
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "informational" => Self::Informational,
            _ => Self::Low,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIncident {
    pub id: String, pub kind: String, pub severity: Severity,
    #[serde(default)]
    pub risk_score: f64,
    pub pid: u32, pub ppid: u32, pub process: String,
    pub cmdline: Vec<String>, pub exe_path: Option<String>,
    pub rule: String, pub confidence: String, pub reason: String,
    pub ancestors: Vec<u32>, pub ts: DateTime<Utc>, pub resolved: bool, pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugEntry {
    pub id: String, pub rule: String, pub pid: u32, pub process: String,
    pub ts: DateTime<Utc>, pub note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppression_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adjusted_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}
