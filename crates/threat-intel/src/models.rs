// models.rs — threat intelligence data types

use serde::{Deserialize, Serialize};

/// Category of an Indicator of Compromise.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Ip,
    Domain,
    Md5,
    Sha1,
    Sha256,
    Url,
}

/// A single threat intel entry from a feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub ioc:        String,
    pub kind:       IocKind,
    pub feed:       String,
    pub threat_type: String,
    pub confidence: u8,   // 0–100
    pub added_ts:   i64,
}

/// Result when an IOC matches a known threat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    pub ioc:         String,
    pub kind:        IocKind,
    pub threat_type: String,
    pub feed:        String,
    pub confidence:  u8,
    /// Context: which process triggered this (pid, name, connection)
    pub context:     String,
}
