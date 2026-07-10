use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IocKind { Ip, Domain, Md5, Sha1, Sha256, Url }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry { pub ioc: String, pub kind: IocKind, pub feed: String, pub threat_type: String, pub confidence: u8, pub added_ts: i64 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch { pub ioc: String, pub kind: IocKind, pub threat_type: String, pub feed: String, pub confidence: u8, pub context: String }
