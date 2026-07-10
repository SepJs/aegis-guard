use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfProtectKind { BinaryTampered, PtraceDetected, AuditChainBroken, SocketTampered, JournalTampered }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfProtectEvent { pub id: String, pub kind: SelfProtectKind, pub confidence: String, pub reason: String, pub detail: String, pub ts: i64 }
