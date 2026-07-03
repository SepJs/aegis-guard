// audit.rs — immutable BLAKE3-chained audit log
//
// Every active defense action is recorded BEFORE and AFTER execution.
// Entries are chained: each entry's digest includes the previous entry's digest.
// This makes the log tamper-evident — any modification breaks the chain.
//
// Stored in SQLite at /var/lib/aegis/audit.db
//
// rusqlite::Connection is Send but NOT Sync (it uses RefCell internally for
// its prepared-statement cache), so it must be wrapped in a Mutex before
// AuditLog can be placed behind an Arc and shared across async tasks.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use uuid::Uuid;

use crate::models::ActionRequest;

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    action      TEXT NOT NULL,
    pid         INTEGER NOT NULL,
    process     TEXT NOT NULL,
    incident_id TEXT,
    note        TEXT,
    status      TEXT NOT NULL DEFAULT 'pending',
    outcome     TEXT,
    ts_before   INTEGER NOT NULL,
    ts_after    INTEGER,
    -- BLAKE3 chain: H(prev_digest || this_entry_fields)
    prev_digest TEXT NOT NULL DEFAULT '',
    digest      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts_before DESC);
";

pub struct AuditLog {
    conn: Mutex<Connection>,
}

impl AuditLog {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let conn = Connection::open(path)
            .context("open audit db")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Lock the connection, recovering from a poisoned mutex rather than
    /// panicking — a panic during one audit write should not take down
    /// every subsequent audit read/write for the life of the process.
    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Record an action BEFORE it executes. Returns the audit entry ID.
    pub fn record_before(&self, req: &ActionRequest) -> Result<String> {
        let id     = Uuid::new_v4().to_string();
        let ts     = Utc::now().timestamp_millis();
        let action = format!("{:?}", req.kind);
        let prev   = self.last_digest().unwrap_or_default();
        let digest = compute_chain_digest(&prev, &id, &action, req.pid, ts);

        self.conn().execute(
            "INSERT INTO audit_log
             (id, action, pid, process, incident_id, note,
              status, ts_before, prev_digest, digest)
             VALUES (?1,?2,?3,?4,?5,?6,'pending',?7,?8,?9)",
            params![
                id, action,
                req.pid, req.process_name,
                req.incident_id,
                req.note,
                ts,
                prev,
                digest,
            ],
        ).context("insert audit before")?;

        Ok(id)
    }

    /// Update the audit entry AFTER execution with outcome.
    pub fn record_after(&self, id: &str, success: bool, outcome: &str) -> Result<()> {
        let status = if success { "success" } else { "failed" };
        self.conn().execute(
            "UPDATE audit_log SET status=?1, outcome=?2, ts_after=?3 WHERE id=?4",
            params![status, outcome, Utc::now().timestamp_millis(), id],
        )?;
        Ok(())
    }

    /// Fetch audit entries, newest first.
    pub fn list(&self, limit: u32, offset: u32) -> Result<Vec<AuditEntry>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, action, pid, process, incident_id, note,
                    status, outcome, ts_before, ts_after, prev_digest, digest
             FROM audit_log
             ORDER BY ts_before DESC
             LIMIT ?1 OFFSET ?2"
        )?;
        let rows = stmt.query_map(params![limit, offset], |row| {
            Ok(AuditEntry {
                id:          row.get(0)?,
                action:      row.get(1)?,
                pid:         row.get(2)?,
                process:     row.get(3)?,
                incident_id: row.get(4)?,
                note:        row.get(5)?,
                status:      row.get(6)?,
                outcome:     row.get(7)?,
                ts_before:   row.get(8)?,
                ts_after:    row.get(9)?,
                prev_digest: row.get(10)?,
                digest:      row.get(11)?,
            })
        })?;
        rows.map(|r| r.map_err(|e| anyhow::anyhow!(e))).collect()
    }

    /// Verify the entire chain. Returns list of broken entries.
    pub fn verify_chain(&self) -> Result<Vec<String>> {
        let entries = self.list(10000, 0)?;
        let mut broken = Vec::new();
        for e in &entries {
            let expected = compute_chain_digest(
                &e.prev_digest, &e.id, &e.action, e.pid, e.ts_before
            );
            if expected != e.digest {
                broken.push(format!(
                    "CHAIN BROKEN at {} (action={} pid={})",
                    e.id, e.action, e.pid
                ));
            }
        }
        Ok(broken)
    }

    fn last_digest(&self) -> Option<String> {
        self.conn().query_row(
            "SELECT digest FROM audit_log ORDER BY ts_before DESC LIMIT 1",
            [], |row| row.get(0),
        ).ok()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    pub id:          String,
    pub action:      String,
    pub pid:         u32,
    pub process:     String,
    pub incident_id: Option<String>,
    pub note:        String,
    pub status:      String,
    pub outcome:     Option<String>,
    pub ts_before:   i64,
    pub ts_after:    Option<i64>,
    pub prev_digest: String,
    pub digest:      String,
}

fn compute_chain_digest(
    prev:   &str,
    id:     &str,
    action: &str,
    pid:    u32,
    ts:     i64,
) -> String {
    let mut h = blake3::Hasher::new();
    h.update(prev.as_bytes());
    h.update(id.as_bytes());
    h.update(action.as_bytes());
    h.update(&pid.to_le_bytes());
    h.update(&ts.to_le_bytes());
    h.finalize().to_hex().to_string()
}
