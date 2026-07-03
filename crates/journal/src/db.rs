// journal/src/db.rs — SQLite persistence layer
//
// Call from Tauri via spawn_blocking:
//   let journal = Journal::open("/var/lib/aegis/journal.db")?;
//   journal.insert_incident(&incident)?;
//   let all = journal.list_incidents(50, 0)?;

use std::path::Path;

use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use rusqlite::{params, Connection};
use tracing::{debug, info};
use uuid::Uuid;

use crate::digest;
use crate::models::{DebugEntry, Severity, ThreatIncident};

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS threat_incidents (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    pid         INTEGER NOT NULL,
    ppid        INTEGER NOT NULL,
    process     TEXT NOT NULL,
    cmdline     TEXT NOT NULL,
    exe_path    TEXT,
    rule        TEXT NOT NULL,
    confidence  TEXT NOT NULL,
    reason      TEXT NOT NULL,
    ancestors   TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    resolved    INTEGER NOT NULL DEFAULT 0,
    digest      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_ts ON threat_incidents(ts DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON threat_incidents(severity);

CREATE TABLE IF NOT EXISTS debug_log (
    id          TEXT PRIMARY KEY,
    rule        TEXT NOT NULL,
    pid         INTEGER NOT NULL,
    process     TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    note        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_debug_ts ON debug_log(ts DESC);
";

pub struct Journal {
    conn: Connection,
}

impl Journal {
    /// Open (or create) the journal database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create journal dir {}", parent.display()))?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("open journal db at {}", path.display()))?;

        conn.execute_batch(SCHEMA)
            .context("apply journal schema")?;

        info!(path = %path.display(), "journal database opened");

        Ok(Self { conn })
    }

    // ── Threat Incidents ──────────────────────────────────────────────────────

    /// Persist a new threat incident. Computes and sets the BLAKE3 digest.
    pub fn insert_incident(&self, mut inc: ThreatIncident) -> Result<ThreatIncident> {
        // Compute digest now that all fields are set
        inc.digest = digest::compute(&inc);

        self.conn.execute(
            "INSERT INTO threat_incidents
             (id, kind, severity, pid, ppid, process, cmdline, exe_path,
              rule, confidence, reason, ancestors, ts, resolved, digest)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                inc.id,
                inc.kind,
                inc.severity.to_string(),
                inc.pid,
                inc.ppid,
                inc.process,
                serde_json::to_string(&inc.cmdline)?,
                inc.exe_path,
                inc.rule,
                inc.confidence,
                inc.reason,
                serde_json::to_string(&inc.ancestors)?,
                inc.ts.timestamp_millis(),
                inc.resolved as i32,
                inc.digest,
            ],
        ).context("insert threat incident")?;

        debug!(id = %inc.id, rule = %inc.rule, "incident persisted");
        Ok(inc)
    }

    /// Fetch incidents, newest first. `limit` / `offset` for pagination.
    pub fn list_incidents(&self, limit: u32, offset: u32) -> Result<Vec<ThreatIncident>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, severity, pid, ppid, process, cmdline, exe_path,
                    rule, confidence, reason, ancestors, ts, resolved, digest
             FROM threat_incidents
             ORDER BY ts DESC
             LIMIT ?1 OFFSET ?2"
        )?;

        let rows = stmt.query_map(params![limit, offset], row_to_incident)?;
        let mut incidents = Vec::new();

        for row in rows {
            let inc = row?;
            // Verify integrity on read
            if let Err(e) = digest::verify(&inc) {
                tracing::error!("{}", e);
            }
            incidents.push(inc);
        }

        Ok(incidents)
    }

    /// Mark an incident as resolved (user dismissed it from the dashboard).
    pub fn resolve_incident(&self, id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE threat_incidents SET resolved = 1 WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Count open (unresolved) incidents — used for the dashboard badge.
    pub fn count_open(&self) -> Result<u32> {
        let n: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM threat_incidents WHERE resolved = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(n)
    }

    // ── Debug Log ─────────────────────────────────────────────────────────────

    /// Insert a benign / false-positive event into the debug log.
    pub fn insert_debug(&self, rule: &str, pid: u32, process: &str, note: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO debug_log (id, rule, pid, process, ts, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                Uuid::new_v4().to_string(),
                rule,
                pid,
                process,
                Utc::now().timestamp_millis(),
                note,
            ],
        )?;
        Ok(())
    }

    /// Fetch debug log entries, newest first.
    pub fn list_debug(&self, limit: u32, offset: u32) -> Result<Vec<DebugEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, rule, pid, process, ts, note
             FROM debug_log
             ORDER BY ts DESC
             LIMIT ?1 OFFSET ?2"
        )?;

        let rows = stmt.query_map(params![limit, offset], |row| {
            let ts_ms: i64 = row.get(4)?;
            Ok(DebugEntry {
                id:      row.get(0)?,
                rule:    row.get(1)?,
                pid:     row.get::<_, u32>(2)?,
                process: row.get(3)?,
                ts:      Utc.timestamp_millis_opt(ts_ms).unwrap(),
                note:    row.get(5)?,
            })
        })?;

        rows.map(|r| r.map_err(|e| anyhow::anyhow!(e)))
            .collect()
    }
}

// ── Row mapper ────────────────────────────────────────────────────────────────

fn row_to_incident(row: &rusqlite::Row<'_>) -> rusqlite::Result<ThreatIncident> {
    let ts_ms: i64          = row.get(12)?;
    let resolved: i32       = row.get(13)?;
    let cmdline_json: String = row.get(6)?;
    let ancestors_json: String = row.get(11)?;
    let severity_str: String = row.get(2)?;

    Ok(ThreatIncident {
        id:         row.get(0)?,
        kind:       row.get(1)?,
        severity:   Severity::from_str(&severity_str),
        pid:        row.get::<_, u32>(3)?,
        ppid:       row.get::<_, u32>(4)?,
        process:    row.get(5)?,
        cmdline:    serde_json::from_str(&cmdline_json).unwrap_or_default(),
        exe_path:   row.get(7)?,
        rule:       row.get(8)?,
        confidence: row.get(9)?,
        reason:     row.get(10)?,
        ancestors:  serde_json::from_str(&ancestors_json).unwrap_or_default(),
        ts:         Utc.timestamp_millis_opt(ts_ms).unwrap(),
        resolved:   resolved != 0,
        digest:     row.get(14)?,
    })
}
