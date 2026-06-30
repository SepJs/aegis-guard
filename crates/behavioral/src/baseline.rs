// baseline.rs — behavioral baseline engine
//
// Collects observations, builds per-process baselines via Welford online
// algorithm (no need to store all historical samples), and emits anomalies
// when a process deviates beyond the configured Z-score threshold.

use std::collections::HashMap;
use std::fs;
use std::sync::RwLock;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use tracing::{debug, info, warn};

use crate::models::{BehaviorAnomaly, ProcessBaseline, ProcessObservation};
use crate::scorer::score_observation;

/// Minimum samples before anomaly detection activates for a process.
const MIN_SAMPLES_FOR_DETECTION: u64 = 30;

/// Z-score threshold above which we emit a behavioral anomaly.
const ANOMALY_Z_THRESHOLD: f64 = 3.5;

/// How often to sample /proc for observations (seconds).
const SAMPLE_INTERVAL_SECS: u64 = 5;

pub struct BehaviorEngine {
    baselines:  RwLock<HashMap<String, ProcessBaseline>>,
    persist_path: String,
}

impl BehaviorEngine {
    pub fn new(data_dir: &str) -> Result<Self> {
        let path = format!("{}/behavioral_baselines.json", data_dir);
        let baselines = if std::path::Path::new(&path).exists() {
            let raw  = fs::read_to_string(&path)?;
            serde_json::from_str::<HashMap<String, ProcessBaseline>>(&raw)
                .unwrap_or_default()
        } else {
            HashMap::new()
        };

        info!(
            loaded = baselines.len(),
            path   = %path,
            "behavioral baselines loaded"
        );

        Ok(Self {
            baselines:    RwLock::new(baselines),
            persist_path: path,
        })
    }

    /// Ingest one observation and return an anomaly if detected.
    pub fn observe(&self, obs: ProcessObservation) -> Option<BehaviorAnomaly> {
        let mut baselines = self.baselines.write().unwrap();
        let baseline      = baselines
            .entry(obs.name.clone())
            .or_insert_with(|| ProcessBaseline {
                name: obs.name.clone(),
                ..Default::default()
            });

        let n_before = baseline.sample_count;
        baseline.update(&obs);

        // Don't detect until we have enough samples
        if n_before < MIN_SAMPLES_FOR_DETECTION {
            debug!(
                name    = %obs.name,
                samples = n_before,
                needed  = MIN_SAMPLES_FOR_DETECTION,
                "still in learning phase"
            );
            return None;
        }

        // Score against baseline
        let (score, cpu_z, mem_z, conn_z, reason) =
            score_observation(&obs, baseline, ANOMALY_Z_THRESHOLD);

        if score > 0.0 {
            let confidence = if score > 80.0 { "high" }
                             else if score > 50.0 { "medium" }
                             else { "low" };

            Some(BehaviorAnomaly {
                pid:           obs.pid,
                name:          obs.name,
                anomaly_score: score,
                confidence:    confidence.to_string(),
                reason,
                cpu_z,
                mem_z,
                conn_z,
                ts:            Utc::now().timestamp_millis(),
            })
        } else {
            None
        }
    }

    /// Collect a snapshot from /proc and return it as an observation.
    pub fn collect_observation(pid: u32) -> Option<ProcessObservation> {
        let base = format!("/proc/{}", pid);

        // status: get Name + Threads + VmRSS
        let status = fs::read_to_string(format!("{}/status", base)).ok()?;
        let mut name = String::new();
        let mut mem_kb = 0u64;
        let mut threads = 0u32;

        for line in status.lines() {
            if let Some(v) = line.strip_prefix("Name:\t")   { name = v.trim().into(); }
            if let Some(v) = line.strip_prefix("VmRSS:\t")  {
                mem_kb = v.split_whitespace().next()
                    .and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            if let Some(v) = line.strip_prefix("Threads:\t") {
                threads = v.trim().parse().unwrap_or(0);
            }
        }
        if name.is_empty() { return None; }

        // Count children
        let children = fs::read_to_string(format!("{}/task/{}/children", base, pid))
            .map(|s| s.split_whitespace().count() as u32)
            .unwrap_or(0);

        // Count open FDs
        let fd_count = fs::read_dir(format!("{}/fd", base))
            .map(|d| d.count() as u32)
            .unwrap_or(0);

        // Count network connections (TCP only for speed)
        let conn_count = count_process_connections(pid);

        // CPU: simple approximation via stat field 14+15 (utime+stime)
        let cpu_pct = read_cpu_pct(pid);

        Some(ProcessObservation {
            pid,
            name,
            ts:           Utc::now().timestamp_millis(),
            cpu_pct,
            mem_kb,
            child_count:  children,
            fd_count,
            conn_count,
            thread_count: threads,
        })
    }

    /// Persist baselines to disk.
    pub fn persist(&self) -> Result<()> {
        let data = self.baselines.read().unwrap();
        let json = serde_json::to_string_pretty(&*data)?;
        fs::write(&self.persist_path, json)?;
        Ok(())
    }

    pub fn baseline_count(&self) -> usize {
        self.baselines.read().unwrap().len()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn count_process_connections(pid: u32) -> u32 {
    let inode_set = collect_proc_fd_inodes(pid);
    if inode_set.is_empty() { return 0; }

    let mut count = 0u32;
    for proto in &["tcp", "tcp6", "udp"] {
        if let Ok(content) = fs::read_to_string(format!("/proc/net/{}", proto)) {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 10 { continue; }
                if let Ok(inode) = fields[9].parse::<u64>() {
                    if inode_set.contains(&inode) {
                        count += 1;
                    }
                }
            }
        }
    }
    count
}

fn collect_proc_fd_inodes(pid: u32) -> std::collections::HashSet<u64> {
    let mut set = std::collections::HashSet::new();
    let Ok(entries) = fs::read_dir(format!("/proc/{}/fd", pid)) else { return set; };
    for entry in entries.flatten() {
        let Ok(link) = fs::read_link(entry.path()) else { continue; };
        let s = link.to_string_lossy();
        if s.starts_with("socket:[") {
            if let Some(inode_str) = s.strip_prefix("socket:[").and_then(|s| s.strip_suffix("]")) {
                if let Ok(inode) = inode_str.parse::<u64>() {
                    set.insert(inode);
                }
            }
        }
    }
    set
}

fn read_cpu_pct(pid: u32) -> f64 {
    // Simplified: read utime+stime from /proc/[pid]/stat, divide by uptime
    // This is a rough approximation sufficient for anomaly baseline purposes
    let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", pid)) else { return 0.0 };
    let after_comm = stat.rfind(')').unwrap_or(0);
    let fields: Vec<&str> = stat[after_comm+2..].split_whitespace().collect();
    if fields.len() < 15 { return 0.0; }
    let utime: u64 = fields[11].parse().unwrap_or(0);
    let stime: u64 = fields[12].parse().unwrap_or(0);
    let Ok(uptime) = fs::read_to_string("/proc/uptime") else { return 0.0 };
    let uptime_secs: f64 = uptime.split_whitespace()
        .next().and_then(|s| s.parse().ok()).unwrap_or(1.0);
    let clk_tck = 100.0f64; // standard HZ
    ((utime + stime) as f64 / clk_tck) / uptime_secs * 100.0
}
