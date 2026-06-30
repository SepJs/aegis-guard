// models.rs — behavioral analysis data types

use serde::{Deserialize, Serialize};

/// A periodic snapshot of a process's resource usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessObservation {
    pub pid:           u32,
    pub name:          String,
    pub ts:            i64,
    /// CPU usage percentage (0.0–100.0)
    pub cpu_pct:       f64,
    /// RSS memory in KB
    pub mem_kb:        u64,
    /// Number of child processes
    pub child_count:   u32,
    /// Number of open file descriptors
    pub fd_count:      u32,
    /// Number of active network connections
    pub conn_count:    u32,
    /// Number of threads
    pub thread_count:  u32,
}

/// Statistical baseline for a named process.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessBaseline {
    pub name:         String,
    pub sample_count: u64,
    /// Running mean + M2 for Welford online algorithm
    pub cpu_mean:     f64,
    pub cpu_m2:       f64,
    pub mem_mean:     f64,
    pub mem_m2:       f64,
    pub child_mean:   f64,
    pub child_m2:     f64,
    pub conn_mean:    f64,
    pub conn_m2:      f64,
    pub fd_mean:      f64,
    pub fd_m2:        f64,
}

impl ProcessBaseline {
    /// Welford online variance update.
    pub fn update(&mut self, obs: &ProcessObservation) {
        self.sample_count += 1;
        let n = self.sample_count as f64;

        welford_update(&mut self.cpu_mean,   &mut self.cpu_m2,   obs.cpu_pct,        n);
        welford_update(&mut self.mem_mean,   &mut self.mem_m2,   obs.mem_kb as f64,  n);
        welford_update(&mut self.child_mean, &mut self.child_m2, obs.child_count as f64, n);
        welford_update(&mut self.conn_mean,  &mut self.conn_m2,  obs.conn_count as f64, n);
        welford_update(&mut self.fd_mean,    &mut self.fd_m2,    obs.fd_count as f64, n);
    }

    pub fn cpu_stddev(&self)   -> f64 { stddev(self.cpu_m2,   self.sample_count) }
    pub fn mem_stddev(&self)   -> f64 { stddev(self.mem_m2,   self.sample_count) }
    pub fn child_stddev(&self) -> f64 { stddev(self.child_m2, self.sample_count) }
    pub fn conn_stddev(&self)  -> f64 { stddev(self.conn_m2,  self.sample_count) }
    pub fn fd_stddev(&self)    -> f64 { stddev(self.fd_m2,    self.sample_count) }
}

/// Emitted when a process deviates significantly from its baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorAnomaly {
    pub pid:           u32,
    pub name:          String,
    /// 0.0–100.0 combined anomaly score
    pub anomaly_score: f64,
    pub confidence:    String,
    pub reason:        String,
    /// Per-metric Z-scores
    pub cpu_z:         f64,
    pub mem_z:         f64,
    pub conn_z:        f64,
    pub ts:            i64,
}

fn welford_update(mean: &mut f64, m2: &mut f64, value: f64, n: f64) {
    let delta  = value - *mean;
    *mean     += delta / n;
    let delta2 = value - *mean;
    *m2       += delta * delta2;
}

fn stddev(m2: f64, n: u64) -> f64 {
    if n < 2 { return 1.0; } // avoid division by zero
    (m2 / (n - 1) as f64).sqrt().max(0.01) // min stddev to avoid zero-division
}
