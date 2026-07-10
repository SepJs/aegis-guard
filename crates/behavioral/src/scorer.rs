use crate::models::{ProcessBaseline, ProcessObservation};

const W_CPU: f64 = 0.25;
const W_MEM: f64 = 0.25;
const W_CONN: f64 = 0.35;
const W_FD: f64 = 0.15;

pub fn score_observation(obs: &ProcessObservation, baseline: &ProcessBaseline, threshold: f64) -> (f64, f64, f64, f64, String) {
    let cpu_z  = z_score(obs.cpu_pct, baseline.cpu_mean, baseline.cpu_stddev());
    let mem_z  = z_score(obs.mem_kb as f64, baseline.mem_mean, baseline.mem_stddev());
    let conn_z = z_score(obs.conn_count as f64, baseline.conn_mean, baseline.conn_stddev());
    let fd_z   = z_score(obs.fd_count as f64, baseline.fd_mean, baseline.fd_stddev());

    let cpu_anom = cpu_z.max(0.0);
    let mem_anom = mem_z.max(0.0);
    let conn_anom = conn_z.max(0.0);
    let fd_anom = fd_z.max(0.0);

    let raw = W_CPU * cpu_anom + W_MEM * mem_anom + W_CONN * conn_anom + W_FD * fd_anom;
    let score = (raw / threshold * 50.0).min(100.0);

    let any_exceeded = cpu_anom > threshold || mem_anom > threshold || conn_anom > threshold || fd_anom > threshold;
    if !any_exceeded { return (0.0, cpu_z, mem_z, conn_z, String::new()); }

    let mut parts = Vec::new();
    if cpu_anom > threshold { parts.push(format!("CPU usage {:.1}% is {:.1}σ above baseline ({:.1}%)", obs.cpu_pct, cpu_z, baseline.cpu_mean)); }
    if mem_anom > threshold { parts.push(format!("Memory {:.0} KB is {:.1}σ above baseline ({:.0} KB)", obs.mem_kb, mem_z, baseline.mem_mean)); }
    if conn_anom > threshold { parts.push(format!("Network connections {} is {:.1}σ above baseline ({:.1})", obs.conn_count, conn_z, baseline.conn_mean)); }
    if fd_anom > threshold { parts.push(format!("Open file descriptors {} is {:.1}σ above baseline ({:.1})", obs.fd_count, fd_z, baseline.fd_mean)); }

    let reason = format!("Process '{}' (pid {}) shows behavioral deviation: {}", obs.name, obs.pid, parts.join("; "));
    (score, cpu_z, mem_z, conn_z, reason)
}

fn z_score(value: f64, mean: f64, stddev: f64) -> f64 { (value - mean) / stddev.max(0.01) }
