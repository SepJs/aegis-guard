// behavioral/src/lib.rs — Phase 5: process behavioral baseline + anomaly scoring
//
// Strategy:
//   1. LEARN phase (first 24h): observe normal behaviour per process name
//      • CPU usage, memory growth rate, child spawn rate, network conn rate
//      • Build per-process statistical baseline (mean + std dev)
//   2. DETECT phase: score each observation against baseline
//      • Z-score: (observed - mean) / stddev
//      • Combined anomaly score: weighted sum of per-metric Z-scores
//      • Score > threshold → emit behavioral anomaly event
//
// No ML library needed — pure statistical baseline is sufficient for Phase 5.

pub mod baseline;
pub mod scorer;
pub mod models;

pub use baseline::BehaviorEngine;
pub use models::{BehaviorAnomaly, ProcessObservation};
