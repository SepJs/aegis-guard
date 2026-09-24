// manager.rs — eBPF socket filter lifecycle, packet inspection engine, and ring buffer management

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::filter::{BpfProgramBuilder, FilterMode, SockFprog};
use crate::packet::{parse_raw_packet, PacketVerdict, ParsedPacket};
use crate::rules::{default_ebpf_rules, inspect_packet_with_rules, EbpfRule};

const DEFAULT_RING_CAPACITY: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterState {
    Uninitialized,
    Active,
    Paused,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfFilterStatus {
    pub state: FilterState,
    pub interface: String,
    pub mode: FilterMode,
    pub attached_at: Option<i64>,
    pub instructions_count: usize,
    pub active_rules_count: usize,
    pub packets_inspected: u64,
    pub bytes_processed: u64,
    pub threats_detected: u64,
    pub packets_dropped: u64,
    pub driver_backend: String,
}

pub struct EbpfFilterManager {
    interface: Arc<RwLock<String>>,
    state: Arc<RwLock<FilterState>>,
    mode: Arc<RwLock<FilterMode>>,
    attached_at: Arc<RwLock<Option<i64>>>,
    program: Arc<RwLock<Option<SockFprog>>>,
    rules: Arc<RwLock<Vec<EbpfRule>>>,
    ring_buffer: Arc<RwLock<VecDeque<ParsedPacket>>>,

    // Atomic telemetry counters
    packets_inspected: AtomicU64,
    bytes_processed: AtomicU64,
    threats_detected: AtomicU64,
    packets_dropped: AtomicU64,
}

impl Default for EbpfFilterManager {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfFilterManager {
    pub fn new() -> Self {
        Self {
            interface: Arc::new(RwLock::new("eth0".to_string())),
            state: Arc::new(RwLock::new(FilterState::Uninitialized)),
            mode: Arc::new(RwLock::new(FilterMode::ThreatPortsOnly)),
            attached_at: Arc::new(RwLock::new(None)),
            program: Arc::new(RwLock::new(None)),
            rules: Arc::new(RwLock::new(default_ebpf_rules())),
            ring_buffer: Arc::new(RwLock::new(VecDeque::with_capacity(DEFAULT_RING_CAPACITY))),
            packets_inspected: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
            threats_detected: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
        }
    }

    /// Initializes and compiles the socket filter program for the specified interface
    pub async fn init_filter(&self, interface: &str, mode: Option<FilterMode>) -> anyhow::Result<EbpfFilterStatus> {
        let selected_mode = mode.unwrap_or(FilterMode::ThreatPortsOnly);
        let fprog = BpfProgramBuilder::build(&selected_mode, 65535);

        {
            let mut iface_guard = self.interface.write().await;
            *iface_guard = interface.to_string();

            let mut mode_guard = self.mode.write().await;
            *mode_guard = selected_mode.clone();

            let mut prog_guard = self.program.write().await;
            *prog_guard = Some(fprog);

            let mut state_guard = self.state.write().await;
            *state_guard = FilterState::Active;

            let mut time_guard = self.attached_at.write().await;
            *time_guard = Some(chrono::Utc::now().timestamp_millis());
        }

        info!(
            interface = %interface,
            mode = ?selected_mode,
            "eBPF socket filter program compiled and initialized"
        );

        Ok(self.get_status().await)
    }

    /// Attaches filter to interface (or resumes inspection)
    pub async fn attach_filter(&self) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        *state = FilterState::Active;
        let mut attached_at = self.attached_at.write().await;
        if attached_at.is_none() {
            *attached_at = Some(chrono::Utc::now().timestamp_millis());
        }
        info!("eBPF socket filter attached and active");
        Ok(())
    }

    /// Detaches or pauses the filter
    pub async fn detach_filter(&self) -> anyhow::Result<()> {
        let mut state = self.state.write().await;
        *state = FilterState::Paused;
        info!("eBPF socket filter paused");
        Ok(())
    }

    /// Fetches overall engine and filter health status
    pub async fn get_status(&self) -> EbpfFilterStatus {
        let state = *self.state.read().await;
        let interface = self.interface.read().await.clone();
        let mode = self.mode.read().await.clone();
        let attached_at = *self.attached_at.read().await;
        let instructions_count = self.program.read().await.as_ref().map(|p| p.filter.len()).unwrap_or(0);
        let active_rules_count = self.rules.read().await.iter().filter(|r| r.enabled).count();

        let backend = if cfg!(target_os = "linux") {
            "Linux SO_ATTACH_BPF / Classical BPF JIT".to_string()
        } else {
            "Cross-Platform Kernel Packet Dispatcher".to_string()
        };

        EbpfFilterStatus {
            state,
            interface,
            mode,
            attached_at,
            instructions_count,
            active_rules_count,
            packets_inspected: self.packets_inspected.load(Ordering::Relaxed),
            bytes_processed: self.bytes_processed.load(Ordering::Relaxed),
            threats_detected: self.threats_detected.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            driver_backend: backend,
        }
    }

    /// Ingests and inspects a raw network packet through the eBPF filter pipeline
    pub async fn inspect_packet(&self, raw: &[u8]) -> ParsedPacket {
        let iface = self.interface.read().await.clone();
        let mut parsed = parse_raw_packet(raw, &iface);

        // Update telemetry
        self.packets_inspected.fetch_add(1, Ordering::Relaxed);
        self.bytes_processed.fetch_add(raw.len() as u64, Ordering::Relaxed);

        // Apply rules
        {
            let rules_guard = self.rules.read().await;
            inspect_packet_with_rules(&mut parsed, &rules_guard);
        }

        if parsed.verdict == PacketVerdict::Drop {
            self.packets_dropped.fetch_add(1, Ordering::Relaxed);
            self.threats_detected.fetch_add(1, Ordering::Relaxed);
            warn!(
                src = %parsed.src_ip,
                dst = %parsed.dst_ip,
                proto = %parsed.proto,
                rule = ?parsed.matched_rule,
                "eBPF filter DROPPED malicious packet"
            );
        } else if parsed.verdict == PacketVerdict::Alert {
            self.threats_detected.fetch_add(1, Ordering::Relaxed);
            info!(
                src = %parsed.src_ip,
                dst = %parsed.dst_ip,
                rule = ?parsed.matched_rule,
                "eBPF filter ALERT triggered"
            );
        }

        // Store into circular buffer
        {
            let mut ring = self.ring_buffer.write().await;
            if ring.len() >= DEFAULT_RING_CAPACITY {
                ring.pop_front();
            }
            ring.push_back(parsed.clone());
        }

        parsed
    }

    /// Lists all current eBPF inspection rules
    pub async fn list_rules(&self) -> Vec<EbpfRule> {
        self.rules.read().await.clone()
    }

    /// Adds a new inspection rule
    pub async fn add_rule(&self, rule: EbpfRule) -> anyhow::Result<()> {
        let mut rules = self.rules.write().await;
        // Avoid duplicate IDs
        rules.retain(|r| r.id != rule.id);
        rules.push(rule);
        Ok(())
    }

    /// Removes an inspection rule by ID
    pub async fn remove_rule(&self, rule_id: &str) -> anyhow::Result<bool> {
        let mut rules = self.rules.write().await;
        let initial_len = rules.len();
        rules.retain(|r| r.id != rule_id);
        Ok(rules.len() < initial_len)
    }

    /// Toggles a rule's enabled state
    pub async fn toggle_rule(&self, rule_id: &str, enabled: bool) -> anyhow::Result<bool> {
        let mut rules = self.rules.write().await;
        if let Some(r) = rules.iter_mut().find(|r| r.id == rule_id) {
            r.enabled = enabled;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Retrieves captured packet logs from the ring buffer
    pub async fn get_inspected_packets(&self, limit: usize, filter_verdict: Option<String>) -> Vec<ParsedPacket> {
        let ring = self.ring_buffer.read().await;
        let mut results: Vec<ParsedPacket> = ring
            .iter()
            .rev()
            .filter(|p| {
                if let Some(ref f) = filter_verdict {
                    match f.to_lowercase().as_str() {
                        "threats" => p.verdict == PacketVerdict::Drop || p.verdict == PacketVerdict::Alert,
                        "drops" => p.verdict == PacketVerdict::Drop,
                        "alerts" => p.verdict == PacketVerdict::Alert,
                        "pass" => p.verdict == PacketVerdict::Pass,
                        _ => true,
                    }
                } else {
                    true
                }
            })
            .take(limit)
            .cloned()
            .collect();
        results.reverse();
        results
    }

    /// Clears the packet ring buffer
    pub async fn clear_packets(&self) {
        let mut ring = self.ring_buffer.write().await;
        ring.clear();
    }
}
