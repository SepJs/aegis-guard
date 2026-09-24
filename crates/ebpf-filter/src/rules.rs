// rules.rs — eBPF packet inspection rules and anomaly detection signatures

use serde::{Deserialize, Serialize};
use crate::packet::{PacketVerdict, ParsedPacket};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Alert,
    Drop,
    Pass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub protocol: Option<String>,
    pub dst_port: Option<u16>,
    pub min_entropy: Option<f64>,
    pub payload_signature: Option<String>,
    pub action: RuleAction,
    pub severity: String,
    pub enabled: bool,
}

impl EbpfRule {
    /// Evaluate a parsed packet against this rule
    pub fn evaluate(&self, packet: &ParsedPacket) -> bool {
        if !self.enabled {
            return false;
        }

        // Protocol match
        if let Some(ref proto) = self.protocol {
            if !packet.proto.eq_ignore_ascii_case(proto) {
                return false;
            }
        }

        // Port match
        if let Some(port) = self.dst_port {
            if packet.dst_port != Some(port) {
                return false;
            }
        }

        // Entropy threshold match
        if let Some(min_ent) = self.min_entropy {
            if packet.payload_entropy < min_ent || packet.payload_len < 16 {
                return false;
            }
        }

        // Payload signature match
        if let Some(ref sig) = self.payload_signature {
            if !packet.payload_preview.to_lowercase().contains(&sig.to_lowercase()) {
                return false;
            }
        }

        true
    }
}

/// Provides standard default rules for network packet inspection
pub fn default_ebpf_rules() -> Vec<EbpfRule> {
    vec![
        EbpfRule {
            id: "EBPF-R001".into(),
            name: "High-Entropy C2 Shellcode".into(),
            description: "Detects encrypted C2 payloads or packed shellcode with Shannon entropy > 7.1".into(),
            protocol: Some("TCP".into()),
            dst_port: None,
            min_entropy: Some(7.1),
            payload_signature: None,
            action: RuleAction::Alert,
            severity: "high".into(),
            enabled: true,
        },
        EbpfRule {
            id: "EBPF-R002".into(),
            name: "Default C2 Reverse Shell Port".into(),
            description: "Flags connections to known default backdoor/C2 listener ports (4444)".into(),
            protocol: Some("TCP".into()),
            dst_port: Some(4444),
            min_entropy: None,
            payload_signature: None,
            action: RuleAction::Drop,
            severity: "critical".into(),
            enabled: true,
        },
        EbpfRule {
            id: "EBPF-R003".into(),
            name: "DNS Covert Tunneling Anomaly".into(),
            description: "High-entropy queries on UDP port 53 indicating covert exfiltration channel".into(),
            protocol: Some("UDP".into()),
            dst_port: Some(53),
            min_entropy: Some(5.8),
            payload_signature: None,
            action: RuleAction::Alert,
            severity: "high".into(),
            enabled: true,
        },
        EbpfRule {
            id: "EBPF-R004".into(),
            name: "Empire / Covenant C2 Listener".into(),
            description: "Inbound or outbound connection to common post-exploitation framework port 8888".into(),
            protocol: Some("TCP".into()),
            dst_port: Some(8888),
            min_entropy: None,
            payload_signature: None,
            action: RuleAction::Alert,
            severity: "medium".into(),
            enabled: true,
        },
        EbpfRule {
            id: "EBPF-R005".into(),
            name: "Suspicious Remote Desktop / VNC Exposure".into(),
            description: "Detects unauthorized lateral movement attempts via RDP (3389)".into(),
            protocol: Some("TCP".into()),
            dst_port: Some(3389),
            min_entropy: None,
            payload_signature: None,
            action: RuleAction::Alert,
            severity: "medium".into(),
            enabled: true,
        },
        EbpfRule {
            id: "EBPF-R006".into(),
            name: "Metasploit Stage 1 Stager Payload".into(),
            description: "Detects common staging string patterns in packet headers".into(),
            protocol: Some("TCP".into()),
            dst_port: None,
            min_entropy: None,
            payload_signature: Some("meterpreter".into()),
            action: RuleAction::Drop,
            severity: "critical".into(),
            enabled: true,
        },
    ]
}

/// Applies all enabled rules to a parsed packet and computes the final security verdict
pub fn inspect_packet_with_rules(packet: &mut ParsedPacket, rules: &[EbpfRule]) {
    for rule in rules {
        if rule.evaluate(packet) {
            match rule.action {
                RuleAction::Drop => {
                    packet.verdict = PacketVerdict::Drop;
                    packet.threat_score = 95;
                    packet.matched_rule = Some(rule.id.clone());
                    packet.reason = Some(format!("[{}] {} — {}", rule.id, rule.name, rule.description));
                    return; // Dropped packet terminates inspection
                }
                RuleAction::Alert => {
                    packet.verdict = PacketVerdict::Alert;
                    packet.threat_score = 80;
                    packet.matched_rule = Some(rule.id.clone());
                    packet.reason = Some(format!("[{}] {} — {}", rule.id, rule.name, rule.description));
                }
                RuleAction::Pass => {
                    // Rule explicitly allows or monitors
                }
            }
        }
    }
}
