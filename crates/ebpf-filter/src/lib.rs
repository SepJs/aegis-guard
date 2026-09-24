// lib.rs — eBPF socket filter module for real-time network packet inspection and defense

pub mod filter;
pub mod packet;
pub mod rules;
pub mod manager;

pub use filter::{BpfProgramBuilder, FilterMode, SockFilter, SockFprog};
pub use packet::{calculate_entropy, parse_raw_packet, PacketVerdict, ParsedPacket};
pub use rules::{default_ebpf_rules, EbpfRule, RuleAction};
pub use manager::{EbpfFilterManager, EbpfFilterStatus, FilterState};
