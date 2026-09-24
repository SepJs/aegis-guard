// filter.rs — eBPF & classical BPF socket filter instruction generation and management

use serde::{Deserialize, Serialize};

// BPF Instruction classes
pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ST: u16 = 0x02;
pub const BPF_STX: u16 = 0x03;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_MISC: u16 = 0x07;

// Size modifiers
pub const BPF_W: u16 = 0x00;
pub const BPF_H: u16 = 0x08;
pub const BPF_B: u16 = 0x10;

// Mode modifiers
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;
pub const BPF_MSH: u16 = 0xa0;

// Jump opcodes
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;

// Source operand
pub const BPF_K: u16 = 0x00;
pub const BPF_X: u16 = 0x08;

/// Low-level BPF instruction structure matching Linux `struct sock_filter`
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl SockFilter {
    pub fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }

    /// Load half-word (16 bits) from absolute packet offset
    pub fn ld_h_abs(offset: u32) -> Self {
        Self::new(BPF_LD | BPF_H | BPF_ABS, 0, 0, offset)
    }

    /// Load byte (8 bits) from absolute packet offset
    pub fn ld_b_abs(offset: u32) -> Self {
        Self::new(BPF_LD | BPF_B | BPF_ABS, 0, 0, offset)
    }

    /// Load word (32 bits) from absolute packet offset
    pub fn ld_w_abs(offset: u32) -> Self {
        Self::new(BPF_LD | BPF_W | BPF_ABS, 0, 0, offset)
    }

    /// Jump if equal constant: if A == k, pc += jt, else pc += jf
    pub fn jmp_eq(k: u32, jt: u8, jf: u8) -> Self {
        Self::new(BPF_JMP | BPF_JEQ | BPF_K, jt, jf, k)
    }

    /// Return instruction: k bytes to capture (0 means drop, u32::MAX means keep all)
    pub fn ret(k: u32) -> Self {
        Self::new(BPF_RET | BPF_K, 0, 0, k)
    }
}

/// Linux `struct sock_fprog` representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SockFprog {
    pub len: u16,
    pub filter: Vec<SockFilter>,
}

impl SockFprog {
    pub fn from_instructions(insns: Vec<SockFilter>) -> Self {
        Self {
            len: insns.len() as u16,
            filter: insns,
        }
    }
}

/// Socket filter mode configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FilterMode {
    /// Pass all packets to userspace inspection engine
    PassAll,
    /// Filter only TCP traffic
    TcpOnly,
    /// Filter only UDP traffic (e.g. DNS inspection)
    UdpOnly,
    /// Filter suspicious C2/Trojan destination ports
    ThreatPortsOnly,
    /// Custom compiled instruction ruleset
    Custom,
}

/// Builder for generating socket filter programs
pub struct BpfProgramBuilder;

impl BpfProgramBuilder {
    /// Builds a classic BPF socket filter bytecode based on mode
    pub fn build(mode: &FilterMode, snapshot_len: u32) -> SockFprog {
        match mode {
            FilterMode::PassAll => {
                // Pass everything up to snapshot_len
                let insns = vec![
                    SockFilter::ret(snapshot_len),
                ];
                SockFprog::from_instructions(insns)
            }
            FilterMode::TcpOnly => {
                // Check Ethernet type IPv4 (0x0800 at offset 12)
                // Check Protocol is TCP (6 at offset 23)
                let insns = vec![
                    SockFilter::ld_h_abs(12),
                    SockFilter::jmp_eq(0x0800, 0, 3), // If IPv4 continue, else drop
                    SockFilter::ld_b_abs(23),
                    SockFilter::jmp_eq(6, 0, 1),      // If TCP continue, else drop
                    SockFilter::ret(snapshot_len),     // Accept packet
                    SockFilter::ret(0),                // Drop packet
                ];
                SockFprog::from_instructions(insns)
            }
            FilterMode::UdpOnly => {
                // Check IPv4 and UDP (protocol 17)
                let insns = vec![
                    SockFilter::ld_h_abs(12),
                    SockFilter::jmp_eq(0x0800, 0, 3),
                    SockFilter::ld_b_abs(23),
                    SockFilter::jmp_eq(17, 0, 1),
                    SockFilter::ret(snapshot_len),
                    SockFilter::ret(0),
                ];
                SockFprog::from_instructions(insns)
            }
            FilterMode::ThreatPortsOnly => {
                // Filter common C2 ports: 4444, 1337, 31337, 6667, 9001
                let insns = vec![
                    SockFilter::ld_h_abs(12),
                    SockFilter::jmp_eq(0x0800, 0, 8),
                    SockFilter::ld_b_abs(23),
                    SockFilter::jmp_eq(6, 0, 6),      // TCP check
                    SockFilter::ld_h_abs(36),          // TCP Dest Port
                    SockFilter::jmp_eq(4444, 3, 0),    // Metasploit default
                    SockFilter::jmp_eq(1337, 2, 0),    // Leet RAT
                    SockFilter::jmp_eq(31337, 1, 0),   // Back Orifice
                    SockFilter::jmp_eq(9001, 0, 1),    // Tor/C2
                    SockFilter::ret(snapshot_len),     // Match -> pass to user inspection
                    SockFilter::ret(0),                // Drop / ignore
                ];
                SockFprog::from_instructions(insns)
            }
            FilterMode::Custom => {
                let insns = vec![SockFilter::ret(snapshot_len)];
                SockFprog::from_instructions(insns)
            }
        }
    }
}
