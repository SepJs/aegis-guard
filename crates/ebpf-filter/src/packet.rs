// packet.rs — Network packet parsing and real-time security inspection forensics

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketVerdict {
    Pass,
    Inspect,
    Suspicious,
    Alert,
    Drop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedPacket {
    pub id: String,
    pub interface: String,
    pub ts: i64,
    pub src_ip: String,
    pub dst_ip: String,
    pub proto: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<Vec<String>>,
    pub packet_len: usize,
    pub payload_len: usize,
    pub payload_preview: String,
    pub payload_entropy: f64,
    pub verdict: PacketVerdict,
    pub matched_rule: Option<String>,
    pub threat_score: u8,
    pub reason: Option<String>,
}

/// Calculate Shannon entropy for a byte slice (0.0 to 8.0)
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len_f = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Dissect raw frame or packet
pub fn parse_raw_packet(raw: &[u8], interface: &str) -> ParsedPacket {
    let now = chrono::Utc::now().timestamp_millis();
    let id = format!("pkt-{}", uuid::Uuid::new_v4().to_string().chars().take(8).collect::<String>());

    // Check if Ethernet header is present (14 bytes)
    // EtherType at offset 12..14
    let (ip_slice, _eth_offset) = if raw.len() >= 14 && raw[12] == 0x08 && raw[13] == 0x00 {
        (&raw[14..], 14)
    } else {
        (raw, 0)
    };

    if ip_slice.len() < 20 {
        return ParsedPacket {
            id,
            interface: interface.to_string(),
            ts: now,
            src_ip: "0.0.0.0".into(),
            dst_ip: "0.0.0.0".into(),
            proto: "RAW".into(),
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            packet_len: raw.len(),
            payload_len: raw.len(),
            payload_preview: hex_preview(raw, 32),
            payload_entropy: calculate_entropy(raw),
            verdict: PacketVerdict::Pass,
            matched_rule: None,
            threat_score: 0,
            reason: None,
        };
    }

    // Parse IPv4 header
    let ihl = ((ip_slice[0] & 0x0F) * 4) as usize;
    let proto_num = ip_slice[9];
    let src_ip = format!("{}.{}.{}.{}", ip_slice[12], ip_slice[13], ip_slice[14], ip_slice[15]);
    let dst_ip = format!("{}.{}.{}.{}", ip_slice[16], ip_slice[17], ip_slice[18], ip_slice[19]);

    let transport_slice = if ip_slice.len() > ihl { &ip_slice[ihl..] } else { &[] };

    let mut proto = format!("PROTO-{}", proto_num);
    let mut src_port = None;
    let mut dst_port = None;
    let mut tcp_flags = None;
    let mut payload = &[][..];

    if proto_num == 6 && transport_slice.len() >= 20 {
        // TCP
        proto = "TCP".into();
        src_port = Some(u16::from_be_bytes([transport_slice[0], transport_slice[1]]));
        dst_port = Some(u16::from_be_bytes([transport_slice[2], transport_slice[3]]));
        let data_offset = ((transport_slice[12] >> 4) * 4) as usize;
        let flags_byte = transport_slice[13];

        let mut flags = Vec::new();
        if flags_byte & 0x01 != 0 { flags.push("FIN".to_string()); }
        if flags_byte & 0x02 != 0 { flags.push("SYN".to_string()); }
        if flags_byte & 0x04 != 0 { flags.push("RST".to_string()); }
        if flags_byte & 0x08 != 0 { flags.push("PSH".to_string()); }
        if flags_byte & 0x10 != 0 { flags.push("ACK".to_string()); }
        if flags_byte & 0x20 != 0 { flags.push("URG".to_string()); }
        tcp_flags = Some(flags);

        if transport_slice.len() > data_offset {
            payload = &transport_slice[data_offset..];
        }
    } else if proto_num == 17 && transport_slice.len() >= 8 {
        // UDP
        proto = "UDP".into();
        src_port = Some(u16::from_be_bytes([transport_slice[0], transport_slice[1]]));
        dst_port = Some(u16::from_be_bytes([transport_slice[2], transport_slice[3]]));
        if transport_slice.len() > 8 {
            payload = &transport_slice[8..];
        }
    } else if proto_num == 1 {
        // ICMP
        proto = "ICMP".into();
        payload = transport_slice;
    }

    let payload_entropy = calculate_entropy(payload);
    let payload_preview = if !payload.is_empty() {
        if let Ok(s) = std::str::from_utf8(payload) {
            let clean: String = s.chars().filter(|c| !c.is_control()).take(64).collect();
            if clean.len() >= 4 { clean } else { hex_preview(payload, 32) }
        } else {
            hex_preview(payload, 32)
        }
    } else {
        "-".into()
    };

    ParsedPacket {
        id,
        interface: interface.to_string(),
        ts: now,
        src_ip,
        dst_ip,
        proto,
        src_port,
        dst_port,
        tcp_flags,
        packet_len: raw.len(),
        payload_len: payload.len(),
        payload_preview,
        payload_entropy,
        verdict: PacketVerdict::Pass,
        matched_rule: None,
        threat_score: 0,
        reason: None,
    }
}

fn hex_preview(data: &[u8], max_len: usize) -> String {
    let take = data.len().min(max_len);
    let mut hex = String::with_capacity(take * 3);
    for &b in &data[..take] {
        use std::fmt::Write;
        let _ = write!(hex, "{:02X} ", b);
    }
    if data.len() > max_len {
        hex.push_str("...");
    }
    hex.trim().to_string()
}
