use crate::models::RiskLevel;

pub fn classify_entropy(h: f64) -> RiskLevel {
    match h { e if e > 7.5 => RiskLevel::High, e if e > 6.5 => RiskLevel::Medium, e if e > 4.0 => RiskLevel::Normal, _ => RiskLevel::Low }
}

pub fn build_note(h: f64, risk: &RiskLevel, mime: &str) -> String {
    let h_str = format!("{:.3}", h);
    match risk {
        RiskLevel::High => format!("Entropy {h_str}/8.0 — randomness profile consistent with encryption, packing (UPX/MPRESS), or compressed data. File type: {mime}."),
        RiskLevel::Medium => format!("Entropy {h_str}/8.0 — higher than typical for this file type ({mime}). May indicate compression, partial encryption, or obfuscated strings."),
        RiskLevel::Normal => format!("Entropy {h_str}/8.0 — within normal range for {mime}."),
        RiskLevel::Low => format!("Entropy {h_str}/8.0 — low randomness; likely plaintext or sparse data. File type: {mime}."),
        RiskLevel::Skipped => "File was skipped.".into(),
    }
}

pub fn guess_mime(header: &[u8]) -> &'static str {
    if header.len() < 4 { return "application/octet-stream"; }
    if &header[..4] == b"\x7fELF" { return "application/x-elf"; }
    if &header[..2] == b"MZ" { return "application/x-dosexec"; }
    if header.starts_with(b"%PDF") { return "application/pdf"; }
    if &header[..4] == b"PK\x03\x04" { return "application/zip"; }
    if &header[..2] == b"\x1f\x8b" { return "application/gzip"; }
    if header.len() >= 6 && &header[..6] == b"\xfd7zXZ\x00" { return "application/x-xz"; }
    if &header[..2] == b"BZ" { return "application/x-bzip2"; }
    if header.len() >= 6 && &header[..6] == b"7z\xbc\xaf\x27\x1c" { return "application/x-7z-compressed"; }
    if header.len() >= 8 && &header[..8] == b"\x89PNG\r\n\x1a\n" { return "image/png"; }
    if &header[..3] == b"\xff\xd8\xff" { return "image/jpeg"; }
    if &header[..4] == b"\x00asm" { return "application/wasm"; }
    if header.starts_with(b"#!/bin/sh") || header.starts_with(b"#!/bin/bash") || header.starts_with(b"#!/usr/bin/env") { return "text/x-shellscript"; }
    let looks_text = header.iter().take(64).all(|&b| b >= 0x20 || b == b'\n' || b == b'\r' || b == b'\t');
    if looks_text { return "text/plain"; }
    "application/octet-stream"
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    freq.iter().filter(|&&c| c > 0).fold(0.0_f64, |acc, &c| { let p = c as f64 / len; acc - p * p.log2() })
}
