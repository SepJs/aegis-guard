use crate::models::RiskLevel;

/// Classify Shannon entropy with awareness of executable vs data files.
/// Executables with high entropy are more suspicious (packers / crypters).
pub fn classify_entropy(h: f64) -> RiskLevel {
    match h {
        e if e > 7.6 => RiskLevel::High,
        e if e > 7.0 => RiskLevel::High,   // tightened threshold
        e if e > 6.2 => RiskLevel::Medium,
        e if e > 4.0 => RiskLevel::Normal,
        _ => RiskLevel::Low,
    }
}

/// Stronger classification when we also know the MIME / magic.
pub fn classify_entropy_with_mime(h: f64, mime: &str) -> RiskLevel {
    let is_exec = mime.contains("elf") || mime.contains("dosexec") || mime.contains("executable") || mime.contains("x-msdownload");
    let is_script = mime.contains("shellscript") || mime.contains("text/x-") || mime == "text/plain";
    match (h, is_exec, is_script) {
        (e, true, _) if e > 7.2 => RiskLevel::High,   // packed / encrypted binary
        (e, true, _) if e > 6.5 => RiskLevel::Medium,
        (e, _, true) if e > 7.4 => RiskLevel::Medium, // highly obfuscated script
        (e, _, _) if e > 7.6 => RiskLevel::High,
        (e, _, _) if e > 6.5 => RiskLevel::Medium,
        (e, _, _) if e > 4.0 => RiskLevel::Normal,
        _ => RiskLevel::Low,
    }
}

pub fn build_note(h: f64, risk: &RiskLevel, mime: &str) -> String {
    let h_str = format!("{:.3}", h);
    let is_exec = mime.contains("elf") || mime.contains("dosexec") || mime.contains("executable");
    match risk {
        RiskLevel::High if is_exec => format!(
            "Entropy {h_str}/8.0 — HIGH RISK executable. Profile matches packers (UPX, Themida, VMProtect), crypters, or ransomware-encrypted payloads. MIME: {mime}."
        ),
        RiskLevel::High => format!(
            "Entropy {h_str}/8.0 — randomness consistent with encryption, strong packing, or compressed malware stages. File type: {mime}."
        ),
        RiskLevel::Medium if is_exec => format!(
            "Entropy {h_str}/8.0 — elevated for an executable ({mime}). Possible light packing, section encryption, or embedded resources."
        ),
        RiskLevel::Medium => format!(
            "Entropy {h_str}/8.0 — higher than typical for {mime}. May indicate compression, partial encryption, or obfuscated strings."
        ),
        RiskLevel::Normal => format!("Entropy {h_str}/8.0 — within normal range for {mime}."),
        RiskLevel::Low => format!("Entropy {h_str}/8.0 — low randomness; likely plaintext or sparse data. File type: {mime}."),
        RiskLevel::Skipped => "File was skipped.".into(),
    }
}

/// Simple content-based signature hits for common malware families / packers.
/// Returns a short note if a signature matched.
pub fn signature_scan(data: &[u8]) -> Option<String> {
    // UPX packer
    if data.windows(4).any(|w| w == b"UPX!") || data.windows(4).any(|w| w == b"UPX0") || data.windows(4).any(|w| w == b"UPX1") {
        return Some("Signature: UPX packer markers detected".into());
    }
    // Common ransomware note fragments / extensions (lightweight)
    let s = String::from_utf8_lossy(&data[..data.len().min(4096)]).to_lowercase();
    if s.contains("your files have been encrypted") || s.contains("all your files are encrypted") || s.contains("decrypt your files") {
        return Some("Signature: Ransomware note language detected".into());
    }
    if s.contains("lockbit") || s.contains("conti ransom") || s.contains("blackcat") || s.contains("alphv") {
        return Some("Signature: Known ransomware family string".into());
    }
    // Cobalt Strike / common C2 beacons (very light heuristic)
    if data.windows(8).any(|w| w == b"\x90\x90\x90\x90\x90\x90\x90\x90") && data.len() > 1024 {
        // NOP sled is weak alone; only report if high entropy later
    }
    // ELF with unusual section names often used by rootkits / droppers
    if data.starts_with(b"\x7fELF") {
        if s.contains(".upx") || s.contains("packed") {
            return Some("Signature: Suspicious ELF section / packing indicator".into());
        }
    }
    // Windows PE + suspicious
    if data.starts_with(b"MZ") {
        if s.contains("this program cannot be run in dos mode") && data.len() > 512 {
            // normal for PE; look for other markers
            if s.contains("virtualalloc") && s.contains("createthread") && s.contains("loadlibrary") {
                return Some("Signature: Classic process-injection API constellation in PE".into());
            }
        }
    }
    None
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
