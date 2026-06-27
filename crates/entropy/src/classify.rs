// entropy/src/classify.rs — MIME guess from magic bytes + entropy classifier

use crate::models::RiskLevel;

/// Classify entropy value into a risk level.
pub fn classify_entropy(h: f64) -> RiskLevel {
    match h {
        e if e > 7.5 => RiskLevel::High,
        e if e > 6.5 => RiskLevel::Medium,
        e if e > 4.0 => RiskLevel::Normal,
        _            => RiskLevel::Low,
    }
}

/// Build a human-readable note combining entropy + MIME context.
pub fn build_note(h: f64, risk: &RiskLevel, mime: &str) -> String {
    let h_str = format!("{:.3}", h);
    match risk {
        RiskLevel::High => format!(
            "Entropy {h_str}/8.0 — randomness profile consistent with encryption, \
             packing (UPX/MPRESS), or compressed data. File type: {mime}."
        ),
        RiskLevel::Medium => format!(
            "Entropy {h_str}/8.0 — higher than typical for this file type ({mime}). \
             May indicate compression, partial encryption, or obfuscated strings."
        ),
        RiskLevel::Normal => format!(
            "Entropy {h_str}/8.0 — within normal range for {mime}."
        ),
        RiskLevel::Low => format!(
            "Entropy {h_str}/8.0 — low randomness; likely plaintext or sparse data. \
             File type: {mime}."
        ),
        RiskLevel::Skipped => "File was skipped.".into(),
    }
}

/// Guess MIME type from first 16 magic bytes.
/// Covers the most common binary formats seen in security analysis.
pub fn guess_mime(header: &[u8]) -> &'static str {
    if header.len() < 4 { return "application/octet-stream"; }

    // ELF binary (Linux executable/shared lib)
    if &header[..4] == b"\x7fELF" { return "application/x-elf"; }

    // PE / DOS MZ (Windows executable — future cross-platform)
    if &header[..2] == b"MZ"       { return "application/x-dosexec"; }

    // PDF
    if header.starts_with(b"%PDF") { return "application/pdf"; }

    // ZIP / DOCX / XLSX / JAR (all ZIP-based)
    if &header[..4] == b"PK\x03\x04" { return "application/zip"; }

    // GZIP
    if &header[..2] == b"\x1f\x8b" { return "application/gzip"; }

    // XZ
    if &header[..6] == b"\xfd7zXZ\x00" { return "application/x-xz"; }

    // Bzip2
    if &header[..2] == b"BZ"       { return "application/x-bzip2"; }

    // 7-zip
    if &header[..6] == b"7z\xbc\xaf'\x1c" { return "application/x-7z-compressed"; }

    // PNG
    if &header[..8] == b"\x89PNG\r\n\x1a\n" { return "image/png"; }

    // JPEG
    if &header[..3] == b"\xff\xd8\xff" { return "image/jpeg"; }

    // WebAssembly
    if &header[..4] == b"\x00asm"   { return "application/wasm"; }

    // Shell script
    if header.starts_with(b"#!/bin/sh")
    || header.starts_with(b"#!/bin/bash")
    || header.starts_with(b"#!/usr/bin/env") {
        return "text/x-shellscript";
    }

    // UTF-8 / ASCII text heuristic: all bytes printable or whitespace
    let looks_text = header.iter().take(64).all(|&b| {
        b >= 0x20 || b == b'\n' || b == b'\r' || b == b'\t'
    });
    if looks_text { return "text/plain"; }

    "application/octet-stream"
}

/// Shannon entropy H(X) = -Σ p(x) * log2(p(x))
/// Returns a value in [0.0, 8.0] bits per byte.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }

    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }

    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .fold(0.0_f64, |acc, &c| {
            let p = c as f64 / len;
            acc - p * p.log2()
        })
}
