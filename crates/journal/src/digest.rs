// journal/src/digest.rs — BLAKE3 tamper-evident digest
//
// The digest is computed over a canonical string of all incident fields.
// On read, we recompute and compare — mismatch means the DB was tampered.

use crate::models::ThreatIncident;

/// Compute BLAKE3 digest for a ThreatIncident.
/// Field order is fixed — never change without a migration.
pub fn compute(inc: &ThreatIncident) -> String {
    let mut h = blake3::Hasher::new();

    h.update(inc.id.as_bytes());
    h.update(inc.kind.as_bytes());
    h.update(inc.severity.to_string().as_bytes());
    h.update(&inc.pid.to_le_bytes());
    h.update(&inc.ppid.to_le_bytes());
    h.update(inc.process.as_bytes());
    h.update(inc.rule.as_bytes());
    h.update(inc.confidence.as_bytes());
    h.update(inc.reason.as_bytes());
    h.update(&inc.ts.timestamp_millis().to_le_bytes());

    for anc in &inc.ancestors {
        h.update(&anc.to_le_bytes());
    }

    if let Some(ref exe) = inc.exe_path {
        h.update(exe.as_bytes());
    }

    for arg in &inc.cmdline {
        h.update(arg.as_bytes());
    }

    h.finalize().to_hex().to_string()
}

/// Verify a stored incident has not been tampered with.
/// Returns Ok(()) if the digest matches, Err with details otherwise.
pub fn verify(inc: &ThreatIncident) -> Result<(), String> {
    let expected = compute(inc);
    if inc.digest == expected {
        Ok(())
    } else {
        Err(format!(
            "DIGEST MISMATCH for incident {} — stored: {} expected: {}",
            inc.id, inc.digest, expected
        ))
    }
}
