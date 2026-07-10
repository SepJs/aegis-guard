use crate::models::ThreatIncident;

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
    for anc in &inc.ancestors { h.update(&anc.to_le_bytes()); }
    if let Some(ref exe) = inc.exe_path { h.update(exe.as_bytes()); }
    for arg in &inc.cmdline { h.update(arg.as_bytes()); }
    h.finalize().to_hex().to_string()
}

pub fn verify(inc: &ThreatIncident) -> Result<(), String> {
    let expected = compute(inc);
    if inc.digest == expected { Ok(()) }
    else { Err(format!("DIGEST MISMATCH for incident {} — stored: {} expected: {}", inc.id, inc.digest, expected)) }
}
