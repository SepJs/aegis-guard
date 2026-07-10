use crate::models::ThreatIncident;

pub fn to_markdown(incidents: &[ThreatIncident], title: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("# {}\n\n", title));
    out.push_str(&format!("_Generated: {}_\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    out.push_str(&format!("**Total incidents:** {}\n\n---\n\n", incidents.len()));
    if incidents.is_empty() { out.push_str("_No incidents recorded._\n"); return out; }
    for inc in incidents {
        let status = if inc.resolved { "✅ Resolved" } else { "🔴 Open" };
        let sev_emoji = match inc.severity {
            crate::models::Severity::High => "🔴 HIGH", crate::models::Severity::Medium => "🟡 MEDIUM", crate::models::Severity::Low => "⚪ LOW",
        };
        out.push_str(&format!("## {} — {}\n\n", inc.rule, inc.process));
        out.push_str("| Field | Value |\n|---|---|\n");
        out.push_str(&format!("| Status | {} |\n", status));
        out.push_str(&format!("| Severity | {} |\n", sev_emoji));
        out.push_str(&format!("| Confidence | {} |\n", inc.confidence.to_uppercase()));
        out.push_str(&format!("| PID | {} |\n", inc.pid));
        out.push_str(&format!("| PPID | {} |\n", inc.ppid));
        out.push_str(&format!("| Timestamp | {} |\n", inc.ts.format("%Y-%m-%d %H:%M:%S UTC")));
        if let Some(ref exe) = inc.exe_path { out.push_str(&format!("| Executable | `{}` |\n", exe)); }
        if !inc.cmdline.is_empty() { out.push_str(&format!("| Command | `{}` |\n", inc.cmdline.join(" "))); }
        out.push_str("\n**Detection reason:**\n\n");
        out.push_str(&format!("> {}\n\n", inc.reason));
        if !inc.ancestors.is_empty() {
            let chain: Vec<String> = inc.ancestors.iter().map(|p| p.to_string()).collect();
            out.push_str(&format!("**Ancestor chain:** {}\n\n", chain.join(" → ")));
        }
        out.push_str(&format!("_Integrity digest: `{}`_\n\n---\n\n", &inc.digest[..16]));
    }
    out
}

pub fn to_json(incidents: &[ThreatIncident]) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(incidents)?)
}
