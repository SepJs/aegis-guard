use std::collections::{HashMap, HashSet};
use std::fs;
use crate::models::{AnomalyDetail, Confidence, ProcInfo};

const BROWSER_NAMES: &[&str] = &["firefox","firefox-bin","firefox-esr","chromium","chromium-browser","chrome","brave","brave-browser","opera","vivaldi","epiphany","midori"];
const SHELL_NAMES: &[&str] = &["bash","sh","dash","zsh","fish","ksh","tcsh","csh","ash","mksh","posh"];
const NETWORK_TOOLS: &[&str] = &["curl","wget","nc","ncat","netcat","nmap","ssh","scp","sftp","ftp","telnet","python3","python","perl","ruby","node","nodejs","php","lua"];
const OFFICE_NAMES: &[&str] = &["soffice","soffice.bin","libreoffice","libreoffice-writer","libreoffice-calc","evince","okular","zathura","abiword","gnumeric"];
const INTERPRETER_NAMES: &[&str] = &["bash","sh","dash","zsh","python3","python","perl","ruby","node","nodejs","php","lua","tclsh","wish"];

#[derive(Clone)]
pub struct RuleEngine {
    browsers: HashSet<&'static str>, shells: HashSet<&'static str>,
    net_tools: HashSet<&'static str>, office: HashSet<&'static str>, interpreters: HashSet<&'static str>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            browsers: BROWSER_NAMES.iter().copied().collect(),
            shells: SHELL_NAMES.iter().copied().collect(),
            net_tools: NETWORK_TOOLS.iter().copied().collect(),
            office: OFFICE_NAMES.iter().copied().collect(),
            interpreters: INTERPRETER_NAMES.iter().copied().collect(),
        }
    }

    pub fn evaluate(&self, child: &ProcInfo, known: &HashMap<u32, ProcInfo>) -> Option<AnomalyDetail> {
        let child_name = child.name.to_lowercase();
        let parent = known.get(&child.ppid);
        let parent_name = parent.map(|p| p.name.to_lowercase()).unwrap_or_default();
        let ancestors = self.build_ancestors(child.ppid, known);

        if let Some(d) = self.par_001(&child_name, &parent_name, &parent, &ancestors) { return Some(d); }
        if let Some(d) = self.par_002(&child_name, &ancestors, known) { return Some(d); }
        if let Some(d) = self.par_003(&child_name, &parent_name, &parent, &ancestors) { return Some(d); }
        if let Some(d) = self.par_004(child, &child_name, &parent_name, &ancestors) { return Some(d); }
        if let Some(d) = self.par_005(child, &ancestors) { return Some(d); }
        if let Some(d) = self.par_006(child, &child_name, &ancestors) { return Some(d); }
        if let Some(d) = self.par_007(child, known, &ancestors) { return Some(d); }
        if let Some(d) = self.par_008(child, known, &ancestors) { return Some(d); }
        None
    }

    fn par_001(&self, child_name: &str, parent_name: &str, parent: &Option<&ProcInfo>, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if !self.shells.contains(child_name) || !self.browsers.contains(parent_name) { return None; }
        Some(AnomalyDetail {
            rule: "PAR-001".into(), confidence: Confidence::High,
            reason: format!("Shell '{}' spawned by browser '{}'. Browsers should never execute interactive shells — this is a common code injection or RCE pattern.", child_name, parent_name),
            parent_exe: parent.and_then(|p| p.exe.clone()), ancestors: ancestors.to_vec(),
        })
    }

    fn par_002(&self, child_name: &str, ancestors: &[u32], known: &HashMap<u32, ProcInfo>) -> Option<AnomalyDetail> {
        if !self.net_tools.contains(child_name) { return None; }
        let (mut found_shell, mut found_sshd, mut sshd_exe) = (false, false, None);
        for &anc_pid in ancestors {
            if let Some(anc) = known.get(&anc_pid) {
                let n = anc.name.to_lowercase();
                if self.shells.contains(n.as_str()) { found_shell = true; }
                if n == "sshd" { found_sshd = true; sshd_exe = anc.exe.clone(); }
            }
        }
        if !(found_sshd && found_shell) { return None; }
        Some(AnomalyDetail {
            rule: "PAR-002".into(), confidence: Confidence::High,
            reason: format!("Network tool '{}' found in an sshd → shell ancestry chain. This matches the pattern of a compromised SSH session being used for data exfiltration or C2 beacon.", child_name),
            parent_exe: sshd_exe, ancestors: ancestors.to_vec(),
        })
    }

    fn par_003(&self, child_name: &str, parent_name: &str, parent: &Option<&ProcInfo>, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if !self.interpreters.contains(child_name) || !self.office.contains(parent_name) { return None; }
        Some(AnomalyDetail {
            rule: "PAR-003".into(), confidence: Confidence::High,
            reason: format!("Interpreter '{}' spawned by document application '{}'. This is the canonical macro-malware / maldoc execution pattern.", child_name, parent_name),
            parent_exe: parent.and_then(|p| p.exe.clone()), ancestors: ancestors.to_vec(),
        })
    }

    fn par_004(&self, child: &ProcInfo, child_name: &str, parent_name: &str, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if parent_name != "systemd" || child.uid == 0 || !self.net_tools.contains(child_name) { return None; }
        Some(AnomalyDetail {
            rule: "PAR-004".into(), confidence: Confidence::Medium,
            reason: format!("Network-capable process '{}' spawned directly by user systemd (uid {}). Unexpected unless this is a registered systemd user service.", child_name, child.uid),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn par_005(&self, child: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = child.exe.as_deref()?;
        if !exe.ends_with(" (deleted)") { return None; }
        Some(AnomalyDetail {
            rule: "PAR-005".into(), confidence: Confidence::Medium,
            reason: format!("Process '{}' (pid {}) is running from a binary that has been deleted from disk: '{}'. Malware often deletes itself after launch to hinder analysis.", child.name, child.pid, exe),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn par_006(&self, child: &ProcInfo, child_name: &str, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if !self.shells.contains(child_name) || child.ppid != 1 { return None; }
        let tty = fs::read_link(format!("/proc/{}/fd/0", child.pid)).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        if tty.starts_with("/dev/pts") || tty.starts_with("/dev/tty") { return None; }
        Some(AnomalyDetail {
            rule: "PAR-006".into(), confidence: Confidence::Medium,
            reason: format!("Shell '{}' (pid {}) is a direct child of init (PID 1) with no controlling terminal. This may indicate a backdoor or post-exploitation persistence mechanism.", child_name, child.pid),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn par_007(&self, child: &ProcInfo, known: &HashMap<u32, ProcInfo>, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if child.ppid <= 1 || known.contains_key(&child.ppid) || proc_pid_exists(child.ppid) { return None; }
        Some(AnomalyDetail {
            rule: "PAR-007".into(), confidence: Confidence::Low,
            reason: format!("Process '{}' (pid {}) has PPID {} which no longer exists in /proc. This may indicate rapid parent termination used to obscure lineage.", child.name, child.pid, child.ppid),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn par_008(&self, child: &ProcInfo, known: &HashMap<u32, ProcInfo>, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if child.ppid <= 1 { return None; }
        let recorded = known.get(&child.ppid)?;
        let live_parent_name = fs::read_to_string(format!("/proc/{}/status", child.ppid)).ok()
            .and_then(|s| s.lines().find(|l| l.starts_with("Name:\t")).map(|l| l.trim_start_matches("Name:\t").trim().to_lowercase()))?;
        if live_parent_name == recorded.name.to_lowercase() { return None; }
        Some(AnomalyDetail {
            rule: "PAR-008".into(), confidence: Confidence::Low,
            reason: format!("PPID {} for process '{}' (pid {}) was previously '{}' but is now '{}'. Possible PID reuse — parent identity may be forged.", child.ppid, child.name, child.pid, recorded.name, live_parent_name),
            parent_exe: recorded.exe.clone(), ancestors: ancestors.to_vec(),
        })
    }

    fn build_ancestors(&self, mut ppid: u32, known: &HashMap<u32, ProcInfo>) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        while ppid > 1 && !seen.contains(&ppid) {
            seen.insert(ppid); chain.push(ppid);
            ppid = known.get(&ppid).map(|p| p.ppid).unwrap_or(0);
        }
        chain
    }
}

impl Default for RuleEngine { fn default() -> Self { Self::new() } }

fn proc_pid_exists(pid: u32) -> bool { std::path::Path::new(&format!("/proc/{}", pid)).exists() }
