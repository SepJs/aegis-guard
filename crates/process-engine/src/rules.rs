use std::collections::{HashMap, HashSet};
use std::fs;
use crate::models::{AnomalyDetail, Confidence, ProcInfo};

const BROWSER_NAMES: &[&str] = &[
    "firefox","firefox-bin","firefox-esr","firefox.exe",
    "chromium","chromium-browser","chrome","chrome.exe",
    "brave","brave-browser","brave.exe",
    "msedge","msedge.exe",
    "opera","opera.exe","vivaldi","vivaldi.exe","epiphany","midori"
];
const SHELL_NAMES: &[&str] = &[
    "bash","bash.exe","sh","sh.exe","dash","dash.exe","zsh","fish","ksh","tcsh","csh","ash","mksh","posh",
    "cmd","cmd.exe","powershell","powershell.exe","pwsh","pwsh.exe",
    "wscript","wscript.exe","cscript","cscript.exe","mshta","mshta.exe"
];
const NETWORK_TOOLS: &[&str] = &[
    "curl","curl.exe","wget","wget.exe","nc","nc.exe","ncat","ncat.exe","netcat","nmap","nmap.exe",
    "ssh","ssh.exe","scp","scp.exe","sftp","ftp","ftp.exe","telnet","telnet.exe",
    "certutil","certutil.exe","bitsadmin","bitsadmin.exe",
    "python3","python3.exe","python","python.exe","perl","perl.exe","ruby","ruby.exe","node","node.exe","nodejs","php","lua",
    "socat","socat.exe","dig","host","nslookup","whois","tftp","tftp.exe"
];

const LOLBINS: &[&str] = &[
    "certutil","certutil.exe","bitsadmin","bitsadmin.exe","mshta","mshta.exe",
    "regsvr32","regsvr32.exe","rundll32","rundll32.exe","msiexec","msiexec.exe",
    "wmic","wmic.exe","cmstp","cmstp.exe","installutil","installutil.exe",
    "regasm","regasm.exe","regsvcs","regsvcs.exe","msbuild","msbuild.exe",
    "csc","csc.exe","jsc","jsc.exe","ilasm","ilasm.exe"
];

const SUSPICIOUS_PATH_MARKERS: &[&str] = &[
    "/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/",
    "\\temp\\", "\\tmp\\", "appdata\\local\\temp", "\\downloads\\"
];
const OFFICE_NAMES: &[&str] = &[
    "soffice","soffice.bin","libreoffice","libreoffice-writer","libreoffice-calc","evince","okular","zathura","abiword","gnumeric",
    "winword","winword.exe","excel","excel.exe","powerpnt","powerpnt.exe","outlook","outlook.exe"
];
const INTERPRETER_NAMES: &[&str] = &[
    "bash","sh","dash","zsh","python3","python","perl","ruby","node","nodejs","php","lua","tclsh","wish",
    "powershell","powershell.exe","cmd","cmd.exe","cscript","cscript.exe","wscript","wscript.exe"
];

#[derive(Clone)]
pub struct RuleEngine {
    browsers: HashSet<&'static str>, shells: HashSet<&'static str>,
    net_tools: HashSet<&'static str>, office: HashSet<&'static str>, interpreters: HashSet<&'static str>,
    lolbins: HashSet<&'static str>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            browsers: BROWSER_NAMES.iter().copied().collect(),
            shells: SHELL_NAMES.iter().copied().collect(),
            net_tools: NETWORK_TOOLS.iter().copied().collect(),
            office: OFFICE_NAMES.iter().copied().collect(),
            interpreters: INTERPRETER_NAMES.iter().copied().collect(),
            lolbins: LOLBINS.iter().copied().collect(),
        }
    }

    pub fn evaluate(&self, child: &ProcInfo, known: &HashMap<u32, ProcInfo>) -> Option<AnomalyDetail> {
        let child_name = child.name.to_lowercase();
        let parent = known.get(&child.ppid);
        let parent_name = parent.map(|p| p.name.to_lowercase()).unwrap_or_default();
        let ancestors = self.build_ancestors(child.ppid, known);

        // High-confidence first
        if let Some(d) = self.par_001(&child_name, &parent_name, &parent, &ancestors) { return Some(d); }
        if let Some(d) = self.par_003(&child_name, &parent_name, &parent, &ancestors) { return Some(d); }
        if let Some(d) = self.par_009(child, &child_name, &ancestors) { return Some(d); } // suspicious path
        if let Some(d) = self.par_010(child, &child_name, &parent_name, &ancestors) { return Some(d); } // LOLBin abuse
        if let Some(d) = self.par_011(child, &child_name, &ancestors) { return Some(d); } // encoded / base64 launch
        if let Some(d) = self.par_012(child, &child_name, &parent_name, &ancestors) { return Some(d); } // reverse shell patterns
        if let Some(d) = self.par_002(&child_name, &ancestors, known) { return Some(d); }
        if let Some(d) = self.par_004(child, &child_name, &parent_name, &ancestors) { return Some(d); }
        if let Some(d) = self.par_005(child, &ancestors) { return Some(d); }
        if let Some(d) = self.par_006(child, &child_name, &ancestors) { return Some(d); }
        if let Some(d) = self.par_013(child, &child_name, &ancestors) { return Some(d); } // hidden / double-extension
        if let Some(d) = self.par_007(child, known, &ancestors) { return Some(d); }
        if let Some(d) = self.par_008(child, known, &ancestors) { return Some(d); }
        if let Some(d) = self.par_014(child, &child_name, &parent_name, &ancestors) { return Some(d); } // root from user shell
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

        // Benign common dev / admin network tools in SSH should not be marked as high false positives
        let is_high_risk_net_tool = matches!(child_name, "nc" | "ncat" | "netcat" | "nmap" | "telnet");
        let confidence = if is_high_risk_net_tool {
            Confidence::Medium
        } else {
            Confidence::Low
        };

        Some(AnomalyDetail {
            rule: "PAR-002".into(), confidence,
            reason: format!("Network utility '{}' executed inside an authenticated SSH session chain. Audited for exfiltration or lateral movement.", child_name),
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

    /// PAR-009: Executable launched from suspicious world-writable paths (/tmp, /dev/shm, Temp, Downloads)
    fn par_009(&self, child: &ProcInfo, child_name: &str, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = child.exe.as_deref()?.to_lowercase();
        let is_sus_path = SUSPICIOUS_PATH_MARKERS.iter().any(|m| exe.contains(m));
        if !is_sus_path { return None; }
        // Ignore common package managers / installers that legitimately use /tmp
        if matches!(child_name, "apt" | "apt-get" | "dpkg" | "yum" | "dnf" | "pacman" | "zypper" | "pip" | "pip3" | "npm" | "cargo" | "go") {
            return None;
        }
        Some(AnomalyDetail {
            rule: "PAR-009".into(), confidence: Confidence::High,
            reason: format!("Process '{}' (pid {}) launched from suspicious path '{}'. Malware frequently stages payloads in world-writable locations.", child_name, child.pid, exe),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    /// PAR-010: Living-Off-The-Land binary abuse (LOLBins) used for download / execution
    fn par_010(&self, child: &ProcInfo, child_name: &str, parent_name: &str, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if !self.lolbins.contains(child_name) { return None; }
        // High risk when spawned by shell or office
        let risky_parent = self.shells.contains(parent_name) || self.office.contains(parent_name) || self.browsers.contains(parent_name);
        if !risky_parent { return None; }
        Some(AnomalyDetail {
            rule: "PAR-010".into(), confidence: Confidence::High,
            reason: format!("LOLBin '{}' spawned by '{}'. Living-off-the-land techniques are commonly used to download or execute payloads while blending with legitimate tools.", child_name, parent_name),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    /// PAR-011: Command-line indicators of encoded / obfuscated execution
    fn par_011(&self, child: &ProcInfo, child_name: &str, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let cmdline = child.cmdline.join(" ").to_lowercase();
        if cmdline.is_empty() { return None; }
        let indicators = [
            "base64", "-enc ", "-encodedcommand", "frombase64string",
            "iex(", "invoke-expression", "downloadstring", "downloadfile",
            " -e ", " -c ", "python -c", "perl -e", "ruby -e",
            "/dev/tcp/", "mkfifo", "bash -i", "sh -i",
        ];
        let hit = indicators.iter().find(|&&i| cmdline.contains(i))?;
        Some(AnomalyDetail {
            rule: "PAR-011".into(), confidence: Confidence::High,
            reason: format!("Process '{}' (pid {}) command line contains obfuscation / download indicator '{}'. Classic stager / reverse-shell pattern.", child_name, child.pid, hit),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    /// PAR-012: Classic reverse-shell / C2 launch patterns
    fn par_012(&self, child: &ProcInfo, child_name: &str, parent_name: &str, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let cmdline = child.cmdline.join(" ").to_lowercase();
        let is_rev = cmdline.contains("nc -e") || cmdline.contains("ncat -e") || cmdline.contains("bash -i >&")
            || cmdline.contains("/dev/tcp/") || cmdline.contains("socat tcp")
            || (cmdline.contains("python -c") && cmdline.contains("socket"))
            || ((child_name == "bash" || child_name == "sh") && cmdline.contains("-i") && (cmdline.contains(">&") || cmdline.contains("2>&1")));
        if !is_rev { return None; }
        Some(AnomalyDetail {
            rule: "PAR-012".into(), confidence: Confidence::High, // Critical not in enum yet
            reason: format!("Reverse shell / interactive C2 pattern detected for '{}' (pid {}) spawned by '{}'. Immediate containment recommended.", child_name, child.pid, parent_name),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    /// PAR-013: Hidden files or double-extension masquerading
    fn par_013(&self, child: &ProcInfo, child_name: &str, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = child.exe.as_deref()?.to_lowercase();
        let name_lower = child_name.to_lowercase();
        // Hidden binary (starts with .)
        if name_lower.starts_with('.') && !name_lower.starts_with("./") {
            return Some(AnomalyDetail {
                rule: "PAR-013".into(), confidence: Confidence::Medium,
                reason: format!("Hidden executable '{}' (pid {}) detected. Attackers often hide binaries with leading-dot names.", child_name, child.pid),
                parent_exe: None, ancestors: ancestors.to_vec(),
            });
        }
        // Double extension style (e.g. invoice.pdf.exe) — more Windows, but check anyway
        if exe.matches('.').count() >= 2 && (exe.ends_with(".exe") || exe.ends_with(".elf") || exe.contains(".sh.")) {
            return Some(AnomalyDetail {
                rule: "PAR-013".into(), confidence: Confidence::Medium,
                reason: format!("Suspicious multi-extension path '{}' for process '{}'. Possible social-engineering masquerade.", exe, child_name),
                parent_exe: None, ancestors: ancestors.to_vec(),
            });
        }
        None
    }

    /// PAR-014: Privilege escalation indicator — root process spawned from non-root user shell
    fn par_014(&self, child: &ProcInfo, child_name: &str, parent_name: &str, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if child.uid != 0 { return None; }
        if !self.shells.contains(parent_name) { return None; }
        // Parent should not be root either for this rule (classic sudo/su is expected; we look for unexpected)
        // We only flag if parent is a user shell that suddenly produced a root child without obvious sudo/su name
        if matches!(child_name, "sudo" | "su" | "pkexec" | "doas") { return None; }
        Some(AnomalyDetail {
            rule: "PAR-014".into(), confidence: Confidence::Medium,
            reason: format!("Root process '{}' (pid {}) spawned by non-privileged shell '{}'. Review for unexpected privilege escalation.", child_name, child.pid, parent_name),
            parent_exe: None, ancestors: ancestors.to_vec(),
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
