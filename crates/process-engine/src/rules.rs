use std::collections::{HashMap, HashSet};
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
    office: HashSet<&'static str>, interpreters: HashSet<&'static str>,
    lolbins: HashSet<&'static str>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            browsers: BROWSER_NAMES.iter().copied().collect(),
            shells: SHELL_NAMES.iter().copied().collect(),
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

        // High-confidence first (noise rules PAR-004/007/008 suppressed standalone)
        if let Some(d) = self.par_001(&child_name, &parent_name, &parent, &ancestors) { return Some(d); }
        if let Some(d) = self.par_003(&child_name, &parent_name, &parent, &ancestors) { return Some(d); }
        if let Some(d) = self.par_012(child, &child_name, &parent_name, &ancestors) { return Some(d); } // reverse shell patterns
        if let Some(d) = self.par_009(child, &child_name, &ancestors) { return Some(d); } // suspicious path
        if let Some(d) = self.par_010(child, &child_name, &parent_name, &ancestors) { return Some(d); } // LOLBin abuse
        if let Some(d) = self.par_011(child, &child_name, &ancestors) { return Some(d); } // encoded / base64 launch
        if let Some(d) = self.par_002(&child_name, &ancestors, known) { return Some(d); }
        if let Some(d) = self.par_005(child, &ancestors) { return Some(d); }
        if let Some(d) = self.par_006(child, &child_name, &ancestors) { return Some(d); }
        if let Some(d) = self.par_013(child, &child_name, &ancestors) { return Some(d); } // hidden / double-extension
        if let Some(d) = self.par_014(child, &child_name, &parent_name, &parent, &ancestors) { return Some(d); } // true user->root escalation
        None
    }

    fn par_001(&self, child_name: &str, parent_name: &str, parent: &Option<&ProcInfo>, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if !self.shells.contains(child_name) || !self.browsers.contains(parent_name) { return None; }
        Some(AnomalyDetail {
            rule: "PAR-001".into(), confidence: Confidence::High,
            priority_tier: "P2".into(), risk_score: 82,
            reason: format!("Shell '{}' spawned by browser '{}'. Browsers should never execute interactive shells — this is a common code injection or RCE pattern.", child_name, parent_name),
            parent_exe: parent.and_then(|p| p.exe.clone()), ancestors: ancestors.to_vec(),
        })
    }

    fn par_002(&self, child_name: &str, ancestors: &[u32], known: &HashMap<u32, ProcInfo>) -> Option<AnomalyDetail> {
        // Only flag raw offensive/pivot socket tools inside SSH chains, never standard curl/git/python/node
        if !matches!(child_name, "nc" | "ncat" | "netcat" | "nmap" | "socat" | "telnet") {
            return None;
        }
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
            rule: "PAR-002".into(), confidence: Confidence::Medium,
            priority_tier: "P3".into(), risk_score: 48,
            reason: format!("Socket utility '{}' executed inside an authenticated SSH session chain. Logged for situational awareness.", child_name),
            parent_exe: sshd_exe, ancestors: ancestors.to_vec(),
        })
    }

    fn par_003(&self, child_name: &str, parent_name: &str, parent: &Option<&ProcInfo>, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if !self.interpreters.contains(child_name) || !self.office.contains(parent_name) { return None; }
        Some(AnomalyDetail {
            rule: "PAR-003".into(), confidence: Confidence::High,
            priority_tier: "P2".into(), risk_score: 84,
            reason: format!("Interpreter '{}' spawned by document application '{}'. This is the canonical macro-malware / maldoc execution pattern.", child_name, parent_name),
            parent_exe: parent.and_then(|p| p.exe.clone()), ancestors: ancestors.to_vec(),
        })
    }

    fn par_005(&self, child: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = child.exe.as_deref()?;
        if !exe.ends_with(" (deleted)") { return None; }
        let lower = exe.to_lowercase();
        // Routine OS / app updates under /usr, /opt, /var/lib should not trigger High/Medium security alerts
        if !SUSPICIOUS_PATH_MARKERS.iter().any(|m| lower.contains(m)) {
            return None;
        }
        Some(AnomalyDetail {
            rule: "PAR-005".into(), confidence: Confidence::High,
            priority_tier: "P2".into(), risk_score: 78,
            reason: format!("Process '{}' (pid {}) is executing from an unlinked binary deleted from volatile storage: '{}'.", child.name, child.pid, exe),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn par_006(&self, child: &ProcInfo, child_name: &str, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if !self.shells.contains(child_name) || child.ppid != 1 { return None; }
        let tty = std::fs::read_link(format!("/proc/{}/fd/0", child.pid)).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        if tty.starts_with("/dev/pts") || tty.starts_with("/dev/tty") { return None; }
        // Container entrypoints /pid1 shells often lack PTY fd0
        if child.pid <= 20 { return None; }
        Some(AnomalyDetail {
            rule: "PAR-006".into(), confidence: Confidence::Low,
            priority_tier: "P4".into(), risk_score: 28,
            reason: format!("Headless shell '{}' (pid {}) reparented to init (PID 1) with no controlling terminal.", child_name, child.pid),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    /// PAR-009: Executable launched from suspicious world-writable paths (/tmp, /dev/shm, Temp, Downloads)
    fn par_009(&self, child: &ProcInfo, child_name: &str, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = child.exe.as_deref()?.to_lowercase();
        let is_sus_path = SUSPICIOUS_PATH_MARKERS.iter().any(|m| exe.contains(m));
        if !is_sus_path { return None; }
        if matches!(child_name, "apt" | "apt-get" | "dpkg" | "yum" | "dnf" | "pacman" | "zypper" | "pip" | "pip3" | "npm" | "npx" | "cargo" | "go" | "node" | "tsx" | "vite" | "esbuild" | "rustc") {
            return None;
        }
        let in_shm = exe.contains("/dev/shm/");
        Some(AnomalyDetail {
            rule: "PAR-009".into(),
            confidence: if in_shm { Confidence::High } else { Confidence::Low },
            priority_tier: if in_shm { "P2".into() } else { "P4".into() },
            risk_score: if in_shm { 78 } else { 32 },
            reason: format!("Process '{}' (pid {}) launched from temporary path '{}'.", child_name, child.pid, exe),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    /// PAR-010: Living-Off-The-Land binary abuse (LOLBins)
    fn par_010(&self, child: &ProcInfo, child_name: &str, parent_name: &str, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if !self.lolbins.contains(child_name) { return None; }
        let risky_parent = self.shells.contains(parent_name) || self.office.contains(parent_name) || self.browsers.contains(parent_name);
        if !risky_parent { return None; }
        Some(AnomalyDetail {
            rule: "PAR-010".into(), confidence: Confidence::High,
            priority_tier: "P2".into(), risk_score: 78,
            reason: format!("LOLBin '{}' spawned by '{}'. Living-off-the-land utility monitored for payload staging.", child_name, parent_name),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    /// PAR-011: Command-line indicators of encoded / obfuscated execution (ignores localhost URLs)
    fn par_011(&self, child: &ProcInfo, child_name: &str, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let cmdline = child.cmdline.join(" ").to_lowercase();
        if cmdline.is_empty() { return None; }
        if matches!(child_name, "node" | "vite" | "tsx" | "esbuild" | "tsc" | "webpack" | "vitest" | "jest") {
            return None;
        }
        let indicators = [
            "base64 -d", "base64 --decode", "-encodedcommand", "frombase64string",
            "iex(", "invoke-expression", "downloadstring", "downloadfile",
            "/dev/tcp/", "mkfifo",
        ];
        let hit = indicators.iter().find(|&&i| cmdline.contains(i))?;
        let is_loopback = cmdline.contains("127.0.0.1") || cmdline.contains("localhost") || cmdline.contains("::1");
        let has_remote_net = !is_loopback && (cmdline.contains("curl ") || cmdline.contains("wget "));
        Some(AnomalyDetail {
            rule: "PAR-011".into(),
            confidence: if has_remote_net { Confidence::High } else { Confidence::Low },
            priority_tier: if has_remote_net { "P2".into() } else { "P3".into() },
            risk_score: if has_remote_net { 76 } else { 36 },
            reason: format!("Process '{}' (pid {}) command line contains obfuscation / inline indicator '{}'.", child_name, child.pid, hit),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    /// PAR-012: Confirmed reverse-shell / C2 launch patterns -> P1 Critical
    fn par_012(&self, child: &ProcInfo, child_name: &str, parent_name: &str, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let cmdline = child.cmdline.join(" ").to_lowercase();
        let is_rev = cmdline.contains("nc -e") || cmdline.contains("ncat -e") || cmdline.contains("bash -i >&")
            || cmdline.contains("/dev/tcp/") || cmdline.contains("socat tcp")
            || (cmdline.contains("python") && cmdline.contains("socket") && cmdline.contains("connect"))
            || ((child_name == "bash" || child_name == "sh") && cmdline.contains("-i") && (cmdline.contains(">&") || cmdline.contains("2>&1")));
        if !is_rev { return None; }
        Some(AnomalyDetail {
            rule: "PAR-012".into(), confidence: Confidence::High,
            priority_tier: "P1".into(), risk_score: 95,
            reason: format!("Reverse shell / interactive C2 pattern detected for '{}' (pid {}) spawned by '{}'. Immediate containment recommended.", child_name, child.pid, parent_name),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    /// PAR-013: Hidden binary masquerading in temp paths or deceptive double extensions
    fn par_013(&self, child: &ProcInfo, child_name: &str, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = child.exe.as_deref()?.to_lowercase();
        let basename = exe.rsplit('/').next().unwrap_or("");
        if basename.starts_with('.') && SUSPICIOUS_PATH_MARKERS.iter().any(|m| exe.contains(m)) {
            return Some(AnomalyDetail {
                rule: "PAR-013".into(), confidence: Confidence::High,
                priority_tier: "P2".into(), risk_score: 74,
                reason: format!("Hidden executable '{}' running from temporary location '{}'.", child_name, exe),
                parent_exe: None, ancestors: ancestors.to_vec(),
            });
        }
        let double_ext = [".pdf.exe", ".doc.exe", ".docx.exe", ".jpg.exe", ".txt.sh", ".png.elf"];
        if double_ext.iter().any(|ext| basename.ends_with(ext)) {
            return Some(AnomalyDetail {
                rule: "PAR-013".into(), confidence: Confidence::High,
                priority_tier: "P2".into(), risk_score: 78,
                reason: format!("Deceptive double-extension binary '{}' detected.", exe),
                parent_exe: None, ancestors: ancestors.to_vec(),
            });
        }
        None
    }

    /// PAR-014: Privilege escalation indicator — root process spawned ONLY from a non-root parent shell
    fn par_014(&self, child: &ProcInfo, child_name: &str, parent_name: &str, parent: &Option<&ProcInfo>, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if child.uid != 0 { return None; }
        let p = parent.as_ref()?;
        if p.uid == 0 || !self.shells.contains(parent_name) { return None; }
        if matches!(child_name, "sudo" | "su" | "pkexec" | "doas" | "passwd") { return None; }
        Some(AnomalyDetail {
            rule: "PAR-014".into(), confidence: Confidence::High,
            priority_tier: "P2".into(), risk_score: 75,
            reason: format!("Root process '{}' (pid {}) spawned by non-root shell '{}' (uid {}). Privilege escalation check.", child_name, child.pid, parent_name, p.uid),
            parent_exe: p.exe.clone(), ancestors: ancestors.to_vec(),
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
