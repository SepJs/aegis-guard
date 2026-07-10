use std::collections::HashMap;
use std::fs;
use crate::models::{AnomalyDetail, Confidence, ProcInfo};

const FORBIDDEN_EXEC_DIRS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];
const OBFUSCATION_PATTERNS: &[&str] = &["base64","eval","exec(","IEX(","fromCharCode","/dev/stdin","/dev/tcp/","/dev/udp/",">${IFS}","${IFS}","\\x"];

pub struct PathRuleEngine;

impl PathRuleEngine {
    pub fn new() -> Self { Self }

    pub fn evaluate(&self, proc: &ProcInfo, known: &HashMap<u32, ProcInfo>) -> Option<AnomalyDetail> {
        let ancestors = self.build_ancestors(proc.ppid, known);
        if let Some(d) = self.path_001(proc, &ancestors) { return Some(d); }
        if let Some(d) = self.path_002(proc, &ancestors) { return Some(d); }
        if let Some(d) = self.path_003(proc, &ancestors) { return Some(d); }
        if let Some(d) = self.path_004(proc, &ancestors) { return Some(d); }
        if let Some(d) = self.arg_001(proc, &ancestors)  { return Some(d); }
        if let Some(d) = self.arg_002(proc, &ancestors)  { return Some(d); }
        if let Some(d) = self.arg_003(proc, &ancestors)  { return Some(d); }
        if let Some(d) = self.env_001(proc, &ancestors)  { return Some(d); }
        if let Some(d) = self.env_002(proc, &ancestors)  { return Some(d); }
        None
    }

    fn path_001(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = proc.exe.as_deref()?;
        let dir = FORBIDDEN_EXEC_DIRS.iter().find(|&&d| exe.starts_with(d))?;
        Some(AnomalyDetail {
            rule: "PATH-001".into(), confidence: Confidence::High,
            reason: format!("Process '{}' (pid {}) is executing from '{}', a world-writable temporary directory. Legitimate software is never installed here — this is a strong indicator of a dropper, fileless malware stage, or exploitation artifact.", proc.name, proc.pid, dir),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn path_002(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = proc.exe.as_deref()?;
        if !exe.starts_with("/proc/") || !exe.contains("/fd/") { return None; }
        Some(AnomalyDetail {
            rule: "PATH-002".into(), confidence: Confidence::High,
            reason: format!("Process '{}' (pid {}) appears to be executing from '{}'. This matches the memfd_create() fileless execution technique.", proc.name, proc.pid, exe),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn path_003(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let cwd = proc.cwd.as_deref()?;
        let exe = proc.exe.as_deref().unwrap_or("");
        if FORBIDDEN_EXEC_DIRS.iter().any(|&d| exe.starts_with(d)) { return None; }
        if !FORBIDDEN_EXEC_DIRS.iter().any(|&d| cwd.starts_with(d)) { return None; }
        Some(AnomalyDetail {
            rule: "PATH-003".into(), confidence: Confidence::Medium,
            reason: format!("Process '{}' (pid {}) has its working directory set to '{}'. Legitimate daemons rarely use temp directories as CWD.", proc.name, proc.pid, cwd),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn path_004(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = proc.exe.as_deref()?;
        let suspicious = exe.contains("/../") || exe.contains("/./")
            || exe.split('/').any(|seg| seg.starts_with('.') && seg.len() > 1);
        if !suspicious { return None; }
        Some(AnomalyDetail {
            rule: "PATH-004".into(), confidence: Confidence::Medium,
            reason: format!("Process '{}' (pid {}) is executing from an unusual path '{}' containing path traversal or hidden directories.", proc.name, proc.pid, exe),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn arg_001(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if proc.cmdline.is_empty() { return None; }
        let full_cmd = proc.cmdline.join(" ");
        let lower = full_cmd.to_lowercase();
        let hit = OBFUSCATION_PATTERNS.iter().find(|&&pat| lower.contains(pat))?;
        Some(AnomalyDetail {
            rule: "ARG-001".into(), confidence: Confidence::High,
            reason: format!("Process '{}' (pid {}) has obfuscation indicator '{}' in its command-line: `{}`.", proc.name, proc.pid, hit, truncate(&full_cmd, 120)),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn arg_002(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if proc.cmdline.len() < 3 { return None; }
        let is_shell = matches!(proc.name.as_str(), "bash"|"sh"|"dash"|"zsh"|"fish"|"ksh");
        if !is_shell || proc.cmdline[1] != "-c" { return None; }
        let script = &proc.cmdline[2];
        if script.len() < 256 { return None; }
        Some(AnomalyDetail {
            rule: "ARG-002".into(), confidence: Confidence::Medium,
            reason: format!("Shell '{}' (pid {}) launched with '-c' and a {}-character inline script. Preview: `{}`", proc.name, proc.pid, script.len(), truncate(script, 80)),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn arg_003(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if proc.cmdline.is_empty() { return None; }
        let argv0 = &proc.cmdline[0];
        if argv0.trim().is_empty() && !argv0.is_empty() {
            return Some(AnomalyDetail {
                rule: "ARG-003".into(), confidence: Confidence::Medium,
                reason: format!("Process '{}' (pid {}) has argv[0] consisting entirely of whitespace — a name-hiding technique.", proc.name, proc.pid),
                parent_exe: None, ancestors: ancestors.to_vec(),
            });
        }
        let argv0_base = argv0.split('/').next_back().unwrap_or(argv0);
        let comm_lower = proc.name.to_lowercase();
        let arg0_lower = argv0_base.to_lowercase();
        let names_match = comm_lower.contains(&arg0_lower) || arg0_lower.contains(&comm_lower)
            || comm_lower.starts_with(&arg0_lower[..arg0_lower.len().min(4)]);
        if names_match || argv0.starts_with('-') || argv0.len() <= 2 { return None; }
        Some(AnomalyDetail {
            rule: "ARG-003".into(), confidence: Confidence::Low,
            reason: format!("Process comm name '{}' (pid {}) does not match argv[0] '{}'. May indicate process masquerading.", proc.name, proc.pid, argv0_base),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn env_001(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let env = read_environ(proc.pid)?;
        let ld_preload = env.iter().find(|line| line.starts_with("LD_PRELOAD="))?;
        let value = ld_preload.trim_start_matches("LD_PRELOAD=");
        if value.is_empty() { return None; }
        Some(AnomalyDetail {
            rule: "ENV-001".into(), confidence: Confidence::High,
            reason: format!("Process '{}' (pid {}) has LD_PRELOAD set to '{}'. This forces the dynamic linker to load an attacker library into every spawned process.", proc.name, proc.pid, truncate(value, 80)),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn env_002(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let env = read_environ(proc.pid)?;
        let path_var = env.iter().find(|line| line.starts_with("PATH="))?;
        let value = path_var.trim_start_matches("PATH=");
        let bad: Vec<&str> = value.split(':').filter(|seg| {
            *seg == "." || seg.is_empty() || seg.starts_with("/tmp") || seg.starts_with("/var/tmp") || seg.starts_with("/dev/shm")
        }).collect();
        if bad.is_empty() { return None; }
        Some(AnomalyDetail {
            rule: "ENV-002".into(), confidence: Confidence::Medium,
            reason: format!("Process '{}' (pid {}) has suspicious segments in PATH: {:?}. Enables command hijacking via writable temp dirs.", proc.name, proc.pid, bad),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn build_ancestors(&self, mut ppid: u32, known: &HashMap<u32, ProcInfo>) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut seen = std::collections::HashSet::new();
        while ppid > 1 && !seen.contains(&ppid) {
            seen.insert(ppid); chain.push(ppid);
            ppid = known.get(&ppid).map(|p| p.ppid).unwrap_or(0);
        }
        chain
    }
}

impl Default for PathRuleEngine { fn default() -> Self { Self::new() } }

fn read_environ(pid: u32) -> Option<Vec<String>> {
    let raw = fs::read(format!("/proc/{}/environ", pid)).ok()?;
    Some(raw.split(|&b| b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect())
}

fn truncate(s: &str, max: usize) -> &str { if s.len() <= max { s } else { &s[..max] } }
