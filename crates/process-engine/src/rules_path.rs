use std::collections::HashMap;
use crate::models::{AnomalyDetail, Confidence, ProcInfo};

const FORBIDDEN_EXEC_DIRS: &[&str] = &[
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "\\AppData\\Local\\Temp", "\\Windows\\Temp", "\\Users\\Public",
    "/appdata/local/temp", "/windows/temp", "/users/public"
];
const SAFE_DOT_SEGMENTS: &[&str] = &[
    ".venv", ".nvm", ".cargo", ".npm", ".local", ".cache", ".rustup",
    ".vscode-server", ".config", ".pyenv", ".pnpm", ".bun", ".yarn",
];
const OBFUSCATION_PATTERNS: &[&str] = &[
    "base64 -d", "base64 --decode", "eval($_", "iex(", "fromcharcode", "/dev/tcp/", "/dev/udp/",
    ">${ifs}", "${ifs}", "downloadstring", "invoke-expression", "bypass -enc", "hidden -enc"
];

pub struct PathRuleEngine;

impl PathRuleEngine {
    pub fn new() -> Self { Self }

    pub fn evaluate(&self, proc: &ProcInfo, known: &HashMap<u32, ProcInfo>) -> Option<AnomalyDetail> {
        let ancestors = self.build_ancestors(proc.ppid, known);
        if let Some(d) = self.path_001(proc, &ancestors) { return Some(d); }
        if let Some(d) = self.path_002(proc, &ancestors) { return Some(d); }
        if let Some(d) = self.path_004(proc, &ancestors) { return Some(d); }
        if let Some(d) = self.arg_001(proc, &ancestors)  { return Some(d); }
        if let Some(d) = self.arg_003(proc, &ancestors)  { return Some(d); }
        if let Some(d) = self.env_001(proc, &ancestors)  { return Some(d); }
        if let Some(d) = self.env_002(proc, &ancestors)  { return Some(d); }
        None
    }

    fn path_001(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = proc.exe.as_deref()?;
        let name_lower = proc.name.to_lowercase();
        if matches!(name_lower.as_str(), "node"|"tsx"|"vite"|"npm"|"npx"|"cargo"|"go"|"pip"|"pip3"|"esbuild"|"rustc"|"gcc") {
            return None;
        }
        let dir = FORBIDDEN_EXEC_DIRS.iter().find(|&&d| exe.starts_with(d))?;
        let in_shm = *dir == "/dev/shm/";
        Some(AnomalyDetail {
            rule: "PATH-001".into(),
            confidence: if in_shm { Confidence::High } else { Confidence::Low },
            priority_tier: if in_shm { "P2".into() } else { "P4".into() },
            risk_score: if in_shm { 76 } else { 32 },
            reason: format!("Process '{}' (pid {}) is executing from '{}', a writable temporary directory.", proc.name, proc.pid, dir),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn path_002(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = proc.exe.as_deref()?;
        if !exe.starts_with("/proc/") || !exe.contains("/fd/") { return None; }
        Some(AnomalyDetail {
            rule: "PATH-002".into(), confidence: Confidence::High,
            priority_tier: "P2".into(), risk_score: 84,
            reason: format!("Process '{}' (pid {}) appears to be executing from '{}'. Matches memfd_create() execution.", proc.name, proc.pid, exe),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn path_004(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = proc.exe.as_deref()?;
        let has_traversal = exe.contains("/../") || exe.contains("/./");
        let hidden_in_tmp = FORBIDDEN_EXEC_DIRS.iter().any(|&d| exe.starts_with(d))
            && exe.split('/').any(|seg| seg.starts_with('.') && seg.len() > 1 && !SAFE_DOT_SEGMENTS.contains(&seg));
        if !has_traversal && !hidden_in_tmp { return None; }
        Some(AnomalyDetail {
            rule: "PATH-004".into(), confidence: Confidence::Medium,
            priority_tier: "P3".into(), risk_score: 52,
            reason: format!("Process '{}' (pid {}) path '{}' contains traversal or hidden temp segment.", proc.name, proc.pid, exe),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn arg_001(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if proc.cmdline.is_empty() { return None; }
        let name_lower = proc.name.to_lowercase();
        let full_cmd = proc.cmdline.join(" ");
        let lower = full_cmd.to_lowercase();
        let critical_pipe = lower.contains("/dev/tcp/") || lower.contains("/dev/udp/");
        if !critical_pipe && matches!(name_lower.as_str(), "node"|"vite"|"tsx"|"esbuild"|"webpack"|"vitest"|"jest"|"tsc") {
            return None;
        }
        let hit = OBFUSCATION_PATTERNS.iter().find(|&&pat| lower.contains(pat))?;
        Some(AnomalyDetail {
            rule: "ARG-001".into(),
            confidence: if critical_pipe { Confidence::High } else { Confidence::Low },
            priority_tier: if critical_pipe { "P1".into() } else { "P3".into() },
            risk_score: if critical_pipe { 92 } else { 42 },
            reason: format!("Process '{}' (pid {}) has command-line indicator '{}': `{}`.", proc.name, proc.pid, hit, truncate(&full_cmd, 120)),
            parent_exe: None, ancestors: ancestors.to_vec(),
        })
    }

    fn arg_003(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if proc.cmdline.is_empty() { return None; }
        let argv0 = &proc.cmdline[0];
        if argv0.trim().is_empty() && !argv0.is_empty() {
            return Some(AnomalyDetail {
                rule: "ARG-003".into(), confidence: Confidence::Medium,
                priority_tier: "P3".into(), risk_score: 56,
                reason: format!("Process '{}' (pid {}) has whitespace-only argv[0].", proc.name, proc.pid),
                parent_exe: None, ancestors: ancestors.to_vec(),
            });
        }
        None
    }

    fn env_001(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let env = read_environ(proc.pid)?;
        let ld_preload = env.iter().find(|line| line.starts_with("LD_PRELOAD="))?;
        let value = ld_preload.trim_start_matches("LD_PRELOAD=");
        if value.is_empty() { return None; }
        Some(AnomalyDetail {
            rule: "ENV-001".into(), confidence: Confidence::High,
            priority_tier: "P2".into(), risk_score: 80,
            reason: format!("Process '{}' (pid {}) has LD_PRELOAD set to '{}'.", proc.name, proc.pid, truncate(value, 80)),
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
            priority_tier: "P3".into(), risk_score: 45,
            reason: format!("Process '{}' (pid {}) has writable segments in PATH: {:?}.", proc.name, proc.pid, bad),
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
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read(format!("/proc/{}/environ", pid)).ok()?;
        Some(raw.split(|&b| b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}
