// rules_path.rs — Phase 2: Anomalous Execution Path detection
//
// Three categories:
//   PATH-*  Suspicious filesystem locations
//   ARG-*   Command-line obfuscation patterns
//   ENV-*   Dangerous environment variable manipulation
//
// Plugs into the existing RuleEngine via evaluate_path() called after
// evaluate() (parentage rules) in scanner.rs.

use std::collections::HashMap;
use std::fs;

use crate::models::{AnomalyDetail, Confidence, ProcInfo};

// ── World-writable / temp directories ────────────────────────────────────────

// Directories that should never contain executed binaries
const FORBIDDEN_EXEC_DIRS: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/dev/shm",
];

// ── Obfuscation indicators in argv ────────────────────────────────────────────

// Substrings that strongly suggest base64/eval obfuscation in cmdline
const OBFUSCATION_PATTERNS: &[&str] = &[
    "base64",
    "eval",
    "exec(",
    "IEX(",           // PowerShell invoke-expression (future cross-platform)
    "fromCharCode",
    "/dev/stdin",
    "/dev/tcp/",      // bash TCP redirection
    "/dev/udp/",
    ">${IFS}",        // IFS separator abuse
    "${IFS}",
    "\\x",            // hex-encoded chars in shell args
];

// ── PATH_RULE engine ──────────────────────────────────────────────────────────

pub struct PathRuleEngine;

impl PathRuleEngine {
    pub fn new() -> Self { Self }

    /// Evaluate all PATH/ARG/ENV rules for a newly-seen process.
    /// Returns the highest-confidence anomaly found, or None if clean.
    pub fn evaluate(
        &self,
        proc: &ProcInfo,
        known: &HashMap<u32, ProcInfo>,
    ) -> Option<AnomalyDetail> {
        let ancestors = self.build_ancestors(proc.ppid, known);

        // PATH rules (High priority first)
        if let Some(d) = self.path_001(proc, &ancestors) { return Some(d); }
        if let Some(d) = self.path_002(proc, &ancestors) { return Some(d); }
        if let Some(d) = self.path_003(proc, &ancestors) { return Some(d); }
        if let Some(d) = self.path_004(proc, &ancestors) { return Some(d); }

        // ARG rules
        if let Some(d) = self.arg_001(proc, &ancestors)  { return Some(d); }
        if let Some(d) = self.arg_002(proc, &ancestors)  { return Some(d); }
        if let Some(d) = self.arg_003(proc, &ancestors)  { return Some(d); }

        // ENV rules
        if let Some(d) = self.env_001(proc, &ancestors)  { return Some(d); }
        if let Some(d) = self.env_002(proc, &ancestors)  { return Some(d); }

        None
    }

    // ── PATH-001: Binary running from /tmp, /dev/shm, /var/tmp ──────────────

    fn path_001(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = proc.exe.as_deref()?;

        let hit = FORBIDDEN_EXEC_DIRS.iter()
            .find(|&&dir| exe.starts_with(dir));

        let dir = hit?;

        Some(AnomalyDetail {
            rule:       "PATH-001".into(),
            confidence: Confidence::High,
            reason: format!(
                "Process '{}' (pid {}) is executing from '{}', \
                 a world-writable temporary directory. \
                 Legitimate software is never installed here — \
                 this is a strong indicator of a dropper, \
                 fileless malware stage, or exploitation artifact.",
                proc.name, proc.pid, dir
            ),
            parent_exe: None,
            ancestors:  ancestors.to_vec(),
        })
    }

    // ── PATH-002: Executing from /proc/[pid]/fd (memfd_create trick) ─────────

    fn path_002(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = proc.exe.as_deref()?;

        if !exe.starts_with("/proc/") || !exe.contains("/fd/") {
            return None;
        }

        Some(AnomalyDetail {
            rule:       "PATH-002".into(),
            confidence: Confidence::High,
            reason: format!(
                "Process '{}' (pid {}) appears to be executing from '{}'. \
                 This matches the memfd_create() fileless execution technique \
                 where malware writes a binary to an anonymous memory file \
                 descriptor and executes it without touching disk.",
                proc.name, proc.pid, exe
            ),
            parent_exe: None,
            ancestors:  ancestors.to_vec(),
        })
    }

    // ── PATH-003: cwd is /tmp or /dev/shm ────────────────────────────────────

    fn path_003(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let cwd = proc.cwd.as_deref()?;

        // Only flag if exe is NOT also in a suspicious dir
        // (PATH-001 already covers that case)
        let exe = proc.exe.as_deref().unwrap_or("");
        if FORBIDDEN_EXEC_DIRS.iter().any(|&d| exe.starts_with(d)) {
            return None; // already caught by PATH-001
        }

        let suspicious_cwd = FORBIDDEN_EXEC_DIRS.iter().any(|&d| cwd.starts_with(d));
        if !suspicious_cwd {
            return None;
        }

        Some(AnomalyDetail {
            rule:       "PATH-003".into(),
            confidence: Confidence::Medium,
            reason: format!(
                "Process '{}' (pid {}) has its working directory set to '{}'. \
                 Legitimate daemons and applications rarely use temporary \
                 directories as their working directory. \
                 This may indicate staging activity.",
                proc.name, proc.pid, cwd
            ),
            parent_exe: None,
            ancestors:  ancestors.to_vec(),
        })
    }

    // ── PATH-004: Executable path contains double-dot or unusual segments ─────

    fn path_004(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let exe = proc.exe.as_deref()?;

        // Path traversal or hidden directory
        let suspicious = exe.contains("/../")
            || exe.contains("/./")
            || exe.split('/').any(|seg| seg.starts_with('.') && seg.len() > 1);

        if !suspicious { return None; }

        Some(AnomalyDetail {
            rule:       "PATH-004".into(),
            confidence: Confidence::Medium,
            reason: format!(
                "Process '{}' (pid {}) is executing from an unusual path '{}' \
                 containing path traversal sequences or hidden directories. \
                 Malware commonly hides in dotfiles or uses traversal to \
                 obscure its true location.",
                proc.name, proc.pid, exe
            ),
            parent_exe: None,
            ancestors:  ancestors.to_vec(),
        })
    }

    // ── ARG-001: Base64 / eval / exec obfuscation in cmdline ─────────────────

    fn arg_001(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if proc.cmdline.is_empty() { return None; }

        let full_cmd = proc.cmdline.join(" ");
        let lower    = full_cmd.to_lowercase();

        let hit = OBFUSCATION_PATTERNS.iter()
            .find(|&&pat| lower.contains(pat))?;

        Some(AnomalyDetail {
            rule:       "ARG-001".into(),
            confidence: Confidence::High,
            reason: format!(
                "Process '{}' (pid {}) has obfuscation indicator '{}' \
                 in its command-line arguments: `{}`. \
                 This pattern is used to bypass command-line auditing, \
                 execute encoded payloads, or establish covert channels.",
                proc.name, proc.pid, hit,
                truncate(&full_cmd, 120)
            ),
            parent_exe: None,
            ancestors:  ancestors.to_vec(),
        })
    }

    // ── ARG-002: Shell launched with -c and a suspiciously long argument ──────

    fn arg_002(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        if proc.cmdline.len() < 3 { return None; }

        let is_shell = matches!(
            proc.name.as_str(),
            "bash" | "sh" | "dash" | "zsh" | "fish" | "ksh"
        );
        if !is_shell { return None; }

        // argv[1] == -c, argv[2] is the inline script
        let flag   = &proc.cmdline[1];
        let script = &proc.cmdline[2];

        if flag != "-c" { return None; }

        // Flag if the inline script is long (>256 chars) — suggests downloaded payload
        if script.len() < 256 { return None; }

        Some(AnomalyDetail {
            rule:       "ARG-002".into(),
            confidence: Confidence::Medium,
            reason: format!(
                "Shell '{}' (pid {}) launched with '-c' and a {}-character inline \
                 script argument. Long inline scripts are commonly used by \
                 download-and-exec one-liners to avoid writing to disk. \
                 Preview: `{}`",
                proc.name, proc.pid,
                script.len(),
                truncate(script, 80)
            ),
            parent_exe: None,
            ancestors:  ancestors.to_vec(),
        })
    }

    // ── ARG-003: Process with empty or single-char argv[0] (name hiding) ──────

    fn arg_003(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        // Some malware replaces argv[0] with spaces or a misleading name
        if proc.cmdline.is_empty() { return None; }

        let argv0      = &proc.cmdline[0];
        let comm_name  = &proc.name;

        // argv[0] is all whitespace
        if argv0.trim().is_empty() && !argv0.is_empty() {
            return Some(AnomalyDetail {
                rule:       "ARG-003".into(),
                confidence: Confidence::Medium,
                reason: format!(
                    "Process '{}' (pid {}) has argv[0] consisting entirely of whitespace. \
                     This is a technique used to hide a process name from tools \
                     that display the command line.",
                    comm_name, proc.pid
                ),
                parent_exe: None,
                ancestors:  ancestors.to_vec(),
            });
        }

        // argv[0] differs significantly from the comm name — masquerade
        // (allow common legitimate patterns like "python3" vs "python")
        let argv0_base = argv0.split('/').last().unwrap_or(argv0);
        let comm_lower = comm_name.to_lowercase();
        let arg0_lower = argv0_base.to_lowercase();

        let names_match = comm_lower.contains(&arg0_lower)
            || arg0_lower.contains(&comm_lower)
            || comm_lower.starts_with(&arg0_lower[..arg0_lower.len().min(4)]);

        if !names_match && !argv0.starts_with('-') && argv0.len() > 2 {
            return Some(AnomalyDetail {
                rule:       "ARG-003".into(),
                confidence: Confidence::Low,
                reason: format!(
                    "Process comm name '{}' (pid {}) does not match argv[0] '{}'. \
                     May indicate process masquerading — a technique where malware \
                     renames itself to look like a legitimate system process.",
                    comm_name, proc.pid, argv0_base
                ),
                parent_exe: None,
                ancestors:  ancestors.to_vec(),
            });
        }

        None
    }

    // ── ENV-001: LD_PRELOAD set (library injection) ───────────────────────────

    fn env_001(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let env = read_environ(proc.pid)?;

        let ld_preload = env.iter()
            .find(|line| line.starts_with("LD_PRELOAD="))?;

        let value = ld_preload.trim_start_matches("LD_PRELOAD=");

        // Empty LD_PRELOAD is harmless (used to clear it)
        if value.is_empty() { return None; }

        Some(AnomalyDetail {
            rule:       "ENV-001".into(),
            confidence: Confidence::High,
            reason: format!(
                "Process '{}' (pid {}) has LD_PRELOAD set to '{}'. \
                 LD_PRELOAD forces the dynamic linker to load an attacker-supplied \
                 shared library into every spawned process, enabling function \
                 hooking, credential theft, and rootkit behaviour.",
                proc.name, proc.pid, truncate(value, 80)
            ),
            parent_exe: None,
            ancestors:  ancestors.to_vec(),
        })
    }

    // ── ENV-002: PATH contains /tmp or . (current-directory hijack) ──────────

    fn env_002(&self, proc: &ProcInfo, ancestors: &[u32]) -> Option<AnomalyDetail> {
        let env = read_environ(proc.pid)?;

        let path_var = env.iter()
            .find(|line| line.starts_with("PATH="))?;

        let value = path_var.trim_start_matches("PATH=");

        let bad_segments: Vec<&str> = value
            .split(':')
            .filter(|seg| {
                *seg == "."
                || seg.is_empty()          // empty = current dir
                || seg.starts_with("/tmp")
                || seg.starts_with("/var/tmp")
                || seg.starts_with("/dev/shm")
            })
            .collect();

        if bad_segments.is_empty() { return None; }

        Some(AnomalyDetail {
            rule:       "ENV-002".into(),
            confidence: Confidence::Medium,
            reason: format!(
                "Process '{}' (pid {}) has suspicious segments in PATH: {:?}. \
                 Including '.' or writable temp directories in PATH allows \
                 an attacker to hijack command execution by placing a malicious \
                 binary with the same name as a common tool.",
                proc.name, proc.pid, bad_segments
            ),
            parent_exe: None,
            ancestors:  ancestors.to_vec(),
        })
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    fn build_ancestors(&self, mut ppid: u32, known: &HashMap<u32, ProcInfo>) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut seen  = std::collections::HashSet::new();
        while ppid > 1 && !seen.contains(&ppid) {
            seen.insert(ppid);
            chain.push(ppid);
            ppid = known.get(&ppid).map(|p| p.ppid).unwrap_or(0);
        }
        chain
    }
}

impl Default for PathRuleEngine { fn default() -> Self { Self::new() } }

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read /proc/[pid]/environ and split into key=value strings.
/// Returns None if unreadable (permission denied, process exited).
fn read_environ(pid: u32) -> Option<Vec<String>> {
    let raw = fs::read(format!("/proc/{}/environ", pid)).ok()?;
    Some(
        raw.split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect(),
    )
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { s }
    else { &s[..max] }
}
