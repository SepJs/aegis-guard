use std::{collections::HashMap, fs, time::Duration};
use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use crate::models::{ProcEvent, ProcEventKind, ProcInfo};
use crate::rules::RuleEngine;
use crate::rules_path::PathRuleEngine;

const POLL_INTERVAL_MS: u64 = 250;
const CHANNEL_CAPACITY: usize = 512;

pub fn start(rules: RuleEngine, path_rules: PathRuleEngine) -> mpsc::Receiver<ProcEvent> {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    tokio::spawn(run_scanner(tx, rules, path_rules));
    rx
}

async fn run_scanner(tx: mpsc::Sender<ProcEvent>, rules: RuleEngine, path_rules: PathRuleEngine) {
    let mut known: HashMap<u32, ProcInfo> = HashMap::new();

    match snapshot_all() {
        Ok(initial) => {
            let count = initial.len();
            for (pid, info) in initial { known.insert(pid, info); }
            info!(count, "initial process table seeded");
        }
        Err(e) => warn!("failed to seed process table: {e}"),
    }

    let interval = Duration::from_millis(POLL_INTERVAL_MS);
    loop {
        tokio::time::sleep(interval).await;
        let current = match snapshot_all() {
            Ok(m)  => m,
            Err(e) => { warn!("snapshot failed: {e}"); continue; }
        };

        for (pid, info) in &current {
            if known.contains_key(pid) { continue; }
            debug!(pid, name = %info.name, "new process");
            let anomaly = rules.evaluate(info, &known)
                .or_else(|| path_rules.evaluate(info, &known));
            let kind = if anomaly.is_some() { ProcEventKind::Anomaly } else { ProcEventKind::Spawned };
            let event = ProcEvent::from_proc(info, kind, anomaly);
            if tx.send(event).await.is_err() {
                warn!("event channel closed for pid {pid}");
            }
        }

        let dead: Vec<u32> = known.keys().filter(|pid| !current.contains_key(*pid)).copied().collect();
        for pid in dead {
            if let Some(info) = known.get(&pid) {
                trace!(pid, name = %info.name, "process exited");
                let event = ProcEvent::from_proc(info, ProcEventKind::Exited, None);
                let _ = tx.send(event).await;
            }
            known.remove(&pid);
        }
        for (pid, info) in current { known.insert(pid, info); }
    }
}

pub fn snapshot_all() -> Result<HashMap<u32, ProcInfo>> {
    #[cfg(target_os = "linux")]
    {
        snapshot_linux()
    }
    #[cfg(windows)]
    {
        snapshot_windows()
    }
    #[cfg(all(not(target_os = "linux"), not(windows)))]
    {
        snapshot_fallback()
    }
}

#[cfg(target_os = "linux")]
fn snapshot_linux() -> Result<HashMap<u32, ProcInfo>> {
    let mut map = HashMap::new();
    for entry in fs::read_dir("/proc")? {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p, None => continue,
        };
        if let Some(info) = read_proc_info(pid) { map.insert(pid, info); }
    }
    Ok(map)
}

#[cfg(windows)]
fn snapshot_windows() -> Result<HashMap<u32, ProcInfo>> {
    if let Ok(map) = snapshot_windows_wmic() {
        if !map.is_empty() {
            return Ok(map);
        }
    }
    snapshot_windows_tasklist()
}

#[cfg(windows)]
fn snapshot_windows_wmic() -> Result<HashMap<u32, ProcInfo>> {
    let output = std::process::Command::new("wmic")
        .args(["process", "get", "ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine", "/FORMAT:LIST"])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("wmic failed");
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut map = HashMap::new();
    let mut name = String::new();
    let mut cmdline = String::new();
    let mut exe = String::new();
    let mut pid = 0u32;
    let mut ppid = 0u32;
    let flush = |map: &mut HashMap<u32, ProcInfo>, name: &str, cmdline: &str, exe: &str, pid: u32, ppid: u32| {
        if pid == 0 || name.is_empty() { return; }
        let cmd_vec = if cmdline.is_empty() { vec![name.to_string()] }
            else { cmdline.split_whitespace().map(|s| s.to_string()).collect() };
        map.insert(pid, ProcInfo {
            pid,
            ppid,
            name: name.to_string(),
            cmdline: cmd_vec,
            exe: if exe.is_empty() { Some(name.to_string()) } else { Some(exe.to_string()) },
            cwd: None,
            uid: 1000,
            gid: 1000,
            start_time: 0,
        });
    };
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            flush(&mut map, &name, &cmdline, &exe, pid, ppid);
            name.clear(); cmdline.clear(); exe.clear(); pid = 0; ppid = 0;
            continue;
        }
        if let Some(v) = line.strip_prefix("CommandLine=") { cmdline = v.trim().to_string(); }
        else if let Some(v) = line.strip_prefix("ExecutablePath=") { exe = v.trim().to_string(); }
        else if let Some(v) = line.strip_prefix("Name=") { name = v.trim().to_string(); }
        else if let Some(v) = line.strip_prefix("ParentProcessId=") { ppid = v.trim().parse().unwrap_or(0); }
        else if let Some(v) = line.strip_prefix("ProcessId=") { pid = v.trim().parse().unwrap_or(0); }
    }
    flush(&mut map, &name, &cmdline, &exe, pid, ppid);
    Ok(map)
}

#[cfg(windows)]
fn snapshot_windows_tasklist() -> Result<HashMap<u32, ProcInfo>> {
    let mut map = HashMap::new();
    if let Ok(output) = std::process::Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let fields: Vec<&str> = line.split("\",\"").collect();
            if fields.len() >= 2 {
                let name = fields[0].trim_matches('"').to_string();
                let pid_str = fields[1].trim_matches('"').replace(',', "");
                if let Ok(pid) = pid_str.parse::<u32>() {
                    if pid == 0 { continue; }
                    map.insert(pid, ProcInfo {
                        pid,
                        ppid: 0,
                        name: name.clone(),
                        cmdline: vec![name.clone()],
                        exe: Some(name),
                        cwd: None,
                        uid: 1000,
                        gid: 1000,
                        start_time: 0,
                    });
                }
            }
        }
    }
    Ok(map)
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn snapshot_fallback() -> Result<HashMap<u32, ProcInfo>> {
    Ok(HashMap::new())
}

#[cfg(target_os = "linux")]
fn read_proc_info(pid: u32) -> Option<ProcInfo> {
    let base = format!("/proc/{}", pid);
    let status_raw = fs::read_to_string(format!("{}/status", base)).ok()?;
    let (name, ppid, uid, gid) = parse_status(&status_raw)?;
    let cmdline_raw = fs::read(format!("{}/cmdline", base)).ok()?;
    let cmdline = parse_cmdline(&cmdline_raw);
    let exe = fs::read_link(format!("{}/exe", base)).ok().map(|p| p.to_string_lossy().into_owned());
    let cwd = fs::read_link(format!("{}/cwd", base)).ok().map(|p| p.to_string_lossy().into_owned());
    let start_time = read_start_time(pid).unwrap_or(0);
    Some(ProcInfo { pid, ppid, name, cmdline, exe, cwd, uid, gid, start_time })
}

#[cfg(target_os = "linux")]
fn parse_status(raw: &str) -> Option<(String, u32, u32, u32)> {
    let (mut name, mut ppid, mut uid, mut gid) = (String::new(), 0u32, 0u32, 0u32);
    for line in raw.lines() {
        if      let Some(r) = line.strip_prefix("Name:\t") { name = r.trim().into(); }
        else if let Some(r) = line.strip_prefix("PPid:\t") { ppid = r.trim().parse().unwrap_or(0); }
        else if let Some(r) = line.strip_prefix("Uid:\t")  { uid  = r.split_whitespace().next()?.parse().unwrap_or(0); }
        else if let Some(r) = line.strip_prefix("Gid:\t")  { gid  = r.split_whitespace().next()?.parse().unwrap_or(0); }
    }
    if name.is_empty() { return None; }
    Some((name, ppid, uid, gid))
}

#[cfg(target_os = "linux")]
fn parse_cmdline(raw: &[u8]) -> Vec<String> {
    raw.split(|&b| b == 0).filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned()).collect()
}

#[cfg(target_os = "linux")]
fn read_start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let after_comm = stat.rfind(')')?;
    stat[after_comm + 2..].split_whitespace().nth(19)?.parse().ok()
}
