import express, { Request, Response } from "express";
import { createServer as createViteServer } from "vite";
import http from "http";
import net from "net";
import path from "path";
import fs from "fs";
import os from "os";
import crypto from "crypto";
import { execSync } from "child_process";
import {
  VIRUS_SIGNATURES,
  calculateShannonEntropy,
  toBufferFromArg,
  detectFileFormat,
  scanBytesWithEngine,
  scanProcessForMalware,
  evaluateProcessRules,
  evaluateCommandDryRun,
  shouldPromoteToIncident,
} from "./server-security";

const APP_VERSION = "1.2.0";
const ENGINE_VERSION = "4.6.0-LINUX";

const app = express();
const server = http.createServer(app);
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json({ limit: "25mb" }));

// -------------------------------------------------------------
// Live System Directories & Persistent Storage Paths
// -------------------------------------------------------------
function resolveDataDir(): string {
  const candidates = [
    process.env.AEGIS_DATA_DIR,
    process.platform === "win32"
      ? path.join(process.env.LOCALAPPDATA || os.tmpdir(), "Aegis-Guard", "data")
      : path.join(os.tmpdir(), "aegis_guard_data"),
    path.join(os.homedir(), ".local", "share", "aegis-guard"),
  ].filter(Boolean) as string[];

  for (const candidate of candidates) {
    try {
      if (!fs.existsSync(candidate)) fs.mkdirSync(candidate, { recursive: true });
      fs.accessSync(candidate, fs.constants.W_OK);
      return candidate;
    } catch {}
  }
  return path.join(os.tmpdir(), `aegis_guard_${process.getuid ? process.getuid() : process.pid}`);
}

const DATA_DIR = resolveDataDir();
const QUARANTINE_DIR = path.join(DATA_DIR, "quarantine");
const SANDBOX_DIR = path.join(DATA_DIR, "sandbox");
const LEGACY_SAMPLES_DIR = path.join(DATA_DIR, "samples");
const AUDIT_FILE = path.join(DATA_DIR, "audit_chain.json");
const INCIDENTS_FILE = path.join(DATA_DIR, "incidents.json");
const WHITELIST_FILE = path.join(DATA_DIR, "trusted_apps.json");
const MALWARE_RESULTS_FILE = path.join(DATA_DIR, "malware_results.json");
const AUTO_PRUNE_FILE = path.join(DATA_DIR, "auto_prune_config.json");
const NET_CONFIG_FILE = path.join(DATA_DIR, "net_defense_config.json");
const SYSTEM_SETTINGS_FILE = path.join(DATA_DIR, "system_settings.json");

for (const dir of [DATA_DIR, QUARANTINE_DIR, SANDBOX_DIR]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
try {
  if (fs.existsSync(LEGACY_SAMPLES_DIR) && fs.readdirSync(LEGACY_SAMPLES_DIR).length === 0) {
    fs.rmdirSync(LEGACY_SAMPLES_DIR);
  }
} catch {}

// -------------------------------------------------------------
// Real Threat Intel Feed Loader (from crates/threat-intel/src/bundled_feed.json)
// -------------------------------------------------------------
interface ThreatIntelEntry {
  ioc: string;
  kind: string;
  feed: string;
  threat_type: string;
  confidence: number;
  added_ts?: number;
}

let threatIntelFeed: ThreatIntelEntry[] = [];
function loadThreatIntelFeed() {
  const feedPath = path.resolve(process.cwd(), "crates/threat-intel/src/bundled_feed.json");
  try {
    if (fs.existsSync(feedPath)) {
      threatIntelFeed = JSON.parse(fs.readFileSync(feedPath, "utf8"));
    }
  } catch (err) {
    console.warn("Could not load bundled_feed.json:", err);
  }
}
loadThreatIntelFeed();

// -------------------------------------------------------------
// SSE Real-time Event Broadcaster
// -------------------------------------------------------------
const sseClients = new Set<Response>();

function broadcastSse(event: string, payload: any) {
  const data = JSON.stringify({ event, payload });
  for (const client of sseClients) {
    try {
      client.write(`event: ${event}\ndata: ${data}\n\n`);
    } catch {
      sseClients.delete(client);
    }
  }
}

app.get("/api/events", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();
  sseClients.add(res);

  req.on("close", () => {
    sseClients.delete(res);
  });
});

// -------------------------------------------------------------
// Persistent JSON Helpers
// -------------------------------------------------------------
function readJson<T>(filePath: string, fallback: T): T {
  try {
    if (fs.existsSync(filePath)) {
      return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
    }
  } catch {}
  return fallback;
}

function writeJson(filePath: string, data: any) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  } catch (err) {
    console.warn(`Failed writing ${filePath}:`, err);
  }
}

// -------------------------------------------------------------
// Real Cryptographic Tamper-Evident Audit Log (SHA-256)
// -------------------------------------------------------------
interface RealAuditEntry {
  id: string;
  action: string;
  pid: number;
  process: string;
  incident_id: string | null;
  note: string;
  status: string;
  outcome: string | null;
  ts_before: number;
  ts_after: number | null;
  prev_digest: string;
  digest: string;
}

function loadAuditLog(): RealAuditEntry[] {
  const existing = readJson<RealAuditEntry[]>(AUDIT_FILE, []);
  if (existing.length > 0) return existing;

  const ts = Date.now();
  const prev = "0000000000000000000000000000000000000000000000000000000000000000";
  const digest = crypto.createHash("sha256").update(`${prev}:KERNEL_ARM:${process.pid}:aegis-engine:${ts}`).digest("hex");
  const init: RealAuditEntry[] = [
    {
      id: `audit-${ts}`,
      action: "KERNEL_ARM",
      pid: process.pid,
      process: "aegis-engine",
      incident_id: null,
      note: "Aegis-Guard live Linux /proc & socket inspection engine initialized",
      status: "success",
      outcome: "Real-time kernel /proc watcher, /proc/net socket sniffer, and fs.watch canary monitor armed.",
      ts_before: ts,
      ts_after: Date.now(),
      prev_digest: prev,
      digest,
    },
  ];
  writeJson(AUDIT_FILE, init);
  return init;
}

function recordAuditAction(
  action: string,
  pid: number,
  processName: string,
  note: string,
  incidentId?: string | null,
  status = "success",
  outcome?: string
): RealAuditEntry {
  const log = loadAuditLog();
  const prev = log[log.length - 1];
  const prev_digest = prev ? prev.digest : "0000000000000000000000000000000000000000000000000000000000000000";

  const ts_before = Date.now();
  const rawData = `${prev_digest}:${action}:${pid}:${processName}:${ts_before}`;
  const digest = crypto.createHash("sha256").update(rawData).digest("hex");

  const entry: RealAuditEntry = {
    id: `audit-${ts_before}-${Math.random().toString(36).slice(2, 6)}`,
    action,
    pid,
    process: processName,
    incident_id: incidentId || null,
    note,
    status,
    outcome: outcome || `Defense action ${action} verified & appended to SHA-256 audit chain.`,
    ts_before,
    ts_after: Date.now(),
    prev_digest,
    digest,
  };

  log.push(entry);
  writeJson(AUDIT_FILE, log);
  broadcastSse("audit-entry", entry);
  return entry;
}

// -------------------------------------------------------------
// Live Stores (Backed by Real System Monitoring & Disk Persistence)
// -------------------------------------------------------------
const incidentsStore: any[] = readJson<any[]>(INCIDENTS_FILE, []);
const telemetryStore: any[] = [];
const debugLogStore: any[] = [];
const dnsQueriesStore: any[] = [];
const networkAttacksStore: any[] = [];
const malwareResultsStore: any[] = readJson<any[]>(MALWARE_RESULTS_FILE, []);
let trustedAppsStore: any[] = readJson<any[]>(WHITELIST_FILE, []);

let netDefenseConfig = readJson<any>(NET_CONFIG_FILE, {
  ids_enabled: true,
  auto_drop_attackers: true,
  auto_block_c2: true,
  sniffing_detection_active: true,
  anti_port_scan_filter: true,
  port_scan_threshold: 20,
  syn_flood_protection: true,
  dns_tunneling_guard: true,
  capture_interface: "eth0 / lo (Linux /proc/net)",
  blocked_ip_list: [] as string[],
});

let autoPruneConfig = readJson<any>(AUTO_PRUNE_FILE, {
  enabled: true,
  retention_days: 14,
  max_debug_entries: 100,
  clean_temp_files: true,
  clean_sandbox_artifacts: true,
  clean_pcap_buffers: true,
  interval_hours: 6,
});

let systemSettings = readJson<{
  process_inspection_enabled: boolean;
  active_kill_enabled: boolean;
  net_admin_enabled: boolean;
  tamper_proof_audit: boolean;
  auto_update_enabled: boolean;
  realtime_av_enabled: boolean;
}>(SYSTEM_SETTINGS_FILE, {
  process_inspection_enabled: true,
  active_kill_enabled: true,
  net_admin_enabled: true,
  tamper_proof_audit: true,
  auto_update_enabled: true,
  realtime_av_enabled: true,
});

let autoUpdateEnabled = systemSettings.auto_update_enabled;
let autoRemediationEnabled = false;
let lastPrunedTs: number | null = null;
let filesScannedCount = malwareResultsStore.length;
let threatsBlockedCount = incidentsStore.length;

function pushTelemetry(ev: any) {
  telemetryStore.unshift(ev);
  if (telemetryStore.length > 300) telemetryStore.length = 300;
  broadcastSse("telemetry-event", ev);
}

function pushDebug(entry: any) {
  debugLogStore.unshift(entry);
  if (debugLogStore.length > 300) debugLogStore.length = 300;
  broadcastSse("debug-entry", entry);
}

function pushIncident(inc: any) {
  incidentsStore.unshift(inc);
  if (incidentsStore.length > 500) incidentsStore.length = 500;
  threatsBlockedCount++;
  writeJson(INCIDENTS_FILE, incidentsStore);
  broadcastSse("anomaly", inc);
}

function pushDnsQuery(q: any) {
  // Avoid duplicate spamming within short window
  const recent = dnsQueriesStore[0];
  if (recent && recent.query === q.query && recent.process_name === q.process_name && Date.now() - Number(recent.ts) < 5000) {
    return;
  }
  dnsQueriesStore.unshift(q);
  if (dnsQueriesStore.length > 200) dnsQueriesStore.length = 200;
}

// -------------------------------------------------------------
// Live Kernel /proc Process Inspector, System Metrics & Socket Mapper
// -------------------------------------------------------------
interface ProcessRaw {
  pid: number;
  ppid: number;
  uid: number;
  gid: number;
  name: string;
  cmdline: string[];
  exe: string | null;
  cwd: string | null;
  start_time: number;
  state: string;
  state_label: string;
  cpu_ticks: number;
  cpu_pct: number;
  mem_rss_kb: number;
  mem_pct: number;
  threads: number;
  fd_count: number;
  io_read_bytes: number;
  io_write_bytes: number;
}

interface SystemMetrics {
  cpu_pct: number;
  mem_total_mb: number;
  mem_used_mb: number;
  mem_available_mb: number;
  mem_pct: number;
  load_1m: number;
  load_5m: number;
  load_15m: number;
  total_procs: number;
  total_threads: number;
  state_counts: {
    running: number;
    sleeping: number;
    disk_wait: number;
    zombie: number;
    stopped: number;
    idle: number;
  };
  ts: number;
}

const STATE_LABELS: Record<string, string> = {
  R: "Running",
  S: "Sleeping",
  D: "Disk Wait",
  Z: "Zombie",
  T: "Stopped",
  t: "Traced",
  I: "Idle",
};

let prevTotalCpuTicks = 0;
let prevIdleCpuTicks = 0;
const prevProcCpuTicks = new Map<number, number>();
let latestSystemMetrics: SystemMetrics = {
  cpu_pct: 0,
  mem_total_mb: 0,
  mem_used_mb: 0,
  mem_available_mb: 0,
  mem_pct: 0,
  load_1m: 0,
  load_5m: 0,
  load_15m: 0,
  total_procs: 0,
  total_threads: 0,
  state_counts: { running: 0, sleeping: 0, disk_wait: 0, zombie: 0, stopped: 0, idle: 0 },
  ts: Date.now(),
};

function readHostCpuMemLoad(): {
  totalTicks: number;
  cpuDelta: number;
  sysCpuPct: number;
  memTotalKb: number;
  memAvailableKb: number;
  load_1m: number;
  load_5m: number;
  load_15m: number;
} {
  let totalTicks = 0;
  let idleTicks = 0;
  try {
    const statLine = fs.readFileSync("/proc/stat", "utf8").split("\n")[0] || "";
    const nums = statLine.trim().split(/\s+/).slice(1).map((n) => parseInt(n, 10) || 0);
    if (nums.length >= 4) {
      totalTicks = nums.reduce((a, b) => a + b, 0);
      idleTicks = (nums[3] || 0) + (nums[4] || 0);
    }
  } catch {}

  const cpuDelta = prevTotalCpuTicks > 0 ? Math.max(1, totalTicks - prevTotalCpuTicks) : 1;
  const idleDelta = prevIdleCpuTicks > 0 ? Math.max(0, idleTicks - prevIdleCpuTicks) : 0;
  const sysCpuPct =
    prevTotalCpuTicks > 0
      ? parseFloat(Math.max(0, Math.min(100, ((cpuDelta - idleDelta) / cpuDelta) * 100)).toFixed(1))
      : 0;
  prevTotalCpuTicks = totalTicks;
  prevIdleCpuTicks = idleTicks;

  let memTotalKb = Math.round(os.totalmem() / 1024);
  let memAvailableKb = Math.round(os.freemem() / 1024);
  try {
    const meminfo = fs.readFileSync("/proc/meminfo", "utf8");
    for (const line of meminfo.split("\n")) {
      if (line.startsWith("MemTotal:")) memTotalKb = parseInt(line.replace(/\D+/g, ""), 10) || memTotalKb;
      else if (line.startsWith("MemAvailable:")) memAvailableKb = parseInt(line.replace(/\D+/g, ""), 10) || memAvailableKb;
    }
  } catch {}

  let load_1m = 0;
  let load_5m = 0;
  let load_15m = 0;
  try {
    const parts = fs.readFileSync("/proc/loadavg", "utf8").trim().split(/\s+/);
    load_1m = parseFloat(parts[0]) || 0;
    load_5m = parseFloat(parts[1]) || 0;
    load_15m = parseFloat(parts[2]) || 0;
  } catch {}

  return { totalTicks, cpuDelta, sysCpuPct, memTotalKb, memAvailableKb, load_1m, load_5m, load_15m };
}

function isWhitelistedProcess(p: ProcessRaw): { trusted: boolean; reason?: string } {
  const exeLower = (p.exe || "").toLowerCase();
  const nameLower = p.name.toLowerCase();
  for (const appEntry of trustedAppsStore) {
    const tPath = (appEntry.path || "").toLowerCase();
    const tName = (appEntry.name || "").toLowerCase();
    if ((tPath && exeLower && exeLower === tPath) || (tName && nameLower === tName)) {
      return { trusted: true, reason: `User Safeguard Whitelist: ${appEntry.name || appEntry.path}` };
    }
  }
  return { trusted: false };
}

function parseLinuxProcesses(): { procs: ProcessRaw[]; inodeToProc: Map<string, ProcessRaw>; metrics: SystemMetrics } {
  const procs: ProcessRaw[] = [];
  const inodeToProc = new Map<string, ProcessRaw>();
  const host = readHostCpuMemLoad();

  const stateCounts = { running: 0, sleeping: 0, disk_wait: 0, zombie: 0, stopped: 0, idle: 0 };
  let totalThreads = 0;

  try {
    const entries = fs.readdirSync("/proc");
    for (const entry of entries) {
      if (!/^\d+$/.test(entry)) continue;
      const pid = parseInt(entry, 10);
      try {
        let ppid = 0;
        let uid = 0;
        let gid = 0;
        let name = `proc-${pid}`;
        let state = "S";
        let mem_rss_kb = 0;
        let threads = 1;
        let start_time = Date.now();
        let cpu_ticks = 0;

        const statusPath = `/proc/${pid}/status`;
        if (fs.existsSync(statusPath)) {
          const statusTxt = fs.readFileSync(statusPath, "utf8");
          for (const line of statusTxt.split("\n")) {
            if (line.startsWith("Name:")) name = line.substring(5).trim();
            else if (line.startsWith("PPid:")) ppid = parseInt(line.substring(5).trim(), 10) || 0;
            else if (line.startsWith("Uid:")) uid = parseInt(line.substring(4).trim().split(/\s+/)[0], 10) || 0;
            else if (line.startsWith("Gid:")) gid = parseInt(line.substring(4).trim().split(/\s+/)[0], 10) || 0;
            else if (line.startsWith("State:")) state = line.substring(6).trim().charAt(0) || "S";
            else if (line.startsWith("VmRSS:")) mem_rss_kb = parseInt(line.substring(6).trim().split(/\s+/)[0], 10) || 0;
            else if (line.startsWith("Threads:")) threads = parseInt(line.substring(8).trim(), 10) || 1;
          }
        }

        // Read utime + stime ticks from /proc/[pid]/stat for real CPU%
        try {
          const statRaw = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
          const closeIdx = statRaw.lastIndexOf(")");
          if (closeIdx > 0) {
            const fields = statRaw.slice(closeIdx + 2).trim().split(/\s+/);
            if (!state && fields[0]) state = fields[0].charAt(0);
            const utime = parseInt(fields[11] || "0", 10) || 0;
            const stime = parseInt(fields[12] || "0", 10) || 0;
            cpu_ticks = utime + stime;
          }
        } catch {}

        try {
          const statInfo = fs.statSync(`/proc/${pid}`);
          start_time = statInfo.ctimeMs || statInfo.mtimeMs || Date.now();
        } catch {}

        let io_read_bytes = 0;
        let io_write_bytes = 0;
        try {
          const ioTxt = fs.readFileSync(`/proc/${pid}/io`, "utf8");
          for (const line of ioTxt.split("\n")) {
            if (line.startsWith("read_bytes:")) io_read_bytes = parseInt(line.slice(11).trim(), 10) || 0;
            else if (line.startsWith("write_bytes:")) io_write_bytes = parseInt(line.slice(12).trim(), 10) || 0;
          }
        } catch {}

        const prevTicks = prevProcCpuTicks.get(pid);
        const procDelta = prevTicks !== undefined ? Math.max(0, cpu_ticks - prevTicks) : 0;
        prevProcCpuTicks.set(pid, cpu_ticks);
        const cpu_pct =
          prevTicks !== undefined && host.cpuDelta > 0
            ? parseFloat(Math.min(100, (procDelta / host.cpuDelta) * 100).toFixed(1))
            : 0;
        const mem_pct = host.memTotalKb > 0 ? parseFloat(((mem_rss_kb / host.memTotalKb) * 100).toFixed(2)) : 0;

        let cmdline: string[] = [];
        const cmdPath = `/proc/${pid}/cmdline`;
        if (fs.existsSync(cmdPath)) {
          cmdline = fs.readFileSync(cmdPath).toString().split("\0").filter(Boolean);
        }
        if (cmdline.length === 0) cmdline = [name];

        let exe: string | null = null;
        try {
          exe = fs.readlinkSync(`/proc/${pid}/exe`);
        } catch {}

        let cwd: string | null = null;
        try {
          cwd = fs.readlinkSync(`/proc/${pid}/cwd`);
        } catch {}

        let fd_count = 0;
        const sockInodes: string[] = [];
        try {
          const fds = fs.readdirSync(`/proc/${pid}/fd`);
          fd_count = fds.length;
          for (const fd of fds) {
            try {
              const link = fs.readlinkSync(`/proc/${pid}/fd/${fd}`);
              if (link.startsWith("socket:[") && link.endsWith("]")) {
                sockInodes.push(link.slice(8, -1));
              }
            } catch {}
          }
        } catch {}

        const state_label = STATE_LABELS[state] || `State(${state})`;
        totalThreads += threads;
        if (state === "R") stateCounts.running++;
        else if (state === "S") stateCounts.sleeping++;
        else if (state === "D") stateCounts.disk_wait++;
        else if (state === "Z") stateCounts.zombie++;
        else if (state === "T" || state === "t") stateCounts.stopped++;
        else stateCounts.idle++;

        const procObj: ProcessRaw = {
          pid,
          ppid,
          uid,
          gid,
          name,
          cmdline,
          exe,
          cwd,
          start_time,
          state,
          state_label,
          cpu_ticks,
          cpu_pct,
          mem_rss_kb,
          mem_pct,
          threads,
          fd_count,
          io_read_bytes,
          io_write_bytes,
        };
        procs.push(procObj);
        for (const inode of sockInodes) {
          inodeToProc.set(inode, procObj);
        }
      } catch {
        // Process exited concurrently
      }
    }
  } catch (err) {
    console.error("Failed to read /proc:", err);
  }

  // Clean up exited PIDs from prevProcCpuTicks
  const liveSet = new Set(procs.map((p) => p.pid));
  for (const oldPid of prevProcCpuTicks.keys()) {
    if (!liveSet.has(oldPid)) prevProcCpuTicks.delete(oldPid);
  }

  const memTotalMb = Math.round(host.memTotalKb / 1024);
  const memAvailMb = Math.round(host.memAvailableKb / 1024);
  const memUsedMb = Math.max(0, memTotalMb - memAvailMb);
  const memPct = memTotalMb > 0 ? parseFloat(((memUsedMb / memTotalMb) * 100).toFixed(1)) : 0;

  const metrics: SystemMetrics = {
    cpu_pct: host.sysCpuPct,
    mem_total_mb: memTotalMb,
    mem_used_mb: memUsedMb,
    mem_available_mb: memAvailMb,
    mem_pct: memPct,
    load_1m: host.load_1m,
    load_5m: host.load_5m,
    load_15m: host.load_15m,
    total_procs: procs.length,
    total_threads: totalThreads,
    state_counts: stateCounts,
    ts: Date.now(),
  };
  latestSystemMetrics = metrics;

  return { procs, inodeToProc, metrics };
}

// Process evaluation rules are provided by ./server-security.ts (anti-false-positive calibrated).

function buildProcessTree(procs: ProcessRaw[]): any[] {
  const procByPid = new Map<number, ProcessRaw>();
  for (const p of procs) procByPid.set(p.pid, p);

  const map = new Map<number, any>();
  for (const p of procs) {
    let anomaly = evaluateProcessRules(p, procByPid);
    if (anomaly) {
      const wl = isWhitelistedProcess(p);
      if (wl.trusted) {
        anomaly = null;
      }
    }

    map.set(p.pid, {
      id: `proc-${p.pid}`,
      pid: p.pid,
      ppid: p.ppid,
      uid: p.uid,
      gid: p.gid,
      name: p.name,
      state: p.state,
      state_label: p.state_label,
      cpu_pct: p.cpu_pct,
      mem_rss_kb: p.mem_rss_kb,
      mem_pct: p.mem_pct,
      threads: p.threads,
      fd_count: p.fd_count,
      io_read_bytes: p.io_read_bytes,
      io_write_bytes: p.io_write_bytes,
      cmdline: p.cmdline,
      exe: p.exe,
      cwd: p.cwd,
      start_time: p.start_time,
      ts: p.start_time,
      flagged: !!anomaly,
      children: [],
      anomaly,
    });
  }

  const roots: any[] = [];
  for (const node of map.values()) {
    if (map.has(node.ppid) && node.ppid !== node.pid) {
      map.get(node.ppid).children.push(node);
    } else {
      roots.push(node);
    }
  }
  return roots.sort((a, b) => a.pid - b.pid);
}

// -------------------------------------------------------------
// Live Network Interfaces (/proc/net/dev), ARP (/proc/net/arp) & Sockets
// -------------------------------------------------------------
function readProcNetDev(): {
  total_tx_bytes: number;
  total_rx_bytes: number;
  interfaces: Array<{ iface: string; rx_bytes: number; rx_packets: number; tx_bytes: number; tx_packets: number }>;
} {
  const interfaces: Array<{ iface: string; rx_bytes: number; rx_packets: number; tx_bytes: number; tx_packets: number }> = [];
  let total_rx_bytes = 0;
  let total_tx_bytes = 0;
  try {
    const raw = fs.readFileSync("/proc/net/dev", "utf8");
    for (const line of raw.split("\n").slice(2)) {
      const colonIdx = line.indexOf(":");
      if (colonIdx < 0) continue;
      const iface = line.slice(0, colonIdx).trim();
      const cols = line.slice(colonIdx + 1).trim().split(/\s+/).map((n) => parseInt(n, 10) || 0);
      if (cols.length >= 10) {
        const rx_bytes = cols[0];
        const rx_packets = cols[1];
        const tx_bytes = cols[8];
        const tx_packets = cols[9];
        total_rx_bytes += rx_bytes;
        total_tx_bytes += tx_bytes;
        interfaces.push({ iface, rx_bytes, rx_packets, tx_bytes, tx_packets });
      }
    }
  } catch {}
  return { total_tx_bytes, total_rx_bytes, interfaces };
}

function readProcNetArp(): Array<{ ip: string; hw_addr: string; device: string; flags: string }> {
  const entries: Array<{ ip: string; hw_addr: string; device: string; flags: string }> = [];
  try {
    if (!fs.existsSync("/proc/net/arp")) return entries;
    const raw = fs.readFileSync("/proc/net/arp", "utf8");
    for (const line of raw.split("\n").slice(1)) {
      const cols = line.trim().split(/\s+/);
      if (cols.length >= 6 && /^\d+\./.test(cols[0])) {
        entries.push({ ip: cols[0], flags: cols[2], hw_addr: cols[3], device: cols[5] });
      }
    }
  } catch {}
  return entries;
}

function hexToIpV4(hex: string): string {
  if (hex.length === 8) {
    const b1 = parseInt(hex.substring(6, 8), 16);
    const b2 = parseInt(hex.substring(4, 6), 16);
    const b3 = parseInt(hex.substring(2, 4), 16);
    const b4 = parseInt(hex.substring(0, 2), 16);
    return `${b1}.${b2}.${b3}.${b4}`;
  }
  return hex;
}

function hexToIpV6(hex: string): string {
  if (hex === "00000000000000000000000000000000") return "::";
  if (hex === "00000000000000000000000001000000") return "::1";
  if (hex.startsWith("0000000000000000FFFF0000") || hex.startsWith("0000000000000000ffff0000")) {
    return hexToIpV4(hex.substring(24));
  }
  const parts: string[] = [];
  for (let i = 0; i < 32; i += 8) {
    const word = hex.substring(i, i + 8);
    parts.push(`${word.substring(6, 8)}${word.substring(4, 6)}:${word.substring(2, 4)}${word.substring(0, 2)}`);
  }
  return parts.join(":");
}

const TCP_STATES: Record<string, string> = {
  "01": "ESTABLISHED",
  "02": "SYN_SENT",
  "03": "SYN_RECV",
  "04": "FIN_WAIT1",
  "05": "FIN_WAIT2",
  "06": "TIME_WAIT",
  "07": "CLOSE",
  "08": "CLOSE_WAIT",
  "09": "LAST_ACK",
  "0A": "LISTEN",
  "0B": "CLOSING",
};

function parseNetworkConnections(inodeToProc: Map<string, ProcessRaw>): any[] {
  const conns: any[] = [];
  const blockedSet = new Set<string>(netDefenseConfig.blocked_ip_list || []);
  const files = [
    { path: "/proc/net/tcp", proto: "tcp", v6: false },
    { path: "/proc/net/tcp6", proto: "tcp6", v6: true },
    { path: "/proc/net/udp", proto: "udp", v6: false },
    { path: "/proc/net/udp6", proto: "udp6", v6: true },
  ];

  for (const { path: netPath, proto, v6 } of files) {
    if (!fs.existsSync(netPath)) continue;
    try {
      const content = fs.readFileSync(netPath, "utf8");
      const lines = content.split("\n").slice(1);
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 10) continue;

        const [localHex, localPortHex] = parts[1].split(":");
        const [remHex, remPortHex] = parts[2].split(":");
        const stateCode = parts[3];
        const txRxQueues = (parts[4] || "00000000:00000000").split(":");
        const txQueueBytes = parseInt(txRxQueues[0] || "0", 16) || 0;
        const rxQueueBytes = parseInt(txRxQueues[1] || "0", 16) || 0;
        const inode = parts[9];

        const localIp = v6 ? hexToIpV6(localHex) : hexToIpV4(localHex);
        const localPort = parseInt(localPortHex, 16) || 0;
        const remoteIp = v6 ? hexToIpV6(remHex) : hexToIpV4(remHex);
        const remotePort = parseInt(remPortHex, 16) || 0;
        const stateName = TCP_STATES[stateCode] || (proto.startsWith("udp") ? "OPEN" : "UNKNOWN");

        const owner = inodeToProc.get(inode);
        const pid = owner ? owner.pid : 0;
        const procName = owner ? owner.name : localPort === PORT ? "aegis-server" : "kernel";

        const isBlocked = blockedSet.has(remoteIp);
        const iocHit = threatIntelFeed.find((e) => e.kind === "ip" && e.ioc === remoteIp);
        const isSuspiciousPort = [4444, 6666, 1337, 31337, 9001].includes(remotePort) && remoteIp !== "0.0.0.0" && remoteIp !== "127.0.0.1";

        let threat = "safe";
        let threat_flag: string | null = null;
        let threat_reason: string | undefined = undefined;

        if (isBlocked) {
          threat = "c2_blocked";
          threat_flag = "BLOCKED_IP";
          threat_reason = `Blocked remote endpoint (${remoteIp})`;
        } else if (iocHit) {
          threat = "c2_detected";
          threat_flag = `THREAT_INTEL_${iocHit.threat_type.toUpperCase()}`;
          threat_reason = `Threat Intel Match: ${iocHit.threat_type} (${iocHit.confidence}% confidence)`;
        } else if (isSuspiciousPort) {
          threat = "c2_detected";
          threat_flag = "C2_NONSTANDARD_PORT";
          threat_reason = `Outbound socket on suspicious port ${remotePort}`;
        }

        conns.push({
          id: `net-${proto}-${inode}-${localPort}-${remotePort}`,
          pid,
          process: procName,
          process_name: procName,
          protocol: proto,
          proto,
          local_ip: localIp,
          local_addr: localIp,
          local_port: localPort,
          remote_ip: remoteIp,
          remote_addr: remoteIp,
          remote_port: remotePort,
          state: stateName,
          direction: stateName === "LISTEN" || localPort === PORT ? "inbound" : "outbound",
          bytes_tx: txQueueBytes,
          bytes_rx: rxQueueBytes,
          is_blocked: isBlocked,
          threat,
          threat_flag,
          threat_reason,
        });
      }
    } catch (err) {
      console.warn(`Could not read ${netPath}:`, err);
    }
  }

  return conns;
}

// -------------------------------------------------------------
// Real Continuous Kernel & Socket Background Monitor (1.5s live)
// -------------------------------------------------------------
let knownPids = new Map<number, ProcessRaw>();
let knownSocketKeys = new Set<string>();
const alertedIncidentsKey = new Set<string>();
let seenDuplicateArpKey = "";
const procExeAvCache = new Map<string, { mtimeMs: number; verdict: ReturnType<typeof scanProcessForMalware> }>();

function readBoundedExeBytes(exePath: string | null): Buffer | null {
  if (!exePath || exePath.endsWith(" (deleted)")) return null;
  try {
    const st = fs.statSync(exePath);
    if (!st.isFile() || st.size === 0) return null;
    const cap = Math.min(st.size, 2 * 1024 * 1024);
    const fd = fs.openSync(exePath, "r");
    const buf = Buffer.alloc(cap);
    fs.readSync(fd, buf, 0, cap, 0);
    fs.closeSync(fd);
    return buf;
  } catch {
    return null;
  }
}

function inspectProcWithLiveAv(p: ProcessRaw): void {
  if (!systemSettings.realtime_av_enabled) return;
  let mtimeMs = 0;
  let exeBuf: Buffer | null = null;
  const cacheKey = p.exe ? `${p.exe}` : "";
  if (cacheKey) {
    try {
      const st = fs.statSync(cacheKey);
      mtimeMs = st.mtimeMs;
      const cached = procExeAvCache.get(cacheKey);
      if (cached && cached.mtimeMs === mtimeMs && !cached.verdict) {
        // Unchanged clean executable already verified; still check cmdline cheaply
        const cmdOnly = scanProcessForMalware(p, null, trustedAppsStore, threatIntelFeed);
        if (!cmdOnly) return;
        promoteProcessAvHit(p, cmdOnly);
        return;
      }
      exeBuf = readBoundedExeBytes(cacheKey);
    } catch {
      exeBuf = null;
    }
  }

  const verdict = scanProcessForMalware(p, exeBuf, trustedAppsStore, threatIntelFeed);
  if (cacheKey && mtimeMs > 0) {
    procExeAvCache.set(cacheKey, { mtimeMs, verdict });
    if (procExeAvCache.size > 400) {
      const firstKey = procExeAvCache.keys().next().value;
      if (firstKey) procExeAvCache.delete(firstKey);
    }
  }
  if (verdict) promoteProcessAvHit(p, verdict);
}

function promoteProcessAvHit(p: ProcessRaw, av: NonNullable<ReturnType<typeof scanProcessForMalware>>) {
  const key = `av:${p.pid}:${av.rule}`;
  if (alertedIncidentsKey.has(key)) return;
  alertedIncidentsKey.add(key);
  threatsBlockedCount++;

  pushIncident({
    id: `inc-procav-${p.pid}-${Date.now()}`,
    kind: "malware_detection",
    severity: av.severity,
    risk_score: av.infected ? 96 : 75,
    pid: p.pid,
    ppid: p.ppid,
    process: p.name,
    cmdline: p.cmdline,
    exe_path: p.exe,
    rule: av.rule,
    confidence: "high",
    reason: `Real-time AV detected ${av.threat_name} (${av.family}) in live process '${p.name}' (PID ${p.pid}).`,
    ancestors: [],
    ts: new Date().toISOString(),
    resolved: false,
    digest: av.sha256,
    virus_name: av.threat_name,
    virus_family: av.family,
    mitre_tactic: "Execution",
    mitre_technique: av.mitre_technique,
    flags: av.indicators,
    factors: [{ name: av.method, impact: av.infected ? 95 : 75, desc: av.rule }],
    movement_steps: [{ ts: Date.now(), event: "Live /proc AV Scan", detail: `${av.threat_name} matched ${av.rule}`, delta: 95 }],
  });

  malwareResultsStore.unshift({
    id: `res-proc-${p.pid}-${Date.now()}`,
    target_path: p.exe || p.cmdline.join(" ") || p.name,
    file_path: p.exe || p.name,
    is_infected: av.infected,
    threat_name: av.threat_name,
    malware_name: av.threat_name,
    rule_matched: av.rule,
    detection_method: av.method,
    family: av.family,
    category: av.family,
    confidence: "HIGH",
    sha256: av.sha256,
    indicators: av.indicators,
    is_quarantined: false,
    quarantined: false,
    remediation_status: av.infected ? "UNREMEDIATED" : "REVIEW_REQUIRED",
    scanned_at: Date.now(),
    status: av.infected ? "infected" : "suspicious",
  });
  if (malwareResultsStore.length > 250) malwareResultsStore.length = 250;
  writeJson(MALWARE_RESULTS_FILE, malwareResultsStore);
}

function runKernelPoll(isInitial = false) {
  const { procs, inodeToProc, metrics } = parseLinuxProcesses();
  const procByPid = new Map<number, ProcessRaw>();
  for (const p of procs) procByPid.set(p.pid, p);

  if (isInitial) {
    for (const p of procs) {
      knownPids.set(p.pid, p);
      if (systemSettings.process_inspection_enabled) {
        inspectProcWithLiveAv(p);
      }
      const anomaly = systemSettings.process_inspection_enabled ? evaluateProcessRules(p, procByPid) : null;
      if (anomaly) {
        const wl = isWhitelistedProcess(p);
        if (wl.trusted) {
          pushDebug({
            id: `dbg-init-${p.pid}`,
            process: p.name,
            rule: anomaly.rule,
            note: anomaly.reason,
            suppression_reason: wl.reason,
            category: "WHITELIST_SUPPRESSED",
            ts: Date.now(),
            pid: p.pid,
            ppid: p.ppid,
            cmdline: p.cmdline,
            original_score: anomaly.risk_score,
            adjusted_score: 0,
          });
        } else if (shouldPromoteToIncident(anomaly)) {
          const key = `${p.pid}:${anomaly.rule}`;
          if (!alertedIncidentsKey.has(key)) {
            alertedIncidentsKey.add(key);
            pushIncident({
              id: `inc-${p.pid}-${Date.now()}`,
              kind: "live_kernel_rule",
              severity: anomaly.severity,
              risk_score: anomaly.risk_score,
              pid: p.pid,
              ppid: p.ppid,
              process: p.name,
              cmdline: p.cmdline,
              exe_path: p.exe,
              rule: anomaly.rule,
              confidence: anomaly.confidence,
              reason: anomaly.reason,
              ancestors: anomaly.ancestors,
              ts: new Date().toISOString(),
              resolved: false,
              digest: crypto.createHash("sha256").update(`${p.pid}:${anomaly.rule}`).digest("hex"),
              mitre_tactic: anomaly.mitre_tactic,
              mitre_technique: anomaly.mitre_technique,
              virus_name: anomaly.virus_name,
              virus_family: anomaly.virus_family,
              flags: anomaly.flags,
              factors: anomaly.factors,
              movement_steps: [{ ts: Date.now(), event: "Kernel /proc Probe", detail: anomaly.reason, delta: anomaly.risk_score }],
            });
          }
        }
      }
    }

    pushTelemetry({
      id: `tel-boot-${Date.now()}`,
      ts: Date.now(),
      event_type: "KERNEL_INIT",
      process: "aegis-engine",
      parent: "systemd",
      pid: process.pid,
      ppid: process.ppid,
      uid: process.getuid ? process.getuid() : 0,
      cmdline: process.argv,
      exe_path: process.execPath,
      score: 0,
      verdict: "clean",
      severity: "informational",
      explanation: `Live Linux /proc monitor attached to ${procs.length} processes (${metrics.total_threads} threads). RAM: ${metrics.mem_used_mb}MB / ${metrics.mem_total_mb}MB.`,
      detail: `Active /proc & /proc/net monitor (${os.platform()} ${os.release()})`,
    });

    for (const p of procs.slice(0, 12)) {
      const parent = procByPid.get(p.ppid);
      pushTelemetry({
        id: `tel-proc-${p.pid}`,
        ts: Date.now(),
        event_type: "PROCESS_ACTIVE",
        process: p.name,
        parent: parent ? parent.name : `ppid:${p.ppid}`,
        pid: p.pid,
        ppid: p.ppid,
        uid: p.uid,
        cmdline: p.cmdline,
        exe_path: p.exe,
        score: 0,
        verdict: "clean",
        severity: "informational",
        detail: `[${p.state_label}] ${(p.mem_rss_kb / 1024).toFixed(1)} MB RSS • ${p.threads} thr • ${p.cmdline.join(" ")}`,
        explanation: `Active Linux process PID ${p.pid} in state ${p.state_label} (${p.state})`,
      });
    }

    try {
      if (fs.existsSync("/etc/resolv.conf")) {
        const resolv = fs.readFileSync("/etc/resolv.conf", "utf8");
        for (const line of resolv.split("\n")) {
          const m = line.match(/^nameserver\s+(\S+)/);
          if (m) {
            pushDnsQuery({
              id: `dns-ns-${m[1]}`,
              domain: `resolver:${m[1]}`,
              query: `System DNS Nameserver (${m[1]})`,
              query_type: "NS",
              qtype: "NS",
              client_pid: 1,
              process: "systemd-resolved",
              process_name: "systemd-resolved",
              status: "ACTIVE",
              verdict: "safe",
              resolved_ip: m[1],
              threat_score: 0,
              ts: Date.now(),
            });
          }
        }
      }
    } catch {}
  } else {
    // Diff processes: NEW spawns, STATE CHANGES (Running/Sleeping/Zombie/Stopped), and EXITS
    for (const p of procs) {
      const prev = knownPids.get(p.pid);
      if (!prev) {
        const parent = procByPid.get(p.ppid);
        if (systemSettings.process_inspection_enabled) {
          inspectProcWithLiveAv(p);
        }
        let anomaly = systemSettings.process_inspection_enabled ? evaluateProcessRules(p, procByPid) : null;
        const wl = isWhitelistedProcess(p);

        if (anomaly && wl.trusted) {
          pushDebug({
            id: `dbg-${p.pid}-${Date.now()}`,
            process: p.name,
            rule: anomaly.rule,
            note: anomaly.reason,
            suppression_reason: wl.reason,
            category: "WHITELIST_SUPPRESSED",
            ts: Date.now(),
            pid: p.pid,
            ppid: p.ppid,
            cmdline: p.cmdline,
            original_score: anomaly.risk_score,
            adjusted_score: 0,
          });
          pushTelemetry({
            id: `tel-sup-${p.pid}-${Date.now()}`,
            ts: Date.now(),
            event_type: "EXEC_SPAWN",
            process: p.name,
            parent: parent ? parent.name : `ppid:${p.ppid}`,
            pid: p.pid,
            ppid: p.ppid,
            uid: p.uid,
            cmdline: p.cmdline,
            exe_path: p.exe,
            score: 0,
            verdict: "suppressed",
            severity: "informational",
            suppression_reason: wl.reason,
            detail: `[${p.state_label}] ${p.cmdline.join(" ")}`,
          });
          anomaly = null;
        } else if (anomaly) {
          const isAlertTier = anomaly.risk_score >= 70;
          pushTelemetry({
            id: `tel-anom-${p.pid}-${Date.now()}`,
            ts: Date.now(),
            event_type: "EXEC_ANOMALY",
            process: p.name,
            parent: parent ? parent.name : `ppid:${p.ppid}`,
            pid: p.pid,
            ppid: p.ppid,
            uid: p.uid,
            cmdline: p.cmdline,
            exe_path: p.exe,
            score: anomaly.risk_score,
            verdict: isAlertTier ? "alert" : "monitored",
            severity: anomaly.severity,
            rule: anomaly.rule,
            mitre_tactic: anomaly.mitre_tactic,
            mitre_technique: anomaly.mitre_technique,
            mitre: anomaly.mitre_technique,
            flags: anomaly.flags,
            factors: anomaly.factors,
            explanation: anomaly.reason,
            detail: `[${p.state_label}] ${anomaly.rule}: ${p.cmdline.join(" ")}`,
          });

          if (isAlertTier) {
            broadcastSse("proc-event", {
              id: `proc-${p.pid}`,
              kind: "anomaly",
              pid: p.pid,
              ppid: p.ppid,
              uid: p.uid,
              gid: p.gid,
              name: p.name,
              state: p.state,
              state_label: p.state_label,
              cpu_pct: p.cpu_pct,
              mem_rss_kb: p.mem_rss_kb,
              mem_pct: p.mem_pct,
              threads: p.threads,
              cmdline: p.cmdline,
              exe: p.exe,
              cwd: p.cwd,
              start_time: p.start_time,
              ts: Date.now(),
              flagged: true,
              anomaly,
              children: [],
            });
          }

          const key = `${p.pid}:${anomaly.rule}`;
          if (shouldPromoteToIncident(anomaly) && !alertedIncidentsKey.has(key)) {
            alertedIncidentsKey.add(key);
            pushIncident({
              id: `inc-${p.pid}-${Date.now()}`,
              kind: "live_kernel_rule",
              severity: anomaly.severity,
              risk_score: anomaly.risk_score,
              pid: p.pid,
              ppid: p.ppid,
              process: p.name,
              cmdline: p.cmdline,
              exe_path: p.exe,
              rule: anomaly.rule,
              confidence: anomaly.confidence,
              reason: anomaly.reason,
              ancestors: anomaly.ancestors,
              ts: new Date().toISOString(),
              resolved: false,
              digest: crypto.createHash("sha256").update(`${p.pid}:${anomaly.rule}`).digest("hex"),
              mitre_tactic: anomaly.mitre_tactic,
              mitre_technique: anomaly.mitre_technique,
              virus_name: anomaly.virus_name,
              virus_family: anomaly.virus_family,
              flags: anomaly.flags,
              factors: anomaly.factors,
              movement_steps: [{ ts: Date.now(), event: "Live Process Spawn", detail: anomaly.reason, delta: anomaly.risk_score }],
            });
          }
        } else {
          pushTelemetry({
            id: `tel-spawn-${p.pid}-${Date.now()}`,
            ts: Date.now(),
            event_type: "EXEC_SPAWN",
            process: p.name,
            parent: parent ? parent.name : `ppid:${p.ppid}`,
            pid: p.pid,
            ppid: p.ppid,
            uid: p.uid,
            cmdline: p.cmdline,
            exe_path: p.exe,
            score: 0,
            verdict: "clean",
            severity: "informational",
            detail: `[${p.state_label}] CPU ${p.cpu_pct}% • ${p.cmdline.join(" ")}`,
            explanation: `Spawned: ${p.name} (PID ${p.pid}, state: ${p.state_label})`,
          });

          broadcastSse("proc-event", {
            id: `proc-${p.pid}`,
            kind: "spawned",
            pid: p.pid,
            ppid: p.ppid,
            uid: p.uid,
            gid: p.gid,
            name: p.name,
            state: p.state,
            state_label: p.state_label,
            cpu_pct: p.cpu_pct,
            mem_rss_kb: p.mem_rss_kb,
            mem_pct: p.mem_pct,
            threads: p.threads,
            cmdline: p.cmdline,
            exe: p.exe,
            cwd: p.cwd,
            start_time: p.start_time,
            ts: Date.now(),
            flagged: false,
            anomaly: null,
            children: [],
          });
        }
      } else if (prev.state !== p.state && (p.state === "Z" || p.state === "T" || prev.state === "Z")) {
        // Real kernel state transition into/out of Zombie or Stopped
        const isAlertState = p.state === "Z" || p.state === "T";
        pushTelemetry({
          id: `tel-state-${p.pid}-${Date.now()}`,
          ts: Date.now(),
          event_type: "STATE_CHANGE",
          process: p.name,
          parent: `ppid:${p.ppid}`,
          pid: p.pid,
          ppid: p.ppid,
          uid: p.uid,
          cmdline: p.cmdline,
          score: isAlertState ? 38 : 5,
          verdict: isAlertState ? "monitored" : "clean",
          severity: isAlertState ? "medium" : "informational",
          detail: `State transition ${prev.state_label} (${prev.state}) -> ${p.state_label} (${p.state})`,
          explanation: `Process ${p.name} changed kernel execution state in /proc/${p.pid}/status.`,
        });
      }
    }

    for (const [oldPid, oldProc] of knownPids.entries()) {
      if (!procByPid.has(oldPid)) {
        pushTelemetry({
          id: `tel-exit-${oldPid}-${Date.now()}`,
          ts: Date.now(),
          event_type: "EXEC_EXIT",
          process: oldProc.name,
          parent: `ppid:${oldProc.ppid}`,
          pid: oldPid,
          ppid: oldProc.ppid,
          uid: oldProc.uid,
          cmdline: oldProc.cmdline,
          score: 0,
          verdict: "clean",
          severity: "informational",
          detail: `Exited [${oldProc.state_label}]: ${oldProc.cmdline.join(" ")}`,
        });

        broadcastSse("proc-event", {
          id: `proc-${oldPid}`,
          kind: "exited",
          pid: oldPid,
          ppid: oldProc.ppid,
          uid: oldProc.uid,
          gid: oldProc.gid,
          name: oldProc.name,
          cmdline: oldProc.cmdline,
          exe: oldProc.exe,
          cwd: oldProc.cwd,
          start_time: oldProc.start_time,
          ts: Date.now(),
          flagged: false,
          anomaly: null,
          children: [],
        });
      }
    }
    knownPids = procByPid;
  }

  // Diff live network sockets & real ARP table
  const conns = parseNetworkConnections(inodeToProc);
  const netDev = readProcNetDev();
  const arpEntries = readProcNetArp();

  // Real duplicate MAC detection from /proc/net/arp (zero fake data)
  const macToIps = new Map<string, string[]>();
  for (const a of arpEntries) {
    if (a.hw_addr === "00:00:00:00:00:00") continue;
    const list = macToIps.get(a.hw_addr) || [];
    list.push(a.ip);
    macToIps.set(a.hw_addr, list);
  }
  for (const [mac, ips] of macToIps.entries()) {
    if (ips.length > 1) {
      const k = `${mac}:${ips.join(",")}`;
      if (k !== seenDuplicateArpKey) {
        seenDuplicateArpKey = k;
        const atk = {
          id: `atk-arp-${Date.now()}`,
          attack_type: "ARP_DUPLICATE_MAC",
          rule: "NET-ARP-001",
          severity: "high",
          source_ip: ips[0],
          source_port: 0,
          target_ip: ips.join(" / "),
          target_port: 0,
          protocol: "ARP",
          process: "kernel-arp",
          pid: 0,
          blocked: false,
          details: `Duplicate MAC ${mac} mapped to multiple IPs in /proc/net/arp: ${ips.join(", ")}`,
          packet_summary: `/proc/net/arp collision: ${mac}`,
          signature_hit: "REAL_ARP_TABLE_COLLISION",
          defense_action: "MONITORED (P2 HIGH)",
          ts: Date.now(),
        };
        networkAttacksStore.unshift(atk);
        broadcastSse("net-attack", atk);
      }
    }
  }

  const nextSocketKeys = new Set<string>();
  for (const c of conns) {
    const key = `${c.protocol}:${c.local_ip}:${c.local_port}->${c.remote_ip}:${c.remote_port}:${c.state}`;
    nextSocketKeys.add(key);

    if (!isInitial && !knownSocketKeys.has(key)) {
      if (c.remote_port === 53 && c.remote_ip !== "0.0.0.0") {
        pushDnsQuery({
          id: `dns-sock-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          domain: `${c.remote_ip}:53 (UDP DNS Lookup)`,
          query: `UDP:53 -> ${c.remote_ip}`,
          query_type: c.protocol.toUpperCase(),
          qtype: c.protocol.toUpperCase(),
          client_pid: c.pid,
          process: c.process_name,
          process_name: c.process_name,
          status: c.threat === "safe" ? "ALLOWED" : "FLAGGED",
          verdict: c.threat === "safe" ? "safe" : "suspicious",
          resolved_ip: c.remote_ip,
          threat_score: c.threat === "safe" ? 0 : 75,
          ts: Date.now(),
        });
      }

      if (c.threat === "c2_detected") {
        const isIntelMatch = String(c.threat_flag || "").startsWith("THREAT_INTEL");
        const atk = {
          id: `atk-live-${Date.now()}`,
          attack_type: c.threat_flag || "SUSPICIOUS_SOCKET",
          rule: isIntelMatch ? "NET-IOC-001" : "NET-001",
          severity: isIntelMatch ? "critical" : "high",
          source_ip: c.remote_ip,
          source_port: c.remote_port,
          target_ip: c.local_ip,
          target_port: c.local_port,
          protocol: c.protocol.toUpperCase(),
          process: c.process_name,
          pid: c.pid,
          blocked: netDefenseConfig.auto_block_c2,
          details: c.threat_reason || `Suspicious connection detected to ${c.remote_ip}:${c.remote_port}`,
          packet_summary: `${c.process_name} -> ${c.remote_ip}:${c.remote_port}`,
          signature_hit: c.threat_flag || "NET_RULE_HIT",
          defense_action: netDefenseConfig.auto_block_c2 ? "AUTO-BLOCKED" : "FLAGGED",
          ts: Date.now(),
        };
        networkAttacksStore.unshift(atk);
        broadcastSse("net-attack", atk);
        pushTelemetry({
          id: `tel-c2-${Date.now()}`,
          ts: Date.now(),
          event_type: "NET_C2_DETECTED",
          process: c.process_name,
          parent: "kernel-net",
          pid: c.pid,
          score: isIntelMatch ? 94 : 76,
          verdict: "alert",
          severity: isIntelMatch ? "critical" : "high",
          rule: atk.rule,
          mitre: "T1071",
          detail: `${c.process_name} -> ${c.remote_ip}:${c.remote_port} (${c.threat_flag || "C2"})`,
          explanation: c.threat_reason || `Suspicious connection detected to ${c.remote_ip}:${c.remote_port}`,
        });
      }
    }
  }
  knownSocketKeys = nextSocketKeys;

  if (!isInitial && sseClients.size > 0) {
    const tree = buildProcessTree(procs);
    broadcastSse("proc-snapshot", { tree, metrics });
    broadcastSse("net-update", { connections: conns, netDev });
    const pktSnap = buildLocalPacketInspectionSnapshot(conns, arpEntries);
    broadcastSse("packet-inspection", pktSnap);
  } else {
    buildLocalPacketInspectionSnapshot(conns, arpEntries);
  }
}

// -------------------------------------------------------------
// Go High-Performance Packet Inspection Bridge (127.0.0.1:50053)
// + Live Linux /proc/net/snmp L3/L4 Inspection Engine
// -------------------------------------------------------------
const PACKET_INSPECTOR_CONFIG_FILE = path.join(DATA_DIR, "packet_inspector_config.json");
let packetInspectorConfig = readJson<any>(PACKET_INSPECTOR_CONFIG_FILE, {
  deep_inspection: true,
  syn_flood_guard: true,
  port_scan_guard: true,
  dns_tunnel_guard: true,
  arp_spoof_guard: true,
  syn_flood_threshold: 25,
  port_scan_threshold: 60,
});

let lastSnmpSegs = 0;
let lastSnmpTimeMs = 0;
let packetFlowsAnalyzedCount = 0;
let packetBytesInspectedCount = 0;
const packetFindingsStore: any[] = [];
const portSweepTracker = new Map<number, Map<string, number>>();
let latestPacketInspectionSnapshot: any = null;

function readProcNetSnmp(nowMs: number) {
  const snmp: any = {
    ip_in_receives: 0,
    ip_out_requests: 0,
    ip_in_hdr_errors: 0,
    tcp_active_opens: 0,
    tcp_passive_opens: 0,
    tcp_curr_estab: 0,
    tcp_in_segs: 0,
    tcp_out_segs: 0,
    tcp_retrans_segs: 0,
    tcp_attempt_fails: 0,
    udp_in_datagrams: 0,
    udp_out_datagrams: 0,
    udp_in_errors: 0,
    icmp_in_msgs: 0,
    icmp_out_msgs: 0,
    segments_per_sec: 0,
    retrans_rate_pct: 0,
  };
  try {
    const raw = fs.readFileSync("/proc/net/snmp", "utf8");
    let headers: string[] | null = null;
    for (const line of raw.split("\n")) {
      const idx = line.indexOf(":");
      if (idx < 0) continue;
      const proto = line.slice(0, idx).trim();
      const fields = line.slice(idx + 1).trim().split(/\s+/);
      if (!headers) {
        headers = fields;
        continue;
      }
      const kv: Record<string, number> = {};
      for (let i = 0; i < headers.length && i < fields.length; i++) {
        kv[headers[i]] = parseInt(fields[i], 10) || 0;
      }
      if (proto === "Ip") {
        snmp.ip_in_receives = kv["InReceives"] || 0;
        snmp.ip_out_requests = kv["OutRequests"] || 0;
        snmp.ip_in_hdr_errors = kv["InHdrErrors"] || 0;
      } else if (proto === "Tcp") {
        snmp.tcp_active_opens = kv["ActiveOpens"] || 0;
        snmp.tcp_passive_opens = kv["PassiveOpens"] || 0;
        snmp.tcp_curr_estab = kv["CurrEstab"] || 0;
        snmp.tcp_in_segs = kv["InSegs"] || 0;
        snmp.tcp_out_segs = kv["OutSegs"] || 0;
        snmp.tcp_retrans_segs = kv["RetransSegs"] || 0;
        snmp.tcp_attempt_fails = kv["AttemptFails"] || 0;
      } else if (proto === "Udp") {
        snmp.udp_in_datagrams = kv["InDatagrams"] || 0;
        snmp.udp_out_datagrams = kv["OutDatagrams"] || 0;
        snmp.udp_in_errors = kv["InErrors"] || 0;
      } else if (proto === "Icmp") {
        snmp.icmp_in_msgs = kv["InMsgs"] || 0;
        snmp.icmp_out_msgs = kv["OutMsgs"] || 0;
      }
      headers = null;
    }
  } catch {}

  const totalSegs = snmp.tcp_in_segs + snmp.tcp_out_segs;
  if (lastSnmpTimeMs > 0) {
    const dt = (nowMs - lastSnmpTimeMs) / 1000;
    if (dt > 0.05 && totalSegs >= lastSnmpSegs) {
      snmp.segments_per_sec = Math.round(((totalSegs - lastSnmpSegs) / dt) * 10) / 10;
    }
  }
  if (snmp.tcp_out_segs > 0) {
    snmp.retrans_rate_pct = Math.round((snmp.tcp_retrans_segs / snmp.tcp_out_segs) * 10000) / 100;
  }
  lastSnmpSegs = totalSegs;
  lastSnmpTimeMs = nowMs;
  return snmp;
}

function buildLocalPacketInspectionSnapshot(conns: any[], arpEntries: Array<{ ip: string; hw_addr: string; device: string; flags: string }>) {
  const nowMs = Date.now();
  const snmp = readProcNetSnmp(nowMs);
  const synRecv = conns.filter((c) => c.state === "SYN_RECV").length;
  const cfg = packetInspectorConfig;

  if (cfg.deep_inspection) {
    packetFlowsAnalyzedCount += conns.length;
    for (const c of conns) {
      packetBytesInspectedCount += (c.bytes_tx || 0) + (c.bytes_rx || 0);
      const rem = c.remote_ip || "";
      if (!rem || rem === "0.0.0.0" || rem === "127.0.0.1" || rem === "::" || rem === "::1") continue;

      if (c.threat === "c2_detected") {
        const dupId = `pkt-c2-${c.pid}-${c.remote_ip}-${c.remote_port}`;
        if (!packetFindingsStore.some((f) => f.id.startsWith(dupId) && nowMs - f.ts_ms < 15000)) {
          packetFindingsStore.unshift({
            id: `${dupId}-${nowMs}`,
            category: "C2_CHANNEL_HIT",
            severity: "high",
            rule: "PKT-C2-001",
            pid: c.pid,
            process: c.process_name,
            protocol: String(c.protocol || "TCP").toUpperCase(),
            src_endpoint: `${c.local_ip}:${c.local_port}`,
            dst_endpoint: `${c.remote_ip}:${c.remote_port}`,
            state: c.state,
            summary: c.threat_reason || `Suspicious remote flow to ${c.remote_ip}:${c.remote_port}`,
            signature_hit: c.threat_flag || "L4_C2_PORT",
            action_taken: "ALERTED",
            ts_ms: nowMs,
          });
        }
      }

      if (cfg.port_scan_guard && c.pid > 0 && c.remote_port !== 80 && c.remote_port !== 443 && c.remote_port !== 53) {
        let hist = portSweepTracker.get(c.pid);
        if (!hist) {
          hist = new Map<string, number>();
          portSweepTracker.set(c.pid, hist);
        }
        hist.set(`${c.remote_ip}:${c.remote_port}`, nowMs);
        for (const [k, t] of hist.entries()) {
          if (nowMs - t > 15000) hist.delete(k);
        }
        if (hist.size >= (cfg.port_scan_threshold || 60)) {
          const dupScan = `pkt-scan-${c.pid}`;
          if (!packetFindingsStore.some((f) => f.id.startsWith(dupScan) && nowMs - f.ts_ms < 15000)) {
            packetFindingsStore.unshift({
              id: `${dupScan}-${nowMs}`,
              category: "PORT_SWEEP_DETECTED",
              severity: "high",
              rule: "PKT-SCAN-001",
              pid: c.pid,
              process: c.process_name,
              protocol: String(c.protocol || "TCP").toUpperCase(),
              src_endpoint: `${c.local_ip}:${c.local_port}`,
              dst_endpoint: `${c.remote_ip}:${c.remote_port}`,
              state: c.state,
              summary: `Process '${c.process_name}' contacted ${hist.size} non-web endpoints within 15s`,
              signature_hit: "HORIZONTAL_PORT_SWEEP",
              action_taken: "MONITORED",
              ts_ms: nowMs,
            });
          }
        }
      }
    }

    if (cfg.syn_flood_guard && synRecv >= (cfg.syn_flood_threshold || 25)) {
      if (!packetFindingsStore.some((f) => f.rule === "PKT-SYN-001" && nowMs - f.ts_ms < 10000)) {
        packetFindingsStore.unshift({
          id: `pkt-syn-${nowMs}`,
          category: "SYN_FLOOD_WARNING",
          severity: "high",
          rule: "PKT-SYN-001",
          pid: 0,
          process: "kernel-tcp-stack",
          protocol: "TCP",
          src_endpoint: "multiple",
          dst_endpoint: "host:syn-backlog",
          state: "SYN_RECV",
          summary: `${synRecv} half-open SYN_RECV sockets exceed threshold (${cfg.syn_flood_threshold})`,
          signature_hit: "L4_HALF_OPEN_SYN_BACKLOG",
          action_taken: "RATE_MONITORED",
          ts_ms: nowMs,
        });
      }
    }

    if (packetFindingsStore.length > 100) packetFindingsStore.length = 100;
  }

  const packetsInspected = snmp.tcp_in_segs + snmp.tcp_out_segs + snmp.udp_in_datagrams + snmp.udp_out_datagrams;
  latestPacketInspectionSnapshot = {
    engine_source: "LINUX_PROC_NET_SNMP_ENGINE",
    go_bridge_connected: false,
    snmp_counters: snmp,
    stats: {
      engine_source: "LINUX_PROC_NET_SNMP_ENGINE",
      worker_threads: Math.max(2, os.cpus().length),
      packets_inspected: packetsInspected,
      flows_analyzed: packetFlowsAnalyzedCount,
      anomalies_found: packetFindingsStore.length,
      bytes_inspected: packetBytesInspectedCount,
      active_syn_recv: synRecv,
      last_scan_ts_ms: nowMs,
    },
    config: cfg,
    flow_findings: packetFindingsStore.slice(0, 64),
    arp_table: arpEntries,
  };
  return latestPacketInspectionSnapshot;
}

async function queryGoBridge(action: string, extra: Record<string, any> = {}): Promise<any | null> {
  return new Promise((resolve) => {
    const reqId = `rpc-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const client = net.createConnection({ host: "127.0.0.1", port: 50053 });
    let settled = false;
    let recvBuf = Buffer.alloc(0);

    const finish = (val: any | null) => {
      if (settled) return;
      settled = true;
      try {
        client.destroy();
      } catch {}
      resolve(val);
    };

    client.setTimeout(350);
    client.on("timeout", () => finish(null));
    client.on("error", () => finish(null));

    client.on("connect", () => {
      const payload = Buffer.from(JSON.stringify({ req_id: reqId, action, ...extra }), "utf8");
      const hdr = Buffer.alloc(4);
      hdr.writeUInt32BE(payload.length, 0);
      client.write(Buffer.concat([hdr, payload]));
    });

    client.on("data", (chunk: Buffer) => {
      recvBuf = Buffer.concat([recvBuf, chunk]);
      while (recvBuf.length >= 4) {
        const frameLen = recvBuf.readUInt32BE(0);
        if (frameLen === 0 || frameLen > 2 * 1024 * 1024) {
          finish(null);
          return;
        }
        if (recvBuf.length < 4 + frameLen) break;
        const body = recvBuf.subarray(4, 4 + frameLen);
        recvBuf = recvBuf.subarray(4 + frameLen);
        try {
          const parsed = JSON.parse(body.toString("utf8"));
          if (parsed?.kind === "rpc_response" && (!parsed.req_id || parsed.req_id === reqId)) {
            finish(parsed);
            return;
          }
        } catch {}
      }
    });
  });
}

runKernelPoll(true);
setInterval(() => runKernelPoll(false), 1500);

// -------------------------------------------------------------
// Real Shannon Entropy & Binary-Safe Antivirus Engine
// -------------------------------------------------------------
function scanFileSystemEntropy(targetPath: string, rawContent?: any): any {
  const start = Date.now();
  const results: any[] = [];

  // 1. If uploaded file bytes were provided from browser
  const uploadedBuf = toBufferFromArg(rawContent);
  if (uploadedBuf && uploadedBuf.length > 0) {
    const ent = calculateShannonEntropy(uploadedBuf);
    const fmt = detectFileFormat(uploadedBuf, targetPath || "uploaded_file.bin");
    let risk = "normal";
    let note = `Standard ${fmt.format} byte distribution.`;
    let is_packed = false;
    let is_encrypted = false;

    if (fmt.isBenignCompressed && ent >= 7.0) {
      risk = "normal";
      note = `Verified ${fmt.format} (entropy ${ent}/8.0 expected for lossless compressed format).`;
    } else if (ent >= 7.6 && fmt.isExecutable) {
      risk = "high";
      note = `High Shannon entropy (${ent}/8.0) in ${fmt.format} indicates packed or encrypted executable payload.`;
      is_packed = true;
      is_encrypted = true;
    } else if (ent >= 7.5) {
      risk = "medium";
      note = `High Shannon entropy (${ent}/8.0) in ${fmt.format}.`;
    } else if (ent >= 6.5) {
      risk = "medium";
      note = `Elevated Shannon entropy (${ent}/8.0) in ${fmt.format}.`;
    } else if (ent < 3.2) {
      risk = "low";
      note = `Low Shannon entropy (${ent}/8.0) with sparse/repetitive data.`;
    }

    results.push({
      path: targetPath || "uploaded_file.bin",
      entropy: ent,
      mime_guess: fmt.format,
      size_bytes: uploadedBuf.length,
      risk,
      note,
      is_packed,
      is_encrypted,
    });
  } else {
    // 2. Scan real file or directory on Linux host
    const p = path.resolve(targetPath || "/app/applet");
    function scanDir(dir: string, depth = 0) {
      if (depth > 2 || results.length >= 60) return;
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const e of entries) {
          if (results.length >= 60) break;
          if (e.name === "node_modules" || e.name === ".git" || e.name === "target" || e.name === ".playwright-cli") continue;
          const full = path.join(dir, e.name);
          if (e.isDirectory()) {
            scanDir(full, depth + 1);
          } else if (e.isFile()) {
            try {
              const stat = fs.statSync(full);
              if (stat.size === 0) {
                results.push({
                  path: full,
                  entropy: 0,
                  mime_guess: "inode/empty",
                  size_bytes: 0,
                  risk: "low",
                  note: "Empty 0-byte file.",
                });
                continue;
              }
              const fd = fs.openSync(full, "r");
              const buf = Buffer.alloc(Math.min(stat.size, 65536));
              fs.readSync(fd, buf, 0, buf.length, 0);
              fs.closeSync(fd);

              const ent = calculateShannonEntropy(buf);
              const fmt = detectFileFormat(buf, full);
              let risk = "normal";
              let note = `${fmt.format} uncompressed distribution.`;
              let is_packed = false;
              let is_encrypted = false;

              if (fmt.isBenignCompressed && ent >= 7.0) {
                risk = "normal";
                note = `Verified ${fmt.format} (${ent}/8.0 expected for compressed media/archive).`;
              } else if (ent >= 7.6 && fmt.isExecutable) {
                risk = "high";
                note = `High Shannon entropy (${ent}/8.0) in ${fmt.format} indicates packed binary.`;
                is_packed = true;
                is_encrypted = true;
              } else if (ent >= 6.5) {
                risk = "medium";
                note = `Elevated entropy (${ent}/8.0) in ${fmt.format}.`;
              } else if (ent < 3.2) {
                risk = "low";
                note = "Low entropy with repetitive byte pattern.";
              }

              results.push({
                path: full,
                entropy: ent,
                mime_guess: fmt.format,
                size_bytes: stat.size,
                risk,
                note,
                is_packed,
                is_encrypted,
              });
            } catch {}
          }
        }
      } catch {}
    }

    if (fs.existsSync(p)) {
      const s = fs.statSync(p);
      if (s.isDirectory()) {
        scanDir(p);
      } else {
        const buf = fs.readFileSync(p);
        const ent = calculateShannonEntropy(buf);
        const fmt = detectFileFormat(buf, p);
        const risk =
          fmt.isBenignCompressed && ent >= 7.0
            ? "normal"
            : ent >= 7.6 && fmt.isExecutable
            ? "high"
            : ent >= 6.5
            ? "medium"
            : ent < 3.2
            ? "low"
            : "normal";
        results.push({
          path: p,
          entropy: ent,
          mime_guess: fmt.format,
          size_bytes: s.size,
          risk,
          note: `Real Shannon entropy of ${path.basename(p)} (${fmt.format}): ${ent}/8.0 bits per byte.`,
        });
      }
    } else {
      throw new Error(`Path not found on filesystem: ${p}`);
    }
  }

  const duration_ms = Math.max(1, Date.now() - start);
  const high_risk = results.filter((r) => r.risk === "high").length;
  const medium_risk = results.filter((r) => r.risk === "medium").length;
  const clean = results.filter((r) => r.risk === "normal" || r.risk === "low").length;
  const total_bytes = results.reduce((a, r) => a + r.size_bytes, 0);

  return {
    scanned_count: results.length,
    scanned_files: results.length,
    high_risk_count: high_risk,
    high_risk,
    medium_risk_count: medium_risk,
    clean_count: clean,
    skipped_count: 0,
    total_bytes,
    duration_ms,
    elapsed_ms: duration_ms,
    results,
  };
}

function scanRealBytesForViruses(targetLabel: string, buf: Buffer): any {
  filesScannedCount++;
  return scanBytesWithEngine(targetLabel, buf, trustedAppsStore, threatIntelFeed);
}

// -------------------------------------------------------------
// Real Canary Honeytoken Watcher (fs.watch on real disk files)
// -------------------------------------------------------------
interface RealCanary {
  id: string;
  token: string;
  file_path: string;
  description: string;
  created_ts: number;
  triggered: boolean;
  watcher?: fs.FSWatcher;
}

const activeCanaries = new Map<string, RealCanary>();

function registerCanary(filePath: string, desc: string): any {
  const token = `AEGIS-CANARY-TOKEN-${crypto.randomBytes(4).toString("hex").toUpperCase()}-${Date.now().toString(36).toUpperCase()}`;
  const fullPath = path.resolve(filePath || path.join(DATA_DIR, `canary_${Date.now()}.txt`));

  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(
    fullPath,
    `# AEGIS-GUARD HONEYTOKEN WATCHER\n# DO NOT MODIFY OR EXFILTRATE\nCANARY_TOKEN="${token}"\n# CREATED: ${new Date().toISOString()}\n`
  );

  const id = `canary-${Date.now()}-${Math.random().toString(36).slice(2, 5)}`;
  const canary: RealCanary = {
    id,
    token,
    file_path: fullPath,
    description: desc || "Honeytoken tripwire on live filesystem",
    created_ts: Date.now(),
    triggered: false,
  };

  try {
    const watcher = fs.watch(fullPath, (eventType) => {
      canary.triggered = true;
      const inc = {
        id: `inc-canary-${Date.now()}`,
        kind: "honeytoken_trip",
        severity: "critical",
        risk_score: 99,
        pid: 0,
        ppid: 1,
        process: "honeytoken_tripwire",
        cmdline: ["fs.watch", fullPath],
        exe_path: fullPath,
        rule: "CANARY-001",
        confidence: "high",
        reason: `Honeytoken tripwire fired on live filesystem! File '${fullPath}' experienced '${eventType}' event.`,
        ancestors: [1],
        ts: new Date().toISOString(),
        resolved: false,
        digest: crypto.createHash("sha256").update(token).digest("hex"),
        mitre_tactic: "Credential Access",
        mitre_technique: "Unsecured Credentials (T1552)",
        flags: ["REAL_KERNEL_FS_TRIPWIRE", `FS_EVENT_${eventType.toUpperCase()}`],
        factors: [{ name: "Live Filesystem Tripwire", impact: 90, desc: fullPath }],
        movement_steps: [{ ts: Date.now(), event: "Filesystem Trip", detail: `${eventType} on ${fullPath}`, delta: 90 }],
      };
      pushIncident(inc);
      pushTelemetry({
        id: `tel-canary-${Date.now()}`,
        ts: Date.now(),
        event_type: "CANARY_TRIP",
        process: "fs.watch",
        parent: "kernel-inotify",
        pid: 0,
        score: 99,
        verdict: "alert",
        severity: "critical",
        rule: "CANARY-001",
        mitre: "T1552",
        detail: `Canary file touched: ${fullPath} (${eventType})`,
        explanation: inc.reason,
      });
    });
    canary.watcher = watcher;
  } catch (err) {
    console.warn("Could not attach fs.watch to canary:", err);
  }

  activeCanaries.set(id, canary);
  return {
    id: canary.id,
    token: canary.token,
    file_path: canary.file_path,
    description: canary.description,
    created_ts: canary.created_ts,
    triggered: canary.triggered,
  };
}

// Seed one default canary on disk
registerCanary(path.join(DATA_DIR, "decoy_ssh_vault.key"), "System Decoy SSH Honeytoken");

// -------------------------------------------------------------
// Real Sandbox Directory Containment & Detonation Analyzer
// -------------------------------------------------------------
function listSandboxReportsFromDisk(): any[] {
  const reports: any[] = [];
  try {
    const dirs = fs.readdirSync(SANDBOX_DIR);
    for (const d of dirs) {
      const reportPath = path.join(SANDBOX_DIR, d, "report.json");
      if (fs.existsSync(reportPath)) {
        try {
          reports.push(JSON.parse(fs.readFileSync(reportPath, "utf8")));
        } catch {}
      }
    }
  } catch {}
  return reports.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
}

function inspectRealSandboxTarget(
  samplePathOrName: string,
  isolationType: string,
  networkConfinement: string,
  sampleBytes?: Buffer
): any {
  const jail_id = `jail-${crypto.randomBytes(4).toString("hex")}`;
  const jailDir = path.join(SANDBOX_DIR, jail_id);
  fs.mkdirSync(jailDir, { recursive: true });

  const start = Date.now();
  let buf = sampleBytes;
  const resolvedInput = path.resolve(samplePathOrName);
  let loadedFromDisk = false;
  if (!buf && fs.existsSync(resolvedInput) && fs.statSync(resolvedInput).isFile()) {
    buf = fs.readFileSync(resolvedInput);
    loadedFromDisk = true;
  }
  if (!buf) {
    throw new Error(`Target file not found on disk and no file bytes uploaded: ${samplePathOrName}`);
  }

  let unshareStatus = `${isolationType} (Static + Byte Inspection)`;
  try {
    execSync("which unshare", { stdio: "ignore" });
    unshareStatus = `${isolationType} (unshare available on host)`;
  } catch {}

  const sha256 = crypto.createHash("sha256").update(buf).digest("hex");
  const entropy = calculateShannonEntropy(buf);
  const isolatedCopy = path.join(jailDir, path.basename(samplePathOrName));
  fs.writeFileSync(isolatedCopy, buf);
  fs.chmodSync(isolatedCopy, 0o400);

  const observed: any[] = [];
  const mitreSet = new Set<string>();
  const evasionList: string[] = [];

  // Real ELF header check
  const isElf = buf.length >= 16 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46;
  const is64 = isElf && buf[4] === 2;
  const textSample = buf.slice(0, Math.min(buf.length, 65536)).toString("utf8");
  const isScript = textSample.startsWith("#!");

  observed.push({
    timestamp: new Date().toISOString(),
    category: "StaticHeader",
    operation: isElf ? "ELF_HEADER_PARSE" : isScript ? "SHEBANG_PARSE" : "BYTE_PROFILE",
    target: isolatedCopy,
    risk: entropy > 7.4 ? "high" : "low",
    severity: entropy > 7.4 ? "high" : "low",
    description: isElf
      ? `ELF ${is64 ? "64-bit" : "32-bit"} binary verified (${buf.length} bytes, entropy ${entropy}/8.0).`
      : isScript
      ? `Executable script (${textSample.split("\n")[0].slice(0, 60)}) — entropy ${entropy}/8.0.`
      : `Raw file (${buf.length} bytes, Shannon entropy ${entropy}/8.0).`,
  });

  if (entropy > 7.4) {
    evasionList.push(`High Shannon Entropy (${entropy}/8.0 — possible packing/encryption)`);
    mitreSet.add("T1027: Obfuscated Files or Information");
  }

  // Real IOC extraction from actual file bytes
  const extractedIps = Array.from(new Set(textSample.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])).slice(0, 20);
  const extractedUrls = Array.from(new Set(textSample.match(/https?:\/\/[a-zA-Z0-9._:/?=&%-]+/g) || [])).slice(0, 20);
  const extractedDomains = Array.from(
    new Set(
      extractedUrls
        .map((u) => {
          try {
            return new URL(u).hostname;
          } catch {
            return "";
          }
        })
        .filter(Boolean)
    )
  );

  for (const ip of extractedIps) {
    const intel = threatIntelFeed.find((e) => e.ioc === ip);
    observed.push({
      timestamp: new Date().toISOString(),
      category: "EmbeddedString",
      operation: "STRING_IP_EXTRACT",
      target: ip,
      risk: intel ? "critical" : "medium",
      severity: intel ? "critical" : "medium",
      description: intel ? `Matched Threat Intel feed (${intel.threat_type})` : `Embedded IPv4 literal found in bytes`,
    });
  }

  const avScan = scanRealBytesForViruses(isolatedCopy, buf);
  let riskScore = entropy > 7.4 ? 55 : 15;
  if (avScan.is_infected) {
    riskScore = 95;
    observed.push({
      timestamp: new Date().toISOString(),
      category: "Signature",
      operation: "BYTE_SIGNATURE_HIT",
      target: avScan.rule_matched,
      risk: "critical",
      severity: "critical",
      description: `Matched signature: ${avScan.malware_name} (${avScan.family})`,
    });
  }
  if (extractedIps.some((ip) => threatIntelFeed.some((e) => e.ioc === ip))) {
    riskScore = Math.max(riskScore, 90);
    mitreSet.add("T1071: Application Layer Protocol");
  }

  const threatLevel =
    riskScore >= 90 ? "CRITICAL" : riskScore >= 70 ? "HIGH" : riskScore >= 35 ? "MEDIUM" : "LOW";

  const report = {
    jail_id,
    sample_name: path.basename(samplePathOrName),
    family: avScan.family || (isElf ? "ELF Binary" : isScript ? "Script" : "File"),
    status: "analyzed",
    isolation_type: unshareStatus,
    network_confinement: networkConfinement,
    sha: sha256.slice(0, 16),
    sha256,
    created_at: new Date().toISOString(),
    runtime_ms: Math.max(1, Date.now() - start),
    blueprint: {
      dynamic_risk_rating: riskScore,
      threat_level: threatLevel,
      threat_summary: `Read-only byte & header inspection of '${path.basename(samplePathOrName)}' (${loadedFromDisk ? "loaded from disk" : "uploaded bytes"}, ${buf.length} bytes, entropy ${entropy}/8.0). No unverified behaviors synthesized.`,
      killchain_phase: avScan.is_infected ? "Matched Known Signature" : "Static Inspection",
      evasion_mechanisms: evasionList.length > 0 ? evasionList : ["None observed in static bytes"],
      unpacking_detected: entropy > 7.4,
      remediation_command: `rm -rf ${jailDir}`,
    },
    extracted_iocs: {
      ips: extractedIps,
      domains: extractedDomains,
      dropped_files: [isolatedCopy],
      mutex_or_pipes: [],
    },
    mitre_techniques_observed: Array.from(mitreSet),
    observed_behaviors: observed,
  };

  writeJson(path.join(jailDir, "report.json"), report);
  recordAuditAction("SANDBOX_INSPECT", 0, samplePathOrName, `Inspected real file bytes in read-only jail ${jail_id}`);
  return report;
}

// -------------------------------------------------------------
// IPC Dispatch Route - Live Linux Kernel & Forensics API
// -------------------------------------------------------------
app.post("/api/ipc", async (req: Request, res: Response) => {
  const { cmd, args = {} } = req.body;

  try {
    switch (cmd) {
      case "list_processes": {
        const { procs } = parseLinuxProcesses();
        const tree = buildProcessTree(procs);
        return res.json(tree);
      }

      case "get_system_metrics": {
        return res.json(latestSystemMetrics);
      }

      case "list_network_connections": {
        const { inodeToProc } = parseLinuxProcesses();
        const conns = parseNetworkConnections(inodeToProc);
        return res.json(conns);
      }

      case "get_network_metrics": {
        return res.json({
          ...readProcNetDev(),
          arp: readProcNetArp(),
        });
      }

      case "get_packet_inspection": {
        const goResp = await queryGoBridge("get_inspection_snapshot");
        if (goResp?.ok && goResp.snapshot) {
          return res.json({
            ...goResp.snapshot,
            go_bridge_connected: true,
          });
        }
        if (latestPacketInspectionSnapshot) {
          return res.json(latestPacketInspectionSnapshot);
        }
        const { inodeToProc } = parseLinuxProcesses();
        const conns = parseNetworkConnections(inodeToProc);
        return res.json(buildLocalPacketInspectionSnapshot(conns, readProcNetArp()));
      }

      case "set_packet_inspector_config": {
        const nextCfg = { ...packetInspectorConfig, ...(args.config || args) };
        packetInspectorConfig = nextCfg;
        writeJson(PACKET_INSPECTOR_CONFIG_FILE, packetInspectorConfig);
        await queryGoBridge("set_inspector_config", { config: packetInspectorConfig });
        recordAuditAction("PACKET_INSPECTOR_CONFIG", 0, "packet-inspector", "Updated Go/Linux packet inspection policy");
        const { inodeToProc } = parseLinuxProcesses();
        const conns = parseNetworkConnections(inodeToProc);
        const snap = buildLocalPacketInspectionSnapshot(conns, readProcNetArp());
        broadcastSse("packet-inspection", snap);
        return res.json(packetInspectorConfig);
      }

      case "list_dns_queries": {
        return res.json(dnsQueriesStore);
      }

      case "list_network_attacks": {
        return res.json(networkAttacksStore);
      }

      case "get_network_defense_config": {
        return res.json(netDefenseConfig);
      }

      case "update_network_defense_config": {
        netDefenseConfig = { ...netDefenseConfig, ...(args.config || {}) };
        writeJson(NET_CONFIG_FILE, netDefenseConfig);
        recordAuditAction("NET_CONFIG_UPDATE", 0, "network-ids", "Updated network IDS defense configuration");
        return res.json(netDefenseConfig);
      }

      case "block_remote_ip":
      case "block_ip_address": {
        const ip = args.ip;
        if (ip && !netDefenseConfig.blocked_ip_list.includes(ip)) {
          netDefenseConfig.blocked_ip_list.push(ip);
          writeJson(NET_CONFIG_FILE, netDefenseConfig);
        }
        recordAuditAction("BLOCK_REMOTE_IP", 0, ip, `Null-routed remote IP ${ip} in active firewall blocklist`);
        pushTelemetry({
          id: `tel-block-${Date.now()}`,
          ts: Date.now(),
          event_type: "NET_BLOCK",
          process: "aegis-firewall",
          parent: "aegis-engine",
          pid: process.pid,
          score: 75,
          verdict: "alert",
          severity: "high",
          rule: "NET-BLOCK-001",
          detail: `Remote IP ${ip} added to active blocklist`,
          explanation: `IP ${ip} blocked via Aegis Network Defense.`,
        });
        return res.json(true);
      }

      case "unblock_remote_ip":
      case "unblock_ip_address": {
        const ip = args.ip;
        if (ip) {
          netDefenseConfig.blocked_ip_list = netDefenseConfig.blocked_ip_list.filter((x: string) => x !== ip);
          writeJson(NET_CONFIG_FILE, netDefenseConfig);
        }
        recordAuditAction("UNBLOCK_REMOTE_IP", 0, ip, `Removed ${ip} from firewall blocklist`);
        return res.json(true);
      }

      case "scan_entropy": {
        const scanPath = args.path || args.request?.path || "/app/applet";
        const rawContent = args.content ?? args.request?.content;
        const summary = scanFileSystemEntropy(scanPath, rawContent);
        return res.json(summary);
      }

      case "list_virus_signatures": {
        return res.json(VIRUS_SIGNATURES);
      }

      case "list_malware_results": {
        return res.json(malwareResultsStore);
      }

      case "scan_malware_target": {
        const target = args.path || args.target_path || "/tmp/scan_target";
        const contentBuf = toBufferFromArg(args.content);
        let buf: Buffer;
        if (contentBuf && contentBuf.length > 0) {
          buf = contentBuf;
        } else if (fs.existsSync(path.resolve(target))) {
          const st = fs.statSync(path.resolve(target));
          if (st.isDirectory()) {
            return res.status(400).json({ error: "Target is a directory; use SCAN DIR or specify a file path." });
          }
          if (st.size > 16 * 1024 * 1024) {
            const fd = fs.openSync(path.resolve(target), "r");
            buf = Buffer.alloc(16 * 1024 * 1024);
            fs.readSync(fd, buf, 0, buf.length, 0);
            fs.closeSync(fd);
          } else {
            buf = fs.readFileSync(path.resolve(target));
          }
        } else {
          return res.json({
            id: `res-${Date.now()}`,
            target_path: target,
            file_path: target,
            is_infected: false,
            rule_matched: "FILE_NOT_FOUND",
            detection_method: "Filesystem Lookup",
            confidence: "LOW",
            quarantined: false,
            indicators: [`File does not exist at ${target}`],
            status: "clean",
          });
        }

        const scanned = scanRealBytesForViruses(target, buf);
        malwareResultsStore.unshift(scanned);
        if (malwareResultsStore.length > 250) malwareResultsStore.length = 250;
        writeJson(MALWARE_RESULTS_FILE, malwareResultsStore);

        if (scanned.is_infected) {
          pushIncident({
            id: `inc-av-${Date.now()}`,
            kind: "malware_detection",
            severity: "critical",
            risk_score: 95,
            pid: 0,
            ppid: 1,
            process: path.basename(target),
            cmdline: [target],
            exe_path: target,
            rule: scanned.rule_matched,
            confidence: "high",
            reason: `Antivirus engine detected ${scanned.malware_name} in '${target}'.`,
            ancestors: [],
            ts: new Date().toISOString(),
            resolved: false,
            digest: scanned.sha256,
            virus_name: scanned.malware_name,
            virus_family: scanned.family,
            flags: scanned.indicators,
            factors: [{ name: "Byte Signature Hit", impact: 95, desc: scanned.rule_matched }],
            movement_steps: [{ ts: Date.now(), event: "AV Scan Hit", detail: scanned.rule_matched, delta: 95 }],
          });
        }
        return res.json(scanned);
      }

      case "scan_directory_malware": {
        const dirPath = path.resolve(args.path || DATA_DIR);
        if (!fs.existsSync(dirPath)) {
          return res.status(404).json({ error: `Directory not found: ${dirPath}` });
        }
        const stRoot = fs.statSync(dirPath);
        if (!stRoot.isDirectory()) {
          const singleBuf = fs.readFileSync(dirPath);
          const scanned = scanRealBytesForViruses(dirPath, singleBuf);
          malwareResultsStore.unshift(scanned);
          writeJson(MALWARE_RESULTS_FILE, malwareResultsStore);
          return res.json({
            directory: dirPath,
            files_scanned: 1,
            infected_count: scanned.is_infected ? 1 : 0,
            suspicious_count: scanned.status === "suspicious" ? 1 : 0,
            clean_count: scanned.status === "clean" ? 1 : 0,
            skipped_count: 0,
            duration_ms: 1,
            results: [scanned],
          });
        }

        const startMs = Date.now();
        const dirResults: any[] = [];
        let skipped = 0;
        const walk = (d: string, depth = 0) => {
          if (depth > 3 || dirResults.length >= 60) return;
          try {
            for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
              if (dirResults.length >= 60) break;
              if (
                entry.name === "node_modules" ||
                entry.name === ".git" ||
                entry.name === "target" ||
                entry.name === ".playwright-cli" ||
                entry.name === "quarantine_vault"
              ) {
                continue;
              }
              const full = path.join(d, entry.name);
              if (d === DATA_DIR && entry.name.endsWith(".json")) continue;
              if (entry.isDirectory()) {
                walk(full, depth + 1);
              } else if (entry.isFile()) {
                try {
                  const st = fs.statSync(full);
                  if (st.size === 0 || st.size > 4 * 1024 * 1024) {
                    skipped++;
                    continue;
                  }
                  const buf = fs.readFileSync(full);
                  const scanned = scanRealBytesForViruses(full, buf);
                  dirResults.push(scanned);
                  if (scanned.is_infected) {
                    pushIncident({
                      id: `inc-av-${Date.now()}-${Math.random().toString(36).slice(2, 5)}`,
                      kind: "malware_detection",
                      severity: "critical",
                      risk_score: 95,
                      pid: 0,
                      ppid: 1,
                      process: entry.name,
                      cmdline: [full],
                      exe_path: full,
                      rule: scanned.rule_matched,
                      confidence: "high",
                      reason: `Antivirus directory scan detected ${scanned.malware_name} in '${full}'.`,
                      ancestors: [],
                      ts: new Date().toISOString(),
                      resolved: false,
                      digest: scanned.sha256,
                      virus_name: scanned.malware_name,
                      virus_family: scanned.family,
                      flags: scanned.indicators,
                      factors: [{ name: "Byte Signature Hit", impact: 95, desc: scanned.rule_matched }],
                      movement_steps: [{ ts: Date.now(), event: "Directory AV Scan", detail: scanned.rule_matched, delta: 95 }],
                    });
                  }
                } catch {
                  skipped++;
                }
              }
            }
          } catch {}
        };
        walk(dirPath);

        // Record non-clean hits plus top findings without flooding store
        const hits = dirResults.filter((r) => r.status !== "clean");
        const toStore = hits.length > 0 ? hits : dirResults.slice(0, 5);
        for (const r of toStore.slice().reverse()) {
          malwareResultsStore.unshift(r);
        }
        if (malwareResultsStore.length > 250) malwareResultsStore.length = 250;
        writeJson(MALWARE_RESULTS_FILE, malwareResultsStore);
        recordAuditAction("AV_DIR_SCAN", 0, dirPath, `Scanned ${dirResults.length} files (${hits.length} non-clean)`);

        return res.json({
          directory: dirPath,
          files_scanned: dirResults.length,
          infected_count: dirResults.filter((r) => r.is_infected).length,
          suspicious_count: dirResults.filter((r) => r.status === "suspicious").length,
          clean_count: dirResults.filter((r) => r.status === "clean").length,
          skipped_count: skipped,
          duration_ms: Math.max(1, Date.now() - startMs),
          results: dirResults,
        });
      }

      case "quarantine_malware":
      case "confirm_malware_quarantine": {
        const id = args.id;
        const action = args.action || "quarantine";
        const item = malwareResultsStore.find((m) => m.id === id);
        if (!item) return res.status(404).json({ error: "Scan result not found" });

        if (action === "restore") {
          if (item.quarantine_path && fs.existsSync(item.quarantine_path)) {
            try {
              fs.chmodSync(item.quarantine_path, 0o644);
              fs.copyFileSync(item.quarantine_path, item.file_path);
              fs.unlinkSync(item.quarantine_path);
            } catch {}
          }
          item.quarantined = false;
          item.is_quarantined = false;
          item.remediation_status = "RESTORED";
          writeJson(MALWARE_RESULTS_FILE, malwareResultsStore);
          recordAuditAction("RESTORE_FILE", 0, item.file_path, `Restored file from quarantine vault`);
          return res.json({ status: "restored", message: `Restored ${item.file_path} from quarantine vault.` });
        }

        if (action === "delete") {
          try {
            if (item.quarantine_path && fs.existsSync(item.quarantine_path)) fs.unlinkSync(item.quarantine_path);
            if (item.file_path && fs.existsSync(item.file_path)) fs.unlinkSync(item.file_path);
          } catch {}
          const idx = malwareResultsStore.indexOf(item);
          if (idx >= 0) malwareResultsStore.splice(idx, 1);
          writeJson(MALWARE_RESULTS_FILE, malwareResultsStore);
          recordAuditAction("DELETE_MALWARE", 0, item.file_path, `Permanently shredded infected file`);
          return res.json({ status: "deleted", message: `Permanently deleted ${item.file_path}.` });
        }

        // Quarantine action
        let qPath = "";
        if (item.file_path && fs.existsSync(item.file_path)) {
          qPath = path.join(QUARANTINE_DIR, `${path.basename(item.file_path)}.${Date.now()}.quarantined`);
          fs.copyFileSync(item.file_path, qPath);
          fs.chmodSync(qPath, 0o000);
          try {
            fs.unlinkSync(item.file_path);
          } catch {}
        }
        item.quarantined = true;
        item.is_quarantined = true;
        item.remediation_status = "QUARANTINED_VAULT";
        item.quarantine_path = qPath;
        writeJson(MALWARE_RESULTS_FILE, malwareResultsStore);
        recordAuditAction("QUARANTINE_FILE", 0, item.file_path, `Moved infected sample to isolated vault ${qPath}`);
        return res.json({ status: "quarantined", quarantine_path: qPath, message: `Quarantined ${item.file_path} (chmod 000) in ${qPath}` });
      }

      case "quick_system_av_scan": {
        const startMs = Date.now();
        const scanFindings: any[] = [];
        const { procs } = parseLinuxProcesses();
        let procsScanned = 0;
        let filesScanned = 0;

        for (const p of procs) {
          procsScanned++;
          const exeBuf = readBoundedExeBytes(p.exe);
          const av = scanProcessForMalware(p, exeBuf, trustedAppsStore, threatIntelFeed);
          if (av) {
            promoteProcessAvHit(p, av);
            scanFindings.push({
              target_path: p.exe || p.name,
              status: av.infected ? "infected" : "suspicious",
              malware_name: av.threat_name,
              family: av.family,
              rule_matched: av.rule,
              sha256: av.sha256,
              pid: p.pid,
            });
          }
        }

        const hotDirs = ["/dev/shm", "/var/tmp", DATA_DIR];
        for (const hd of hotDirs) {
          if (!fs.existsSync(hd)) continue;
          try {
            for (const entry of fs.readdirSync(hd, { withFileTypes: true })) {
              if (filesScanned >= 120) break;
              if (!entry.isFile()) continue;
              if (entry.name.endsWith(".json")) continue;
              const full = path.join(hd, entry.name);
              try {
                const st = fs.statSync(full);
                if (st.size === 0 || st.size > 4 * 1024 * 1024) continue;
                const buf = fs.readFileSync(full);
                const scanned = scanRealBytesForViruses(full, buf);
                filesScanned++;
                if (scanned.status !== "clean") {
                  scanFindings.push(scanned);
                  malwareResultsStore.unshift(scanned);
                  if (scanned.is_infected) {
                    promoteProcessAvHit(
                      { pid: 0, ppid: 1, uid: 0, gid: 0, name: entry.name, state: "S", state_label: "File", cpu_pct: 0, mem_rss_kb: 0, mem_pct: 0, threads: 1, cmdline: [full], exe: full, cwd: hd, start_time: Date.now() },
                      {
                        infected: true,
                        suspicious: false,
                        rule: scanned.rule_matched,
                        threat_name: scanned.malware_name || "Malware",
                        family: scanned.family || "Malware",
                        severity: "critical",
                        sha256: scanned.sha256,
                        indicators: scanned.indicators || [],
                        method: scanned.detection_method,
                        mitre_technique: "T1204",
                      }
                    );
                  }
                }
              } catch {}
            }
          } catch {}
        }

        if (malwareResultsStore.length > 250) malwareResultsStore.length = 250;
        writeJson(MALWARE_RESULTS_FILE, malwareResultsStore);
        const durationMs = Math.max(1, Date.now() - startMs);
        recordAuditAction(
          "QUICK_SYSTEM_AV_SCAN",
          process.pid,
          "av-engine",
          `Inspected ${procsScanned} live processes and ${filesScanned} volatile files (${scanFindings.length} finding(s)) in ${durationMs}ms`
        );

        return res.json({
          procs_scanned: procsScanned,
          files_scanned: filesScanned,
          infected_count: scanFindings.filter((f) => f.status === "infected").length,
          suspicious_count: scanFindings.filter((f) => f.status === "suspicious").length,
          clean_count: Math.max(0, procsScanned + filesScanned - scanFindings.length),
          duration_ms: durationMs,
          results: scanFindings,
        });
      }

      case "set_auto_remediation": {
        autoRemediationEnabled = !!args.enabled;
        return res.json(autoRemediationEnabled);
      }

      case "get_av_stats": {
        const quarantinedCount = malwareResultsStore.filter((m) => m.quarantined).length;
        return res.json({
          engine_status: systemSettings.realtime_av_enabled ? "ARMED & LIVE (/PROC + BYTE SCANNER)" : "ON-DEMAND ONLY (REAL-TIME PAUSED)",
          engine_version: ENGINE_VERSION,
          db_version: "2026.11.13",
          signatures_loaded: VIRUS_SIGNATURES.length,
          files_scanned: filesScannedCount,
          threats_blocked: threatsBlockedCount,
          quarantined_count: quarantinedCount,
          quarantined_files: quarantinedCount,
          last_update: "Live",
          auto_remediation_enabled: autoRemediationEnabled,
        });
      }

      case "list_user_whitelisted_apps": {
        return res.json(trustedAppsStore);
      }

      case "trust_user_app": {
        const entry = {
          id: args.id || `app-${Date.now()}`,
          name: args.name || path.basename(args.path || "trusted-app"),
          path: args.path,
          added_ts: Date.now(),
        };
        trustedAppsStore = trustedAppsStore.filter((a) => a.path !== entry.path);
        trustedAppsStore.push(entry);
        writeJson(WHITELIST_FILE, trustedAppsStore);

        // Also update any matching malware scan result
        const mr = malwareResultsStore.find((m) => m.id === args.id || m.file_path === args.path);
        if (mr) {
          mr.status = "user_whitelisted";
          mr.user_verdict = "trusted_user_app";
          mr.is_infected = false;
          writeJson(MALWARE_RESULTS_FILE, malwareResultsStore);
        }

        recordAuditAction("WHITELIST_APP", 0, entry.path, `Added ${entry.name} to Developer Safeguard whitelist`);
        return res.json({ status: "trusted", ...entry, message: `Protected ${entry.name} under Developer Safeguard.` });
      }

      case "remove_user_whitelisted_app": {
        trustedAppsStore = trustedAppsStore.filter((a) => a.path !== args.path);
        writeJson(WHITELIST_FILE, trustedAppsStore);
        recordAuditAction("REMOVE_WHITELIST", 0, args.path, `Removed ${args.path} from Developer Safeguard whitelist`);
        return res.json(true);
      }

      case "list_canaries": {
        return res.json(
          Array.from(activeCanaries.values()).map((c) => ({
            id: c.id,
            token: c.token,
            file_path: c.file_path,
            description: c.description,
            created_ts: c.created_ts,
            triggered: c.triggered,
          }))
        );
      }

      case "create_canary": {
        const canary = registerCanary(args.filePath, args.description);
        recordAuditAction("CREATE_CANARY", 0, canary.file_path, `Deployed canary honeytoken ${canary.token}`);
        return res.json(canary);
      }

      case "delete_canary": {
        const c = activeCanaries.get(args.id);
        if (c) {
          if (c.watcher) c.watcher.close();
          try {
            if (fs.existsSync(c.file_path)) fs.unlinkSync(c.file_path);
          } catch {}
          activeCanaries.delete(args.id);
        }
        return res.json(true);
      }

      case "trigger_canary_test": {
        const c = activeCanaries.get(args.id);
        if (c) {
          fs.appendFileSync(c.file_path, `\n# TRIPWIRE TEST READ/WRITE AT ${new Date().toISOString()}\n`);
        }
        return res.json(true);
      }

      case "list_incidents": {
        const limit = args.limit || 50;
        const offset = args.offset || 0;
        return res.json(incidentsStore.slice(offset, offset + limit));
      }

      case "count_open": {
        return res.json(incidentsStore.filter((i) => !i.resolved).length);
      }

      case "resolve_incident": {
        const inc = incidentsStore.find((i) => i.id === args.id);
        if (inc) {
          inc.resolved = true;
          writeJson(INCIDENTS_FILE, incidentsStore);
          broadcastSse("incident-resolved", { id: args.id });
        }
        return res.json(true);
      }

      case "export_markdown": {
        const openCount = incidentsStore.filter((i) => !i.resolved).length;
        const md = `# Aegis-Guard Live Security Report\nGenerated: ${new Date().toISOString()}\nOpen Incidents: ${openCount}\nTotal Recorded: ${incidentsStore.length}\n\n${incidentsStore
          .map(
            (i) =>
              `### [${String(i.severity).toUpperCase()}] ${i.process} (PID ${i.pid})\n- **Rule:** ${i.rule}\n- **Command:** \`${(i.cmdline || []).join(" ")}\`\n- **Reason:** ${i.reason}\n- **Status:** ${i.resolved ? "RESOLVED" : "OPEN"}\n`
          )
          .join("\n")}`;
        return res.json(md);
      }

      case "export_json": {
        return res.json(JSON.stringify(incidentsStore, null, 2));
      }

      case "execute_action": {
        const pid = Number(args.pid) || 0;
        const action = (args.action || "kill").toUpperCase();
        const processName = args.processName || `proc-${pid}`;
        let outcome = "";

        if ((action === "KILL" || action === "QUARANTINE") && !systemSettings.active_kill_enabled) {
          return res.status(403).json({
            error: "Active Process Neutralization (CAP_KILL) is disabled in Settings. Enable it before dispatching SIGTERM/SIGSTOP.",
          });
        }

        if (action === "KILL" && pid > 0) {
          if (pid === process.pid || pid === 1) {
            return res.status(400).json({ error: "Refusing to terminate PID 1 or Aegis server itself." });
          }
          try {
            process.kill(pid, "SIGTERM");
            outcome = `SIGTERM dispatched to real Linux PID ${pid}`;
          } catch (e: any) {
            outcome = `SIGKILL/SIGTERM attempt on PID ${pid}: ${e?.message}`;
          }
        } else if (action === "WHITELIST") {
          const entry = {
            id: `app-${Date.now()}`,
            name: processName,
            path: args.exePath || processName,
            added_ts: Date.now(),
          };
          trustedAppsStore.push(entry);
          writeJson(WHITELIST_FILE, trustedAppsStore);
          outcome = `Added ${processName} to Developer Safeguard whitelist.`;
        } else if (action === "QUARANTINE") {
          if (pid > 1 && pid !== process.pid) {
            try {
              process.kill(pid, "SIGSTOP");
              outcome = `SIGSTOP freeze sent to PID ${pid}`;
            } catch (e: any) {
              outcome = `Quarantine freeze attempted on PID ${pid}: ${e?.message}`;
            }
          }
        } else if (action === "LIFT_QUARANTINE") {
          if (pid > 1 && pid !== process.pid) {
            try {
              process.kill(pid, "SIGCONT");
              outcome = `SIGCONT resume sent to PID ${pid}`;
            } catch {}
          }
        }

        if (args.incidentId) {
          const inc = incidentsStore.find((i) => i.id === args.incidentId);
          if (inc) {
            inc.resolved = true;
            writeJson(INCIDENTS_FILE, incidentsStore);
          }
        }

        const audit = recordAuditAction(
          action,
          pid,
          processName,
          args.note || `Action executed via dashboard`,
          args.incidentId,
          "success",
          outcome
        );
        return res.json({
          message: `Action ${action} executed for ${processName} (PID ${pid}). Audit SHA-256: ${audit.digest.slice(0, 16)}...`,
        });
      }

      case "list_audit_log": {
        const limit = args.limit || 100;
        const offset = args.offset || 0;
        const log = loadAuditLog().slice().reverse();
        return res.json(log.slice(offset, offset + limit));
      }

      case "verify_audit_chain": {
        const log = loadAuditLog();
        const errors: string[] = [];
        for (let i = 1; i < log.length; i++) {
          if (log[i].prev_digest !== log[i - 1].digest) {
            errors.push(`Tamper detected at entry ${log[i].id}: prev_digest mismatch`);
          }
        }
        return res.json(errors);
      }

      case "list_telemetry": {
        const limit = args.limit || 120;
        return res.json(telemetryStore.slice(0, limit));
      }

      case "record_telemetry_event": {
        pushTelemetry({
          id: `tel-ui-${Date.now()}`,
          ts: Date.now(),
          event_type: args.category || "SYSTEM_EVENT",
          process: "aegis-ui",
          parent: "aegis-engine",
          pid: process.pid,
          score: 0,
          verdict: "clean",
          severity: "low",
          detail: `${args.action || "EVENT"}: ${args.details || ""}`,
          explanation: args.details || "",
        });
        return res.json(true);
      }

      case "list_debug_log": {
        const limit = args.limit || 50;
        const offset = args.offset || 0;
        return res.json(debugLogStore.slice(offset, offset + limit));
      }

      case "evaluate_command": {
        return res.json(evaluateCommandDryRun(args, threatIntelFeed));
      }

      case "list_sandbox_reports": {
        return res.json(listSandboxReportsFromDisk());
      }

      case "launch_sandbox_jail": {
        const targetPath = args.filePath || args.file_path || args.sampleName || args.sample_name;
        if (!targetPath) {
          return res.status(400).json({ error: "Specify a real file path or upload a file to inspect." });
        }
        const buf = toBufferFromArg(args.content);
        const report = inspectRealSandboxTarget(
          targetPath,
          args.isolationType || args.isolation_type || "ReadOnly-Byte-Jail",
          args.networkConfinement || args.network_confinement || "OFFLINE",
          buf || undefined
        );
        broadcastSse("sandbox-update", { reports: listSandboxReportsFromDisk() });
        return res.json(report);
      }

      case "terminate_sandbox_jail": {
        const jailDir = path.join(SANDBOX_DIR, args.jailId || "");
        if (args.jailId && fs.existsSync(jailDir)) {
          fs.rmSync(jailDir, { recursive: true, force: true });
          recordAuditAction("TERMINATE_SANDBOX", 0, args.jailId, `Purged sandbox directory ${jailDir}`);
        }
        return res.json(true);
      }

      case "send_target_to_sandbox": {
        const item = malwareResultsStore.find((m) => m.id === args.id);
        let bytes: Buffer | undefined = undefined;
        if (item?.file_path && fs.existsSync(item.file_path)) {
          bytes = fs.readFileSync(item.file_path);
        } else if (item?.quarantine_path && fs.existsSync(item.quarantine_path)) {
          try {
            fs.chmodSync(item.quarantine_path, 0o400);
            bytes = fs.readFileSync(item.quarantine_path);
            fs.chmodSync(item.quarantine_path, 0o000);
          } catch {}
        }
        if (!bytes) {
          return res.status(400).json({ error: "Original file bytes unavailable on disk for sandbox inspection." });
        }
        const report = inspectRealSandboxTarget(
          item ? item.file_path : `target-${args.id}`,
          "ReadOnly-Byte-Jail",
          "OFFLINE",
          bytes
        );
        if (item) {
          item.sandbox_jail_id = report.jail_id;
          writeJson(MALWARE_RESULTS_FILE, malwareResultsStore);
        }
        return res.json({ jail_id: report.jail_id, message: `Isolated into sandbox jail ${report.jail_id}` });
      }

      case "get_ioc_stats": {
        const ips = threatIntelFeed.filter((e) => e.kind === "ip").length;
        const cidrs = threatIntelFeed.filter((e) => e.kind === "cidr").length;
        const domains = threatIntelFeed.filter((e) => e.kind === "domain").length;
        const hashes = threatIntelFeed.filter((e) => e.kind === "md5" || e.kind === "sha1" || e.kind === "sha256").length;
        return res.json({ ips, cidrs, domains, hashes });
      }

      case "check_ioc_manual": {
        const q = (args.value || "").trim().toLowerCase();
        const hit = threatIntelFeed.find((e) => e.ioc.toLowerCase() === q);
        if (hit) {
          pushDnsQuery({
            id: `dns-ioc-${Date.now()}`,
            domain: q,
            query: q,
            query_type: hit.kind.toUpperCase(),
            qtype: hit.kind.toUpperCase(),
            client_pid: process.pid,
            process: "manual-lookup",
            process_name: "manual-lookup",
            status: "FLAGGED",
            verdict: "malicious_c2",
            resolved_ip: hit.kind === "ip" ? q : null,
            threat_score: hit.confidence,
            ts: Date.now(),
          });
          return res.json({
            ioc: hit.ioc,
            kind: hit.kind,
            threat_type: hit.threat_type,
            feed: hit.feed,
            confidence: hit.confidence,
            context: args.context || "manual-lookup",
          });
        }
        return res.json(null);
      }

      case "get_storage_stats": {
        const dirSize = (dir: string) => {
          let total = 0;
          let count = 0;
          try {
            for (const f of fs.readdirSync(dir)) {
              const p = path.join(dir, f);
              const st = fs.statSync(p);
              if (st.isFile()) {
                total += st.size;
                count++;
              } else if (st.isDirectory()) {
                const sub = dirSize(p);
                total += sub.total;
                count += sub.count;
              }
            }
          } catch {}
          return { total, count };
        };

        const qStat = dirSize(QUARANTINE_DIR);
        const sStat = dirSize(SANDBOX_DIR);
        const auditSize = fs.existsSync(AUDIT_FILE) ? fs.statSync(AUDIT_FILE).size : 0;
        const incSize = fs.existsSync(INCIDENTS_FILE) ? fs.statSync(INCIDENTS_FILE).size : 0;
        const dbSize = auditSize + incSize;

        const artifacts: any[] = [];
        try {
          for (const f of fs.readdirSync(QUARANTINE_DIR)) {
            const p = path.join(QUARANTINE_DIR, f);
            const st = fs.statSync(p);
            artifacts.push({
              id: `art-${f}`,
              path: p,
              category: "quarantine_vault",
              size_bytes: st.size,
              created_at: st.ctimeMs,
              created_ts: st.ctimeMs,
              status: "quarantined",
              stale: Date.now() - st.ctimeMs > 60000,
            });
          }
        } catch {}

        const reclaimable = qStat.total + sStat.total;
        return res.json({
          total_storage_bytes: dbSize + reclaimable,
          db_size_bytes: dbSize,
          debug_size_bytes: JSON.stringify(debugLogStore).length,
          temp_files_bytes: qStat.total,
          temp_files_count: qStat.count,
          sandbox_artifacts_bytes: sStat.total,
          pcap_buffer_bytes: 0,
          debug_entries_count: debugLogStore.length,
          incidents_count: incidentsStore.length,
          audit_entries_count: loadAuditLog().length,
          total_reclaimable_bytes: reclaimable,
          temp_artifacts: artifacts,
          last_prune_ts: lastPrunedTs,
          last_pruned_ts: lastPrunedTs,
        });
      }

      case "get_auto_prune_config": {
        return res.json(autoPruneConfig);
      }

      case "update_auto_prune_config": {
        autoPruneConfig = { ...autoPruneConfig, ...args };
        writeJson(AUTO_PRUNE_FILE, autoPruneConfig);
        return res.json(autoPruneConfig);
      }

      case "prune_logs": {
        let freed = 0;
        let filesDeleted = 0;
        if (args.clean_temp_files !== false) {
          for (const dir of [QUARANTINE_DIR, LEGACY_SAMPLES_DIR]) {
            try {
              for (const f of fs.readdirSync(dir)) {
                const p = path.join(dir, f);
                freed += fs.statSync(p).size;
                fs.unlinkSync(p);
                filesDeleted++;
              }
            } catch {}
          }
        }
        if (args.clean_sandbox) {
          try {
            for (const d of fs.readdirSync(SANDBOX_DIR)) {
              fs.rmSync(path.join(SANDBOX_DIR, d), { recursive: true, force: true });
              filesDeleted++;
            }
          } catch {}
        }

        const maxDbg = Number(args.max_debug_entries) || autoPruneConfig.max_debug_entries || 50;
        let dbgDeleted = 0;
        if (debugLogStore.length > maxDbg) {
          dbgDeleted = debugLogStore.length - maxDbg;
          debugLogStore.length = maxDbg;
        }
        lastPrunedTs = Date.now();
        recordAuditAction("STORAGE_PRUNE", 0, "storage", `Pruned ${filesDeleted} temp/sandbox files (${freed} bytes)`);

        return res.json({
          success: true,
          freed_bytes: freed,
          debug_entries_deleted: dbgDeleted,
          pruned_debug_entries: dbgDeleted,
          temp_files_deleted: filesDeleted,
          pruned_temp_files: filesDeleted,
          sandbox_artifacts_deleted: args.clean_sandbox ? 1 : 0,
          pcap_buffers_deleted: 0,
          timestamp: lastPrunedTs,
        });
      }

      case "get_system_settings": {
        return res.json(systemSettings);
      }

      case "update_system_settings": {
        const next = {
          process_inspection_enabled: args.process_inspection_enabled ?? systemSettings.process_inspection_enabled,
          active_kill_enabled: args.active_kill_enabled ?? systemSettings.active_kill_enabled,
          net_admin_enabled: args.net_admin_enabled ?? systemSettings.net_admin_enabled,
          tamper_proof_audit: args.tamper_proof_audit ?? systemSettings.tamper_proof_audit,
          auto_update_enabled: args.auto_update_enabled ?? systemSettings.auto_update_enabled,
          realtime_av_enabled: args.realtime_av_enabled ?? systemSettings.realtime_av_enabled,
        };
        systemSettings = next;
        autoUpdateEnabled = next.auto_update_enabled;
        netDefenseConfig.ids_enabled = next.net_admin_enabled;
        writeJson(SYSTEM_SETTINGS_FILE, systemSettings);
        writeJson(NET_CONFIG_FILE, netDefenseConfig);
        recordAuditAction(
          "SETTINGS_UPDATE",
          process.pid,
          "system-settings",
          `Updated kernel/AV policies (inspect:${next.process_inspection_enabled}, kill:${next.active_kill_enabled}, net:${next.net_admin_enabled}, av:${next.realtime_av_enabled})`
        );
        return res.json(systemSettings);
      }

      case "get_runtime_info": {
        const goCheck = await queryGoBridge("get_inspection_snapshot");
        return res.json({
          app_version: APP_VERSION,
          engine_version: ENGINE_VERSION,
          transport: "HTTP + SSE IPC",
          platform: os.platform(),
          arch: os.arch(),
          hostname: os.hostname(),
          data_dir: DATA_DIR,
          quarantine_dir: QUARANTINE_DIR,
          audit_hash_algo: "SHA-256",
          go_bridge_connected: Boolean(goCheck?.ok),
        });
      }

      case "check_update": {
        return res.json({
          current_version: APP_VERSION,
          engine_version: ENGINE_VERSION,
          latest_version: APP_VERSION,
          update_available: false,
          release_url: "https://github.com/SepJs/aegis-guard/releases",
          release_notes: "Live Linux /proc, Go packet bridge, & real-time AV engine active.",
          auto_update_enabled: autoUpdateEnabled,
        });
      }

      case "set_auto_update": {
        autoUpdateEnabled = !!args.enabled;
        systemSettings.auto_update_enabled = autoUpdateEnabled;
        writeJson(SYSTEM_SETTINGS_FILE, systemSettings);
        return res.json(autoUpdateEnabled);
      }

      case "apply_update": {
        loadThreatIntelFeed();
        return res.json({
          status: "applied",
          app_version: APP_VERSION,
          engine_version: ENGINE_VERSION,
          message: "Threat intel feeds and signature database reloaded from disk.",
        });
      }

      default: {
        console.warn(`[Aegis Server] Unhandled IPC command: ${cmd}`);
        return res.json(null);
      }
    }
  } catch (err: any) {
    console.error(`Error handling IPC cmd ${cmd}:`, err);
    return res.status(500).json({ error: err?.message || String(err) });
  }
});

// -------------------------------------------------------------
// Vite Dev Server / Static Hosting
// -------------------------------------------------------------
async function startServer() {
  const isProduction = process.env.NODE_ENV === "production";

  if (!isProduction) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
      root: path.resolve(process.cwd(), "tauri-app"),
    });
    app.use(vite.middlewares);
  } else {
    const tauriDist = path.resolve(process.cwd(), "tauri-app/dist");
    const rootDist = path.resolve(process.cwd(), "dist");
    const distPath = fs.existsSync(path.join(tauriDist, "index.html")) ? tauriDist : rootDist;
    if (!fs.existsSync(path.join(distPath, "index.html"))) {
      console.error(`[Aegis-Guard] Frontend build not found at ${tauriDist} or ${rootDist}. Run 'npm run build' first.`);
    }
    app.use(express.static(distPath));
    app.use((_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`[Aegis-Guard] Live Endpoint Security & IDS Suite active on http://127.0.0.1:${PORT}`);
  });
}

startServer();
