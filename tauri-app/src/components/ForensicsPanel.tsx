import { useState, useCallback, useRef, useEffect } from "react";
import { invoke } from "../lib/ipc/core";
import type {
  ScanSummary,
  FileScanResult,
  VirusSignature,
  MalwareScanResult,
  AvEngineStats,
} from "../types";

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function EntropyBar({ value }: { value: number }) {
  const pct = Math.min((value / 8) * 100, 100);
  const cls = value > 7.5 ? "ef--high" : value > 6.5 ? "ef--medium" : value > 4.0 ? "ef--normal" : "ef--low";
  return (
    <div className="entropy-track">
      <div className={`entropy-fill ${cls}`} style={{ width: `${pct.toFixed(1)}%` }} />
    </div>
  );
}

function ResultRow({ r }: { r: FileScanResult }) {
  const [open, setOpen] = useState(false);
  const fname = r.path.split("/").pop() ?? r.path;

  return (
    <>
      <div className={`result-row result-row--${r.risk}`} onClick={() => setOpen((v) => !v)}>
        <span className="result-name" title={r.path}>
          {fname}
        </span>
        {r.entropy != null ? <EntropyBar value={r.entropy} /> : <div style={{ flex: 1 }} />}
        <span className="entropy-val">{r.entropy?.toFixed(3) ?? "—"}</span>
        <span className="result-mime">{r.mime_guess}</span>
        <span className="result-size">{fmtBytes(r.size_bytes)}</span>
        <span className={`risk-pill rp--${r.risk === "skipped" ? "skip" : r.risk}`}>{r.risk.toUpperCase()}</span>
      </div>
      {open && (
        <div className="result-detail">
          <div className="meta-row">
            <span className="meta-label">PATH</span>
            <code className="meta-code">{r.path}</code>
          </div>
          <div className="meta-row">
            <span className="meta-label">NOTE</span>
            <span className="meta-val">{r.note}</span>
          </div>
          {r.entropy != null && (
            <div className="meta-row">
              <span className="meta-label">SHANNON ENTROPY</span>
              <span className="meta-val">
                {r.entropy.toFixed(3)} / 8.000 bits per byte ({((r.entropy / 8) * 100).toFixed(1)}% randomness)
              </span>
            </div>
          )}
        </div>
      )}
    </>
  );
}

export default function ForensicsPanel() {
  const [mode, setMode] = useState<"entropy" | "antivirus">("antivirus");

  // Entropy scan state
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [filter, setFilter] = useState("all");
  const [customPath, setCustomPath] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  // Antivirus state
  const [signatures, setSignatures] = useState<VirusSignature[]>([]);
  const [malwareResults, setMalwareResults] = useState<MalwareScanResult[]>([]);
  const [whitelistedApps, setWhitelistedApps] = useState<any[]>([]);
  const [avSubTab, setAvSubTab] = useState<"scans" | "whitelist">("scans");
  const [avStats, setAvStats] = useState<AvEngineStats | null>(null);
  const [avScanning, setAvScanning] = useState(false);
  const [avNotice, setAvNotice] = useState<string | null>(null);
  const [targetPath, setTargetPath] = useState("");
  const [targetContent, setTargetContent] = useState("");
  const [sigFilter, setSigFilter] = useState<string>("all");
  const [sigSearch, setSigSearch] = useState("");
  const [expandedResultId, setExpandedResultId] = useState<string | null>(null);

  // Load AV data
  const loadAvData = useCallback(async () => {
    try {
      const [sigs, results, stats, uapps] = await Promise.all([
        invoke<VirusSignature[]>("list_virus_signatures"),
        invoke<MalwareScanResult[]>("list_malware_results"),
        invoke<AvEngineStats>("get_av_stats"),
        invoke<any[]>("list_user_whitelisted_apps"),
      ]);
      if (Array.isArray(sigs)) setSignatures(sigs);
      if (Array.isArray(results)) setMalwareResults(results);
      if (stats) setAvStats(stats);
      if (Array.isArray(uapps)) setWhitelistedApps(uapps);
    } catch (err) {
      console.error("Failed to load AV signatures & results:", err);
    }
  }, []);

  const handleTrustUserApp = async (id: string, path: string, name?: string) => {
    try {
      const res: any = await invoke("trust_user_app", { id, path, name });
      setAvNotice(`SAFEGUARD ENFORCED: ${res?.message || "Program whitelisted as trusted user software"}`);
      loadAvData();
    } catch (err) {
      console.error("Error trusting user app:", err);
    }
  };

  const handleSendToSandbox = async (id: string) => {
    try {
      const res: any = await invoke("send_target_to_sandbox", { id });
      setAvNotice(`SANDBOX ISOLATED: ${res?.message || "Target isolated in sandbox jail"}`);
      loadAvData();
    } catch (err) {
      console.error("Error isolating target in sandbox:", err);
    }
  };

  const handleConfirmMalware = async (id: string) => {
    try {
      const res: any = await invoke("confirm_malware_quarantine", { id });
      setAvNotice(`THREAT QUARANTINED: ${res?.message || "Malware neutralized"}`);
      loadAvData();
    } catch (err) {
      console.error("Error confirming malware:", err);
    }
  };

  const handleRemoveWhitelist = async (path: string) => {
    try {
      await invoke("remove_user_whitelisted_app", { path });
      setAvNotice(`Safeguard protection removed for ${path}`);
      loadAvData();
    } catch (err) {
      console.error("Error removing whitelist:", err);
    }
  };

  useEffect(() => {
    loadAvData();
  }, [loadAvData]);

  // Run Entropy Scan
  const runScan = useCallback(async (path: string, content?: Uint8Array | string) => {
    setScanning(true);
    setError(null);
    try {
      const r = await invoke<ScanSummary>("scan_entropy", {
        request: { path, content, max_bytes: 33554432, recursive: true },
        path,
        content,
      });
      setSummary(r);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setScanning(false);
    }
  }, []);

  async function handleFileSelected(file: File) {
    try {
      const buffer = await file.arrayBuffer();
      const uint8 = new Uint8Array(buffer);
      if (mode === "entropy") {
        runScan(file.name, uint8);
      } else {
        // Send lossless raw binary bytes (up to 8MB) without UTF-8 decoder corruption
        const slice = uint8.slice(0, Math.min(uint8.length, 8 * 1024 * 1024));
        scanTarget(file.name, Array.from(slice));
      }
    } catch {
      if (mode === "entropy") {
        runScan(file.name);
      } else {
        scanTarget(file.name);
      }
    }
  }

  // Run AV Scan on target path or custom content
  const scanTarget = async (target: string, content?: string | number[]) => {
    setAvScanning(true);
    setAvNotice(null);
    try {
      const res = await invoke<MalwareScanResult>("scan_malware_target", {
        path: target.trim() || "/tmp/unknown_binary",
        content: content !== undefined ? content : targetContent,
      });
      if (res) {
        setAvNotice(
          res.status === "infected"
            ? `ALERT: Infected with ${res.malware_name || "Malware"} (${res.family || "Unknown"}) — Rule ${res.rule_matched}`
            : res.status === "suspicious"
            ? `SUSPICIOUS: Anomaly flagged by ${res.rule_matched}`
            : `CLEAN: ${res.rule_matched || `No virus signature detected in ${res.target_path}`}`
        );
        loadAvData();
      }
    } catch (err) {
      console.error("AV scan failed:", err);
    } finally {
      setAvScanning(false);
    }
  };

  // Recursive directory malware scan
  const scanDirectory = async (dirPath: string) => {
    const cleanDir = dirPath.trim() || "/tmp/aegis_guard_data";
    setAvScanning(true);
    setAvNotice(null);
    try {
      const res = await invoke<{
        directory: string;
        files_scanned: number;
        infected_count: number;
        suspicious_count: number;
        clean_count: number;
        duration_ms: number;
      }>("scan_directory_malware", { path: cleanDir });
      if (res) {
        setAvNotice(
          res.infected_count > 0
            ? `ALERT: Directory scan (${res.directory}) found ${res.infected_count} infected, ${res.suspicious_count} suspicious across ${res.files_scanned} files (${res.duration_ms}ms)`
            : res.suspicious_count > 0
            ? `SUSPICIOUS: Directory scan (${res.directory}) flagged ${res.suspicious_count} files across ${res.files_scanned} files (${res.duration_ms}ms)`
            : `CLEAN: Scanned ${res.files_scanned} files in ${res.directory} (${res.clean_count} verified clean in ${res.duration_ms}ms)`
        );
        loadAvData();
      }
    } catch (err: any) {
      setAvNotice(`Directory scan error: ${err?.message || String(err)}`);
    } finally {
      setAvScanning(false);
    }
  };

  // Quick system-wide AV scan (/proc executables + volatile host paths)
  const runQuickSystemAvScan = async () => {
    setAvScanning(true);
    setAvNotice(null);
    try {
      const res = await invoke<{
        procs_scanned: number;
        files_scanned: number;
        infected_count: number;
        suspicious_count: number;
        clean_count: number;
        duration_ms: number;
      }>("quick_system_av_scan");
      if (res) {
        setAvNotice(
          res.infected_count > 0 || res.suspicious_count > 0
            ? `ALERT: System AV Sweep inspected ${res.procs_scanned} live processes + ${res.files_scanned} volatile files (${res.infected_count} infected, ${res.suspicious_count} suspicious) in ${res.duration_ms}ms`
            : `CLEAN: System AV Sweep verified ${res.procs_scanned} live processes + ${res.files_scanned} volatile files (${res.duration_ms}ms)`
        );
        loadAvData();
      }
    } catch (err: any) {
      setAvNotice(`System AV scan failed: ${err?.message || String(err)}`);
    } finally {
      setAvScanning(false);
    }
  };

  // Quarantine / Restore action
  const handleQuarantineAction = async (id: string, action: "quarantine" | "restore" | "delete") => {
    try {
      const res = await invoke<any>("quarantine_malware", { id, action });
      if (res?.message) {
        setAvNotice(res.message);
        loadAvData();
      }
    } catch (err) {
      console.error("Quarantine action failed:", err);
    }
  };

  const handleToggleAutoRemediation = async () => {
    try {
      const current = avStats?.auto_remediation_enabled ?? true;
      await invoke("set_auto_remediation", { enabled: !current });
      setAvNotice(`Automated Malware Neutralization Engine ${!current ? "ARMED (Quarantines confirmed threats)" : "DISARMED (Manual Action Required)"}`);
      loadAvData();
    } catch (err) {
      console.error("Failed to toggle auto remediation:", err);
    }
  };

  const displayedEntropy = summary?.results.filter((r) => (filter === "all" ? true : r.risk === filter)) ?? [];

  const filteredSignatures = signatures.filter((sig) => {
    if (sigFilter !== "all" && sig.family !== sigFilter) return false;
    if (sigSearch) {
      const q = sigSearch.toLowerCase();
      return (
        sig.name.toLowerCase().includes(q) ||
        sig.rule_code.toLowerCase().includes(q) ||
        sig.description.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="panel" id="forensics-panel">
      {/* Top Header */}
      <div className="panel-header">
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <button
            className={`sm-btn ${mode === "antivirus" ? "sm-btn--active" : ""}`}
            onClick={() => setMode("antivirus")}
            style={{ fontWeight: 700 }}
          >
            ANTIVIRUS &amp; MALWARE DETECTOR
          </button>
          <button
            className={`sm-btn ${mode === "entropy" ? "sm-btn--active" : ""}`}
            onClick={() => setMode("entropy")}
            style={{ fontWeight: 700 }}
          >
            SHANNON ENTROPY INSPECTOR
          </button>
        </div>

        {mode === "antivirus" && avStats && (
          <>
            <span className="pstat" style={{ color: "var(--teall)", borderColor: "var(--teal)" }}>
              ENGINE: {avStats.engine_version}
            </span>
            <span className="pstat">{signatures.length} SIGNATURES</span>
            {avStats.threats_blocked > 0 && (
              <span className="pstat pstat--warn">{avStats.threats_blocked} BLOCKED</span>
            )}
            {avStats.quarantined_files > 0 && (
              <span className="pstat" style={{ color: "var(--amberl)", borderColor: "var(--amber)" }}>
                {avStats.quarantined_files} QUARANTINED
              </span>
            )}
            <button
              className="sm-btn"
              onClick={handleToggleAutoRemediation}
              style={{
                background: avStats.auto_remediation_enabled ? "rgba(13,148,136,.15)" : "rgba(220,38,38,.12)",
                color: avStats.auto_remediation_enabled ? "var(--teall)" : "var(--redl)",
                borderColor: avStats.auto_remediation_enabled ? "var(--teal)" : "var(--red)",
                fontWeight: 700,
                fontSize: 10,
              }}
              title="Automatically quarantines critical threats and takeover malware"
            >
              {avStats.auto_remediation_enabled ? "AUTO-QUARANTINE: ARMED" : "AUTO-QUARANTINE: OFF"}
            </button>
          </>
        )}

        {mode === "entropy" && summary && (
          <>
            <span className="pstat">{summary.scanned_files} SCANNED</span>
            {summary.high_risk > 0 && <span className="pstat pstat--warn">{summary.high_risk} HIGH-RISK</span>}
            <span className="scan-time">{summary.elapsed_ms}ms</span>
          </>
        )}

        <div className="toolbar-right">
          {mode === "antivirus" && (
            <button
              className="btn-primary"
              onClick={runQuickSystemAvScan}
              disabled={avScanning}
              title="Inspect all live /proc process binaries and volatile directories (/dev/shm, /var/tmp)"
            >
              {avScanning ? "SCANNING HOST…" : "QUICK SYSTEM AV SCAN"}
            </button>
          )}
          {mode === "entropy" && summary && (
            <>
              <select className="filter-select" value={filter} onChange={(e) => setFilter(e.target.value)}>
                <option value="all">ALL ENTROPY RESULTS</option>
                <option value="high">HIGH RISK (&gt;7.5)</option>
                <option value="medium">MEDIUM RISK</option>
                <option value="normal">NORMAL</option>
              </select>
              <button
                className="sm-btn"
                onClick={() => {
                  setSummary(null);
                  setFilter("all");
                }}
              >
                NEW SCAN
              </button>
            </>
          )}
          <input
            ref={inputRef}
            type="file"
            style={{ display: "none" }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) handleFileSelected(f);
            }}
          />
          <button className="sm-btn" onClick={() => inputRef.current?.click()} disabled={scanning || avScanning}>
            BROWSE FILE…
          </button>
        </div>
      </div>

      {/* AV Notice Banner */}
      {avNotice && (
        <div
          style={{
            padding: "8px 14px",
            background: avNotice.includes("ALERT") || avNotice.includes("failed") || avNotice.includes("error")
              ? "rgba(220,38,38,.12)"
              : "rgba(13,148,136,.12)",
            borderBottom: "1px solid var(--border)",
            color: avNotice.includes("ALERT") || avNotice.includes("failed") || avNotice.includes("error")
              ? "var(--redl)"
              : "var(--teall)",
            fontSize: 11,
            fontWeight: 600,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <span>{avNotice}</span>
          <button onClick={() => setAvNotice(null)} style={{ color: "var(--tx2)", fontSize: 11, cursor: "pointer" }}>
            ×
          </button>
        </div>
      )}

      {/* MODE 1: ANTIVIRUS & MALWARE DETECTOR */}
      {mode === "antivirus" && (
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {/* Real File & Payload Scanner Bar */}
          <div
            style={{
              padding: "10px 14px",
              background: "var(--bg1)",
              borderBottom: "1px solid var(--border)",
              display: "flex",
              flexDirection: "column",
              gap: 8,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <span style={{ fontSize: 10, color: "var(--tx2)", letterSpacing: "0.08em", fontWeight: 700 }}>
                HOST FILE &amp; PAYLOAD BYTE SCANNER
              </span>
              <span style={{ fontSize: 10, color: "var(--tx2)" }}>
                Scans files on disk, live processes, or uploaded binaries via SHA-256 and byte-signature inspection.
              </span>
            </div>

            {/* Custom Target / Script / Directory Scanner */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto auto", gap: 8, marginTop: 4 }}>
              <input
                className="challenge-input"
                style={{ fontSize: 11, padding: "5px 8px" }}
                value={targetPath}
                onChange={(e) => setTargetPath(e.target.value)}
                placeholder="File or directory path (e.g. /tmp/aegis_guard_data, /bin/sh)..."
              />
              <input
                className="challenge-input"
                style={{ fontSize: 11, padding: "5px 8px" }}
                value={targetContent}
                onChange={(e) => setTargetContent(e.target.value)}
                placeholder="Payload string / command to inspect (or paste script snippet)..."
              />
              <button
                className="action-btn"
                onClick={() => scanTarget(targetPath, targetContent)}
                disabled={avScanning || (!targetPath && !targetContent)}
                style={{ height: 28, padding: "0 14px" }}
              >
                {avScanning ? "SCANNING…" : "SCAN FILE"}
              </button>
              <button
                className="sm-btn sm-btn--active"
                onClick={() => scanDirectory(targetPath || "/tmp/aegis_guard_data")}
                disabled={avScanning}
                style={{ height: 28, padding: "0 12px", fontWeight: 700 }}
                title="Recursively scan all files inside the specified directory"
              >
                SCAN DIR
              </button>
            </div>
          </div>

          {/* Main AV View: Split between Scan Results and Signatures Database */}
          <div style={{ flex: 1, display: "grid", gridTemplateColumns: "1fr 420px", overflow: "hidden" }}>
            {/* Left: Malware Detection & Quarantine Results OR Whitelisted User Apps */}
            <div style={{ display: "flex", flexDirection: "column", borderRight: "1px solid var(--border)", overflow: "hidden" }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "6px 14px",
                  background: "var(--bg1)",
                  borderBottom: "1px solid var(--border)",
                  fontSize: 9,
                  color: "var(--tx2)",
                  fontWeight: 700,
                  letterSpacing: "0.08em",
                }}
              >
                <div style={{ display: "flex", gap: 6 }}>
                  <button
                    className={`sm-btn ${avSubTab === "scans" ? "sm-btn--active" : ""}`}
                    onClick={() => setAvSubTab("scans")}
                    style={{ fontSize: 9 }}
                  >
                    THREAT SCANS ({malwareResults.length})
                  </button>
                  <button
                    className={`sm-btn ${avSubTab === "whitelist" ? "sm-btn--active" : ""}`}
                    onClick={() => setAvSubTab("whitelist")}
                    style={{ fontSize: 9, color: "var(--teall)", borderColor: avSubTab === "whitelist" ? "var(--teal)" : undefined }}
                  >
                    USER APPS SAFEGUARD ({whitelistedApps.length})
                  </button>
                </div>
                <button className="sm-btn" onClick={loadAvData} style={{ fontSize: 8 }}>
                  REFRESH
                </button>
              </div>

              {avSubTab === "whitelist" ? (
                <div style={{ flex: 1, overflowY: "auto", padding: 12 }}>
                  <div style={{ marginBottom: 12, padding: "8px 12px", background: "rgba(13,148,136,0.08)", border: "1px solid rgba(13,148,136,0.3)", borderRadius: 4 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: "var(--teall)", marginBottom: 4 }}>
                      User Application Safeguard Protection
                    </div>
                    <div style={{ fontSize: 10, color: "var(--tx1)", lineHeight: 1.4 }}>
                      All binaries, scripts, and dev tools registered here are shielded from automated deletion. The heuristic antivirus will never quarantine or purge them without explicit administrator consent.
                    </div>
                  </div>

                  {whitelistedApps.length === 0 ? (
                    <div className="empty-state">
                      <span>NO PROGRAMS IN SAFEGUARD LIST</span>
                      <span style={{ fontSize: 10 }}>
                        When a program triggers heuristic suspicion, mark it as trusted software to protect it here.
                      </span>
                    </div>
                  ) : (
                    whitelistedApps.map((uapp) => (
                      <div
                        key={uapp.id || uapp.path}
                        style={{
                          padding: "10px 12px",
                          background: "var(--bg2)",
                          border: "1px solid var(--border)",
                          borderLeft: "3px solid var(--teal)",
                          borderRadius: 4,
                          marginBottom: 8,
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          gap: 12,
                        }}
                      >
                        <div style={{ display: "flex", flexDirection: "column", gap: 3, flex: 1, overflow: "hidden" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <span style={{ fontSize: 11, fontWeight: 700, color: "var(--tx0)" }}>{uapp.name}</span>
                            <span style={{ fontSize: 8, padding: "1px 5px", background: "rgba(13,148,136,0.2)", color: "var(--teall)", borderRadius: 2, fontWeight: 700 }}>
                              PROTECTED
                            </span>
                          </div>
                          <div style={{ fontSize: 10, color: "var(--tx2)", fontFamily: "var(--mono)" }}>{uapp.path}</div>
                          {uapp.note && <div style={{ fontSize: 10, color: "var(--tx1)" }}>{uapp.note}</div>}
                          {uapp.sha256 && (
                            <div style={{ fontSize: 9, color: "var(--tx2)", fontFamily: "var(--mono)" }}>SHA-256: {uapp.sha256.slice(0, 24)}...</div>
                          )}
                        </div>
                        <button
                          className="sm-btn"
                          onClick={() => handleRemoveWhitelist(uapp.path)}
                          style={{ borderColor: "var(--red)", color: "var(--redl)", fontSize: 9 }}
                        >
                          Remove Protection
                        </button>
                      </div>
                    ))
                  )}
                </div>
              ) : (
                <div style={{ flex: 1, overflowY: "auto" }}>
                  {malwareResults.length === 0 ? (
                    <div className="empty-state">
                      <span>NO MALWARE SCANS CONDUCTED YET</span>
                      <span style={{ fontSize: 10 }}>
                        Run Quick System AV Scan or enter a file/directory path above to inspect host artifacts.
                      </span>
                    </div>
                  ) : (
                    malwareResults.map((mr) => {
                      const isExpanded = expandedResultId === mr.id;
                      return (
                        <div
                          key={mr.id}
                          style={{
                            borderBottom: "1px solid rgba(37,37,50,.55)",
                            borderLeft: `3px solid ${
                              mr.status === "infected"
                                ? "var(--red)"
                                : mr.status === "suspicious"
                                ? "var(--amber)"
                                : mr.status === "user_whitelisted"
                                ? "var(--teal)"
                                : "var(--teal)"
                            }`,
                            background: isExpanded ? "var(--bg3)" : "transparent",
                            transition: "background 70ms",
                          }}
                        >
                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: 10,
                              padding: "7px 12px",
                              cursor: "pointer",
                            }}
                            onClick={() => setExpandedResultId(isExpanded ? null : mr.id)}
                          >
                            <span
                              style={{
                                fontSize: 8,
                                fontWeight: 700,
                                padding: "2px 6px",
                                borderRadius: 2,
                                background:
                                  mr.status === "infected"
                                    ? "rgba(220,38,38,.2)"
                                    : mr.status === "suspicious"
                                    ? "rgba(217,119,6,.2)"
                                    : "rgba(13,148,136,.2)",
                                color:
                                  mr.status === "infected"
                                    ? "var(--redl)"
                                    : mr.status === "suspicious"
                                    ? "var(--amberl)"
                                    : "var(--teall)",
                                border: "1px solid currentColor",
                                letterSpacing: "0.04em",
                              }}
                            >
                              {mr.status.toUpperCase()}
                            </span>

                            <span style={{ fontSize: 11, fontWeight: 600, color: "var(--tx0)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              {mr.malware_name ? `${mr.malware_name} [${mr.family}]` : mr.target_path}
                            </span>

                            {mr.user_verdict === "trusted_user_app" && (
                              <span style={{ fontSize: 8, color: "var(--teall)", fontWeight: 700 }}>
                                SAFEGUARDED
                              </span>
                            )}

                            {mr.sandbox_jail_id && (
                              <span style={{ fontSize: 8, color: "var(--purplel)", fontWeight: 700 }}>
                                ISOLATED
                              </span>
                            )}

                            <span
                              style={{
                                fontSize: 8,
                                fontFamily: "var(--mono)",
                                padding: "1px 5px",
                                borderRadius: 2,
                                background: "var(--bg1)",
                                color: "var(--tx1)",
                                border: "1px solid var(--border)",
                              }}
                            >
                              {mr.rule_matched}
                            </span>

                            {mr.quarantined ? (
                              <span style={{ fontSize: 8, color: "var(--amberl)", fontWeight: 700 }}>
                                QUARANTINED
                              </span>
                            ) : mr.status === "infected" ? (
                              <button
                                className="sm-btn"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleQuarantineAction(mr.id, "quarantine");
                                }}
                                style={{ borderColor: "var(--amber)", color: "var(--amberl)", fontSize: 8 }}
                              >
                                QUARANTINE
                              </button>
                            ) : null}

                            <span style={{ fontSize: 9, color: "var(--tx2)" }}>{isExpanded ? "▲" : "▼"}</span>
                          </div>

                          {/* Suspicious User Program Triage Prompt */}
                          {mr.status === "suspicious" && (
                            <div style={{ margin: "4px 12px 8px", padding: "8px 10px", background: "rgba(245,158,11,0.08)", border: "1px solid rgba(245,158,11,0.3)", borderRadius: 4 }}>
                              <div style={{ fontSize: 10, fontWeight: 700, color: "var(--amberl)" }}>
                                SUSPICIOUS SOFTWARE TRIAGE
                              </div>
                              <div style={{ fontSize: 10, color: "var(--tx1)", margin: "4px 0 6px", lineHeight: 1.4 }}>
                                This binary or script triggered heuristic detection patterns. Select an action to handle it safely:
                              </div>
                              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                                <button
                                  className="sm-btn"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleTrustUserApp(mr.id, mr.target_path, mr.malware_name);
                                  }}
                                  style={{ borderColor: "var(--teal)", color: "var(--teall)", fontSize: 9, fontWeight: 700 }}
                                >
                                  Trust &amp; Safeguard (Whitelist)
                                </button>
                                <button
                                  className="sm-btn"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleSendToSandbox(mr.id);
                                  }}
                                  style={{ borderColor: "var(--purple)", color: "var(--purplel)", fontSize: 9, fontWeight: 700 }}
                                >
                                  Isolate in Sandbox
                                </button>
                                <button
                                  className="sm-btn"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleConfirmMalware(mr.id);
                                  }}
                                  style={{ borderColor: "var(--red)", color: "var(--redl)", fontSize: 9, fontWeight: 700 }}
                                >
                                  Confirm Threat &amp; Quarantine
                                </button>
                              </div>
                            </div>
                          )}

                          {isExpanded && (
                            <div
                              style={{
                                padding: "8px 14px 10px",
                                background: "var(--bg0)",
                                borderTop: "1px solid var(--border-dim)",
                                display: "flex",
                                flexDirection: "column",
                                gap: 4,
                                fontSize: 10,
                              }}
                            >
                              <div className="meta-row">
                                <span className="meta-label">TARGET PATH</span>
                                <code className="meta-code">{mr.target_path}</code>
                              </div>
                              <div className="meta-row">
                                <span className="meta-label">DETECTION</span>
                                <span className="meta-val">
                                  {mr.detection_method.toUpperCase()} · CONFIDENCE: {mr.confidence.toUpperCase()}
                                </span>
                              </div>
                              {mr.user_verdict && (
                                <div className="meta-row">
                                  <span className="meta-label">USER VERDICT</span>
                                  <span className="meta-val" style={{ color: mr.user_verdict === "trusted_user_app" ? "var(--teall)" : "var(--amberl)", fontWeight: 700 }}>
                                    {mr.user_verdict.toUpperCase()}
                                  </span>
                                </div>
                              )}
                              {mr.sha256 && (
                                <div className="meta-row">
                                  <span className="meta-label">SHA-256</span>
                                  <code className="meta-code meta-code--muted">{mr.sha256}</code>
                                </div>
                              )}
                              {mr.indicators && mr.indicators.length > 0 && (
                                <div style={{ marginTop: 3 }}>
                                  <span style={{ color: "var(--tx2)", fontSize: 9, fontWeight: 700 }}>
                                    MATCHED INDICATORS:
                                  </span>
                                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 2 }}>
                                    {mr.indicators.map((ind, iidx) => (
                                      <span
                                        key={iidx}
                                        style={{
                                          fontSize: 9,
                                          fontFamily: "var(--mono)",
                                          padding: "1px 5px",
                                          borderRadius: 2,
                                          background: "rgba(220,38,38,.12)",
                                          color: "var(--redl)",
                                          border: "1px solid rgba(220,38,38,.3)",
                                        }}
                                      >
                                        {ind}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}

                              <div style={{ display: "flex", gap: 6, marginTop: 6, flexWrap: "wrap" }}>
                                {mr.quarantined ? (
                                  <button
                                    className="sm-btn"
                                    onClick={() => handleQuarantineAction(mr.id, "restore")}
                                    style={{ borderColor: "var(--teal)", color: "var(--teall)", fontSize: 9 }}
                                  >
                                    RESTORE FROM QUARANTINE
                                  </button>
                                ) : (
                                  <button
                                    className="sm-btn"
                                    onClick={() => handleQuarantineAction(mr.id, "quarantine")}
                                    style={{ borderColor: "var(--amber)", color: "var(--amberl)", fontSize: 9 }}
                                  >
                                    MOVE TO QUARANTINE
                                  </button>
                                )}

                                <button
                                  className="sm-btn"
                                  onClick={() => handleTrustUserApp(mr.id, mr.target_path, mr.malware_name)}
                                  style={{ borderColor: "var(--teal)", color: "var(--teall)", fontSize: 9 }}
                                >
                                  SAFEGUARD USER APP
                                </button>

                                <button
                                  className="sm-btn"
                                  onClick={() => handleSendToSandbox(mr.id)}
                                  style={{ borderColor: "var(--purple)", color: "var(--purplel)", fontSize: 9 }}
                                >
                                  ISOLATE IN SANDBOX
                                </button>

                                <button
                                  className="sm-btn"
                                  onClick={() => handleQuarantineAction(mr.id, "delete")}
                                  style={{ borderColor: "var(--red)", color: "var(--redl)", fontSize: 9 }}
                                >
                                  DELETE RECORD
                                </button>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              )}
            </div>

            {/* Right: Virus Signatures & Rules Database */}
            <div style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "6px 12px",
                  background: "var(--bg1)",
                  borderBottom: "1px solid var(--border)",
                  gap: 6,
                }}
              >
                <span style={{ fontSize: 9, color: "var(--tx2)", fontWeight: 700, letterSpacing: "0.08em" }}>
                  SIGNATURE DATABASE ({filteredSignatures.length})
                </span>

                <select
                  className="filter-select"
                  value={sigFilter}
                  onChange={(e) => setSigFilter(e.target.value)}
                  style={{ fontSize: 8 }}
                >
                  <option value="all">ALL FAMILIES</option>
                  <option value="TestSample">TEST SAMPLE</option>
                  <option value="Packer">PACKER</option>
                  <option value="CoinMiner">COINMINER</option>
                  <option value="WebShell">WEBSHELL</option>
                  <option value="Ransomware">RANSOMWARE</option>
                  <option value="Rootkit">ROOTKIT</option>
                  <option value="Backdoor">BACKDOOR</option>
                  <option value="Botnet">BOTNET</option>
                  <option value="InfoStealer">INFOSTEALER</option>
                  <option value="Exploit">EXPLOIT</option>
                  <option value="Trojan">TROJAN</option>
                </select>
              </div>

              <div style={{ padding: "6px 10px", background: "var(--bg2)", borderBottom: "1px solid var(--border)" }}>
                <input
                  className="search-input"
                  style={{ width: "100%", fontSize: 9 }}
                  placeholder="Filter signatures by name, rule, or indicator…"
                  value={sigSearch}
                  onChange={(e) => setSigSearch(e.target.value)}
                />
              </div>

              <div style={{ flex: 1, overflowY: "auto", padding: "6px 10px", display: "flex", flexDirection: "column", gap: 6 }}>
                {filteredSignatures.map((sig) => (
                  <div
                    key={sig.id}
                    style={{
                      padding: "8px 10px",
                      background: "var(--bg3)",
                      border: "1px solid var(--border)",
                      borderRadius: 4,
                      display: "flex",
                      flexDirection: "column",
                      gap: 4,
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: "var(--tx0)" }}>{sig.name}</span>
                      <span
                        style={{
                          fontSize: 8,
                          fontWeight: 700,
                          padding: "1px 5px",
                          borderRadius: 2,
                          background:
                            sig.family === "CoinMiner"
                              ? "rgba(217,119,6,.2)"
                              : sig.family === "WebShell"
                              ? "rgba(124,58,237,.2)"
                              : "rgba(220,38,38,.2)",
                          color:
                            sig.family === "CoinMiner"
                              ? "var(--amberl)"
                              : sig.family === "WebShell"
                              ? "var(--vl)"
                              : "var(--redl)",
                        }}
                      >
                        {sig.family}
                      </span>
                    </div>

                    <div style={{ fontSize: 9, color: "var(--tx2)", lineHeight: 1.4 }}>{sig.description}</div>

                    <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", fontSize: 8 }}>
                      <span style={{ fontFamily: "var(--mono)", color: "var(--teall)" }}>{sig.rule_code}</span>
                      <span style={{ color: "var(--tx2)" }}>·</span>
                      <span style={{ color: "var(--tx1)" }}>PLATFORM: {sig.target_platform}</span>
                      {sig.mitre_technique && (
                        <>
                          <span style={{ color: "var(--tx2)" }}>·</span>
                          <span style={{ color: "var(--vl)" }}>{sig.mitre_technique}</span>
                        </>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MODE 2: SHANNON ENTROPY INSPECTOR */}
      {mode === "entropy" && (
        <>
          {!scanning && !summary && !error && (
            <div style={{ flex: 1, display: "flex", flexDirection: "column", padding: "16px 20px", overflowY: "auto" }}>
              <div
                className={`drop-zone ${dragOver ? "drop-zone--active" : ""}`}
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragOver(true);
                }}
                onDragLeave={() => setDragOver(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragOver(false);
                  const f = e.dataTransfer.files[0];
                  if (f) handleFileSelected(f);
                }}
                onClick={() => inputRef.current?.click()}
              >
                <div className="drop-icon-box">⊕</div>
                <div className="drop-title">DROP FILE HERE OR CLICK TO SELECT</div>
                <div className="drop-sub">
                  Shannon entropy calculation measures information density. Encrypted ransomware payloads, packed ELF/PE droppers, and encrypted memory blobs score &gt;7.5 bits/byte.
                </div>
                <div className="drop-sub drop-passive">PASSIVE CLIENT-SIDE & ENDPOINT ANALYSIS ONLY · NO MODIFICATION</div>
              </div>

              {/* Quick Preset Scans */}
              <div style={{ marginTop: 12, borderTop: "1px solid var(--border)", paddingTop: 14 }}>
                <div style={{ fontSize: 9, color: "var(--tx2)", letterSpacing: ".08em", marginBottom: 8 }}>
                  QUICK TARGET SAMPLES & SYSTEM PATH INSPECTOR:
                </div>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                  <button
                    className="sm-btn"
                    style={{ borderColor: "var(--purple)", color: "var(--vl)" }}
                    onClick={() => runScan("/app/applet")}
                  >
                    ⊕ Scan Workspace (/app/applet)
                  </button>
                  <button
                    className="sm-btn"
                    style={{ borderColor: "var(--teal)", color: "var(--teall)" }}
                    onClick={() => runScan("/etc/os-release")}
                  >
                    ✓ Scan System Config (/etc/os-release)
                  </button>
                  <div style={{ display: "flex", gap: 4, marginLeft: "auto" }}>
                    <input
                      type="text"
                      className="search-input"
                      placeholder="Target system path (/bin/bash, /tmp/…)"
                      value={customPath}
                      onChange={(e) => setCustomPath(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && customPath && runScan(customPath)}
                    />
                    <button
                      className="sm-btn sm-btn--active"
                      disabled={!customPath}
                      onClick={() => customPath && runScan(customPath)}
                    >
                      SCAN PATH
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {scanning && (
            <div className="empty-state">
              <div className="spinner" />
              <span style={{ marginTop: 8 }}>CALCULATING SHANNON ENTROPY…</span>
            </div>
          )}

          {error && (
            <div className="empty-state" style={{ color: "var(--redl)" }}>
              <span className="empty-icon" style={{ color: "var(--red)" }}>✕</span>
              {error}
            </div>
          )}

          {summary && !scanning && (
            <div style={{ display: "flex", flexDirection: "column", flex: 1, overflow: "hidden" }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  padding: "4px 14px",
                  fontSize: 9,
                  color: "var(--tx2)",
                  letterSpacing: ".08em",
                  textTransform: "uppercase",
                  borderBottom: "1px solid var(--border)",
                  background: "var(--bg1)",
                  flexShrink: 0,
                }}
              >
                <span style={{ width: 150, flexShrink: 0 }}>TARGET FILE</span>
                <span style={{ flex: 1 }}>SHANNON ENTROPY DISTRIBUTION</span>
                <span style={{ width: 34, textAlign: "right" }}>BITS</span>
                <span style={{ width: 100 }}>MIME TYPE</span>
                <span style={{ width: 60, textAlign: "right" }}>SIZE</span>
                <span style={{ width: 58, textAlign: "center" }}>RISK</span>
              </div>

              <div className="result-list">
                {displayedEntropy.map((r, i) => (
                  <ResultRow key={i} r={r} />
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
