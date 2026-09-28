import { useState, useEffect } from "react";
import { invoke } from "../lib/ipc/core";
import type { StorageStats, AutoPruneConfig, PruneResult } from "../types";

export type ThemeId = "cyber-purple" | "dark-void" | "github-dark" | "obsidian-matrix";

interface ThemeOption {
  id: ThemeId;
  name: string;
  tag: string;
  desc: string;
  previewBg: string;
  previewAccent: string;
  previewText: string;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatTimeAgo(ts: number | null): string {
  if (!ts) return "Never";
  const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${Math.floor(diffHours / 24)}d ago`;
}

const THEMES: ThemeOption[] = [
  {
    id: "cyber-purple",
    name: "Cyber Purple",
    tag: "SIGNATURE",
    desc: "Aegis-Guard classic deep ultraviolet neon with subtle scanlines",
    previewBg: "#0d0d16",
    previewAccent: "#8b5cf6",
    previewText: "#c4b5fd",
  },
  {
    id: "dark-void",
    name: "Dark Void",
    tag: "STEALTH OLED",
    desc: "True pitch-black 0% luminance canvas with crimson stealth accents",
    previewBg: "#040404",
    previewAccent: "#e11d48",
    previewText: "#ffffff",
  },
  {
    id: "github-dark",
    name: "GitHub Dark Modern",
    tag: "DEV REFINED",
    desc: "Subtle blue-gray slate background with GitHub sky accent & crisp borders",
    previewBg: "#161b22",
    previewAccent: "#58a6ff",
    previewText: "#f0f6fc",
  },
  {
    id: "obsidian-matrix",
    name: "Obsidian Matrix",
    tag: "TACTICAL",
    desc: "Deep tactical emerald green phosphor for high-stress security monitoring",
    previewBg: "#06140c",
    previewAccent: "#10b981",
    previewText: "#6ee7b7",
  },
];

export default function SettingsPanel() {
  const [currentTheme, setCurrentTheme] = useState<ThemeId>(() => {
    return (localStorage.getItem("aegis_theme") as ThemeId) || "cyber-purple";
  });

  // Permission toggles
  const [permEBPF, setPermEBPF] = useState(true);
  const [permKill, setPermKill] = useState(true);
  const [permNetAdmin, setPermNetAdmin] = useState(true);
  const [permAutoUpdate, setPermAutoUpdate] = useState(true);
  const [permTamperProof, setPermTamperProof] = useState(true);

  // Status message
  const [savedMsg, setSavedMsg] = useState(false);

  // Storage & Pruner Utility state
  const [storageStats, setStorageStats] = useState<StorageStats | null>(null);
  const [autoPruneConfig, setAutoPruneConfig] = useState<AutoPruneConfig | null>(null);
  const [isPruning, setIsPruning] = useState(false);
  const [pruneResult, setPruneResult] = useState<PruneResult | null>(null);
  const [showArtifacts, setShowArtifacts] = useState(false);

  // Editable pruning preferences
  const [retentionDays, setRetentionDays] = useState(7);
  const [maxDebugEntries, setMaxDebugEntries] = useState(100);
  const [cleanTempFiles, setCleanTempFiles] = useState(true);
  const [cleanSandbox, setCleanSandbox] = useState(true);
  const [cleanPcap, setCleanPcap] = useState(true);

  async function loadStorageInfo() {
    try {
      const stats = await invoke<StorageStats>("get_storage_stats");
      if (stats) setStorageStats(stats);
      const cfg = await invoke<AutoPruneConfig>("get_auto_prune_config");
      if (cfg) {
        setAutoPruneConfig(cfg);
        setRetentionDays(cfg.retention_days);
        setMaxDebugEntries(cfg.max_debug_entries);
        setCleanTempFiles(cfg.clean_temp_files);
        setCleanSandbox(cfg.clean_sandbox_artifacts);
        setCleanPcap(cfg.clean_pcap_buffers);
      }
    } catch (err) {
      console.error("Failed to load storage stats:", err);
    }
  }

  useEffect(() => {
    loadStorageInfo();
  }, []);

  async function handleRunPrune() {
    setIsPruning(true);
    try {
      const res = await invoke<PruneResult>("prune_logs", {
        older_than_ms: retentionDays * 24 * 60 * 60 * 1000,
        max_debug_entries: maxDebugEntries,
        clean_temp_files: cleanTempFiles,
        clean_sandbox: cleanSandbox,
        clean_pcap: cleanPcap,
      });
      setPruneResult(res);
      await loadStorageInfo();
      setTimeout(() => setPruneResult(null), 6000);
    } catch (err) {
      console.error("Prune failed:", err);
    } finally {
      setIsPruning(false);
    }
  }

  async function handleToggleAutoPrune(enabled: boolean) {
    try {
      const updated = await invoke<AutoPruneConfig>("update_auto_prune_config", {
        enabled,
        retention_days: retentionDays,
        max_debug_entries: maxDebugEntries,
        clean_temp_files: cleanTempFiles,
        clean_sandbox_artifacts: cleanSandbox,
        clean_pcap_buffers: cleanPcap,
      });
      setAutoPruneConfig(updated);
      await loadStorageInfo();
      setSavedMsg(true);
      setTimeout(() => setSavedMsg(false), 2000);
    } catch (err) {
      console.error("Failed to update auto prune config:", err);
    }
  }

  async function handleSavePruningConfig() {
    try {
      const updated = await invoke<AutoPruneConfig>("update_auto_prune_config", {
        enabled: autoPruneConfig?.enabled ?? true,
        retention_days: retentionDays,
        max_debug_entries: maxDebugEntries,
        clean_temp_files: cleanTempFiles,
        clean_sandbox_artifacts: cleanSandbox,
        clean_pcap_buffers: cleanPcap,
      });
      setAutoPruneConfig(updated);
      await loadStorageInfo();
      setSavedMsg(true);
      setTimeout(() => setSavedMsg(false), 2000);
    } catch (err) {
      console.error("Failed to save pruning preferences:", err);
    }
  }

  useEffect(() => {
    // Apply theme class to document body
    document.body.className = `theme-${currentTheme}`;
    localStorage.setItem("aegis_theme", currentTheme);
  }, [currentTheme]);

  const handleSelectTheme = (id: ThemeId) => {
    setCurrentTheme(id);
    setSavedMsg(true);
    setTimeout(() => setSavedMsg(false), 2000);
  };

  const handleSavePerms = () => {
    invoke("record_telemetry_event", {
      category: "SETTINGS_PERMISSIONS_UPDATE",
      action: "CAPABILITIES_RECONFIGURED",
      details: `eBPF:${permEBPF}, Kill:${permKill}, Net:${permNetAdmin}, Update:${permAutoUpdate}, Tamper:${permTamperProof}`,
    }).catch(() => {});

    setSavedMsg(true);
    setTimeout(() => setSavedMsg(false), 2500);
  };

  return (
    <div className="panel" id="settings-panel" style={{ overflowY: "auto", padding: 20 }}>
      {/* Top Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20, borderBottom: "1px solid var(--border)", paddingBottom: 14 }}>
        <div>
          <h1 style={{ fontSize: 16, fontWeight: 700, color: "var(--tx0)", letterSpacing: "0.06em", margin: 0 }}>
            SYSTEM CONFIGURATION & PREFERENCES
          </h1>
          <p style={{ fontSize: 11, color: "var(--tx2)", margin: "4px 0 0" }}>
            Kernel Capabilities, Security Policies & Premium Display Themes
          </p>
        </div>
        {savedMsg && (
          <span style={{ fontSize: 11, color: "var(--teall)", fontWeight: 700, animation: "fadeIn 200ms" }}>
            ✓ SETTINGS PERSISTED
          </span>
        )}
      </div>

      {/* Theme Customization Section */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
          <span style={{ fontSize: 14, color: "var(--vl)" }}>🎨</span>
          <h2 style={{ fontSize: 13, fontWeight: 700, color: "var(--tx0)", letterSpacing: "0.05em", margin: 0 }}>
            APPEARANCE & DISPLAY THEME
          </h2>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 14 }}>
          {THEMES.map((th) => {
            const isSelected = currentTheme === th.id;
            return (
              <div
                key={th.id}
                onClick={() => handleSelectTheme(th.id)}
                style={{
                  background: "var(--bg1)",
                  border: isSelected ? "2px solid var(--v)" : "1px solid var(--border)",
                  borderRadius: "var(--r)",
                  padding: 14,
                  cursor: "pointer",
                  display: "flex",
                  flexDirection: "column",
                  gap: 10,
                  transition: "all 140ms ease",
                  position: "relative",
                  boxShadow: isSelected ? "0 0 16px var(--v2)" : "none",
                }}
              >
                {/* Visual Swatch Pill */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div
                      style={{
                        width: 18,
                        height: 18,
                        borderRadius: "50%",
                        backgroundColor: th.previewBg,
                        border: `2px solid ${th.previewAccent}`,
                        boxShadow: `0 0 8px ${th.previewAccent}66`,
                      }}
                    />
                    <span style={{ fontSize: 12, fontWeight: 700, color: isSelected ? "var(--vl)" : "var(--tx0)" }}>
                      {th.name}
                    </span>
                  </div>
                  <span
                    style={{
                      fontSize: 8.5,
                      fontWeight: 700,
                      padding: "2px 6px",
                      borderRadius: 3,
                      background: isSelected ? "var(--v)" : "var(--bg3)",
                      color: isSelected ? "#fff" : "var(--tx2)",
                      letterSpacing: "0.05em",
                    }}
                  >
                    {th.tag}
                  </span>
                </div>

                <p style={{ margin: 0, fontSize: 10.5, color: "var(--tx2)", lineHeight: 1.45 }}>
                  {th.desc}
                </p>

                {/* Color swatches strip */}
                <div style={{ display: "flex", height: 6, borderRadius: 3, overflow: "hidden", marginTop: 4 }}>
                  <div style={{ flex: 2, background: th.previewBg }} />
                  <div style={{ flex: 1, background: th.previewAccent }} />
                  <div style={{ flex: 1, background: th.previewText }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Kernel Privileges & System Capabilities */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
          <span style={{ fontSize: 14, color: "var(--teall)" }}>🛡️</span>
          <h2 style={{ fontSize: 13, fontWeight: 700, color: "var(--tx0)", letterSpacing: "0.05em", margin: 0 }}>
            KERNEL HOOKS & SYSTEM PRIVILEGES
          </h2>
        </div>

        <div style={{ background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: "8px 16px" }}>
          {/* Privilege Row 1 */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 0", borderBottom: "1px solid var(--border)" }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tx0)" }}>
                Process Lineage & Memory Inspection (<code style={{ color: "var(--teall)", fontSize: 10 }}>CAP_SYS_PTRACE</code>)
              </div>
              <div style={{ fontSize: 10.5, color: "var(--tx2)", marginTop: 2 }}>
                Allows Aegis-Guard to attach non-invasive probes to inspect parent-child execution forks and environment tampering.
              </div>
            </div>
            <label className="switch" style={{ cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={permEBPF}
                onChange={(e) => setPermEBPF(e.target.checked)}
                style={{ accentColor: "var(--teal)" }}
              />
            </label>
          </div>

          {/* Privilege Row 2 */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 0", borderBottom: "1px solid var(--border)" }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tx0)" }}>
                Active Process Neutralization (<code style={{ color: "var(--redl)", fontSize: 10 }}>CAP_KILL</code>)
              </div>
              <div style={{ fontSize: 10.5, color: "var(--tx2)", marginTop: 2 }}>
                Permits sending immediate atomic <code style={{ color: "var(--redl)" }}>SIGKILL</code> / <code style={{ color: "var(--amberl)" }}>SIGSTOP</code> to rogue process trees exceeding confidence thresholds.
              </div>
            </div>
            <input
              type="checkbox"
              checked={permKill}
              onChange={(e) => setPermKill(e.target.checked)}
              style={{ accentColor: "var(--teal)" }}
            />
          </div>

          {/* Privilege Row 3 */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 0", borderBottom: "1px solid var(--border)" }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tx0)" }}>
                Raw Packet Filter & Null-Route (<code style={{ color: "var(--vl)", fontSize: 10 }}>CAP_NET_ADMIN / CAP_NET_RAW</code>)
              </div>
              <div style={{ fontSize: 10.5, color: "var(--tx2)", marginTop: 2 }}>
                Promiscuous socket monitoring, ARP spoofing detection, and automated iptables/nftables C2 IP blocking.
              </div>
            </div>
            <input
              type="checkbox"
              checked={permNetAdmin}
              onChange={(e) => setPermNetAdmin(e.target.checked)}
              style={{ accentColor: "var(--teal)" }}
            />
          </div>

          {/* Privilege Row 4 */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 0", borderBottom: "1px solid var(--border)" }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tx0)" }}>
                Cryptographic Tamper-Proof Audit Vault
              </div>
              <div style={{ fontSize: 10.5, color: "var(--tx2)", marginTop: 2 }}>
                BLAKE3 hash-chained journal entries in SQLite. Records cannot be silently modified or rolled back by malware.
              </div>
            </div>
            <input
              type="checkbox"
              checked={permTamperProof}
              onChange={(e) => setPermTamperProof(e.target.checked)}
              style={{ accentColor: "var(--teal)" }}
            />
          </div>

          {/* Privilege Row 5 */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 0" }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tx0)" }}>
                Automated Background Threat Intel & Patching
              </div>
              <div style={{ fontSize: 10.5, color: "var(--tx2)", marginTop: 2 }}>
                Periodically check for malware rule updates and engine patches with cryptographic signature verification.
              </div>
            </div>
            <input
              type="checkbox"
              checked={permAutoUpdate}
              onChange={(e) => setPermAutoUpdate(e.target.checked)}
              style={{ accentColor: "var(--teal)" }}
            />
          </div>
        </div>

        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 12 }}>
          <button
            className="action-btn"
            onClick={handleSavePerms}
            style={{ padding: "6px 18px", fontSize: 11 }}
          >
            APPLY PRIVILEGE CONFIGURATION
          </button>
        </div>
      </div>

      {/* Automated Application Directory Cleanup & Storage Pruner */}
      <div
        id="directory-cleaner-section"
        style={{
          background: "var(--bg1)",
          border: "1px solid var(--border)",
          borderRadius: "var(--r)",
          padding: 16,
          marginBottom: 24,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 15, color: "var(--vl)" }}>🧹</span>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: "var(--tx0)", letterSpacing: "0.05em" }}>
                AUTOMATED APPLICATION DIRECTORY CLEANUP & STORAGE PRUNER
              </div>
              <div style={{ fontSize: 10.5, color: "var(--tx2)", marginTop: 2 }}>
                Maintains a lean, pristine application directory by automatically purging outdated debug traces and temporary forensic dumps.
              </div>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {storageStats && (
              <span
                style={{
                  fontSize: 10,
                  fontWeight: 700,
                  padding: "3px 8px",
                  borderRadius: "var(--r)",
                  background: storageStats.total_reclaimable_bytes > 0 ? "rgba(139,92,246,0.15)" : "rgba(13,148,136,0.15)",
                  color: storageStats.total_reclaimable_bytes > 0 ? "var(--vl)" : "var(--teall)",
                  border: `1px solid ${storageStats.total_reclaimable_bytes > 0 ? "var(--v)" : "var(--teal)"}`,
                }}
              >
                {storageStats.total_reclaimable_bytes > 0
                  ? `${formatBytes(storageStats.total_reclaimable_bytes)} RECLAIMABLE`
                  : "DIRECTORY PRISTINE"}
              </span>
            )}
            <button
              id="btn-run-directory-prune"
              onClick={handleRunPrune}
              disabled={isPruning}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                padding: "6px 14px",
                background: "var(--v)",
                color: "#ffffff",
                border: "none",
                borderRadius: "var(--r)",
                fontSize: 11,
                fontWeight: 700,
                cursor: isPruning ? "not-allowed" : "pointer",
                transition: "all 150ms ease",
              }}
            >
              <span>{isPruning ? "CLEANING..." : "⚡ CLEAN DIRECTORY NOW"}</span>
            </button>
          </div>
        </div>

        {/* Pruning Result Alert */}
        {pruneResult && (
          <div
            style={{
              background: "rgba(13,148,136,0.15)",
              border: "1px solid var(--teal)",
              borderRadius: "var(--r)",
              padding: "10px 14px",
              marginBottom: 14,
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              fontSize: 11,
              color: "var(--teall)",
            }}
          >
            <div>
              <strong>Cleanup Succeeded:</strong> Removed {pruneResult.pruned_debug_entries} debug entries and {pruneResult.pruned_temp_files} temporary files. Reclaimed {formatBytes(pruneResult.freed_bytes)} of storage.
            </div>
            <span style={{ fontSize: 9.5, opacity: 0.8 }}>AUDIT RECORD DIGEST GENERATED</span>
          </div>
        )}

        {/* Storage Metrics Cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
          <div style={{ background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 10 }}>
            <div style={{ fontSize: 9.5, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
              Debug Trace Logs
            </div>
            <div style={{ fontSize: 15, fontWeight: 700, color: "var(--tx0)", marginTop: 4 }}>
              {storageStats ? storageStats.debug_entries_count : 0}{" "}
              <span style={{ fontSize: 10.5, fontWeight: 500, color: "var(--tx2)" }}>
                ({formatBytes(storageStats ? storageStats.debug_size_bytes : 0)})
              </span>
            </div>
            <div style={{ fontSize: 9.5, color: "var(--tx2)", marginTop: 2 }}>Suppressed FP entries</div>
          </div>

          <div style={{ background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 10 }}>
            <div style={{ fontSize: 9.5, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
              Temp & Forensic Files
            </div>
            <div style={{ fontSize: 15, fontWeight: 700, color: "var(--tx0)", marginTop: 4 }}>
              {storageStats ? storageStats.temp_files_count : 0}{" "}
              <span style={{ fontSize: 10.5, fontWeight: 500, color: "var(--tx2)" }}>
                ({formatBytes(storageStats ? storageStats.temp_files_bytes : 0)})
              </span>
            </div>
            <div style={{ fontSize: 9.5, color: "var(--tx2)", marginTop: 2 }}>Dumps, PCAP & scratch files</div>
          </div>

          <div style={{ background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 10 }}>
            <div style={{ fontSize: 9.5, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
              Reclaimable Space
            </div>
            <div style={{ fontSize: 15, fontWeight: 700, color: "var(--vl)", marginTop: 4 }}>
              {formatBytes(storageStats ? storageStats.total_reclaimable_bytes : 0)}
            </div>
            <div style={{ fontSize: 9.5, color: "var(--tx2)", marginTop: 2 }}>Stale buffers ready to purge</div>
          </div>

          <div style={{ background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 10 }}>
            <div style={{ fontSize: 9.5, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
              Last Maintenance
            </div>
            <div style={{ fontSize: 15, fontWeight: 700, color: "var(--tx0)", marginTop: 4 }}>
              {formatTimeAgo(storageStats?.last_pruned_ts ?? null)}
            </div>
            <div style={{ fontSize: 9.5, color: "var(--teall)", marginTop: 2 }}>
              {autoPruneConfig?.enabled ? "● Auto-Scheduler Active" : "○ Manual Mode"}
            </div>
          </div>
        </div>

        {/* Configuration Options */}
        <div style={{ background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 14, marginBottom: 12 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12, paddingBottom: 10, borderBottom: "1px solid var(--border)" }}>
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: "var(--tx0)" }}>
                Automated Background Pruner Routine
              </div>
              <div style={{ fontSize: 10, color: "var(--tx2)", marginTop: 2 }}>
                Periodically executes cleanup cycles in the background (every {autoPruneConfig?.interval_hours || 6} hours) to prevent disk clutter.
              </div>
            </div>
            <input
              id="chk-auto-prune-toggle"
              type="checkbox"
              checked={autoPruneConfig?.enabled ?? true}
              onChange={(e) => handleToggleAutoPrune(e.target.checked)}
              style={{ accentColor: "var(--v)", width: 16, height: 16, cursor: "pointer" }}
            />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
            <div>
              <label style={{ fontSize: 10, fontWeight: 600, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.05em", display: "block", marginBottom: 6 }}>
                Log & Dump Retention Window
              </label>
              <select
                id="select-retention-days"
                value={retentionDays}
                onChange={(e) => setRetentionDays(Number(e.target.value))}
                style={{
                  width: "100%",
                  padding: "6px 10px",
                  background: "var(--bg1)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--r)",
                  color: "var(--tx0)",
                  fontSize: 11,
                  fontFamily: "inherit",
                }}
              >
                <option value={1}>1 Day (Aggressive Developer Clean)</option>
                <option value={3}>3 Days (Fast Rotation)</option>
                <option value={7}>7 Days (Standard Production Balance)</option>
                <option value={14}>14 Days (Extended Forensic Window)</option>
                <option value={30}>30 Days (Compliance Archive Mode)</option>
              </select>
            </div>

            <div>
              <label style={{ fontSize: 10, fontWeight: 600, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.05em", display: "block", marginBottom: 6 }}>
                Debug Log Retention Cap
              </label>
              <select
                id="select-max-debug-entries"
                value={maxDebugEntries}
                onChange={(e) => setMaxDebugEntries(Number(e.target.value))}
                style={{
                  width: "100%",
                  padding: "6px 10px",
                  background: "var(--bg1)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--r)",
                  color: "var(--tx0)",
                  fontSize: 11,
                  fontFamily: "inherit",
                }}
              >
                <option value={25}>Keep Top 25 Entries</option>
                <option value={50}>Keep Top 50 Entries</option>
                <option value={100}>Keep Top 100 Entries (Default)</option>
                <option value={250}>Keep Top 250 Entries</option>
              </select>
            </div>
          </div>

          <div style={{ marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--border)" }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 8 }}>
              Clean Target Directories & File Categories
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, fontSize: 10.5 }}>
              <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", color: "var(--tx1)" }}>
                <input
                  type="checkbox"
                  checked={cleanTempFiles}
                  onChange={(e) => setCleanTempFiles(e.target.checked)}
                  style={{ accentColor: "var(--teal)" }}
                />
                <span>Stale Forensics Memory Dumps</span>
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", color: "var(--tx1)" }}>
                <input
                  type="checkbox"
                  checked={cleanSandbox}
                  onChange={(e) => setCleanSandbox(e.target.checked)}
                  style={{ accentColor: "var(--teal)" }}
                />
                <span>Sandbox Detonation Scratch Dumps</span>
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", color: "var(--tx1)" }}>
                <input
                  type="checkbox"
                  checked={cleanPcap}
                  onChange={(e) => setCleanPcap(e.target.checked)}
                  style={{ accentColor: "var(--teal)" }}
                />
                <span>Network PCAP Packet Buffers</span>
              </label>
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 12 }}>
            <button
              id="btn-toggle-artifacts-list"
              onClick={() => setShowArtifacts((v) => !v)}
              style={{
                background: "transparent",
                border: "none",
                color: "var(--vl)",
                fontSize: 10.5,
                fontWeight: 600,
                cursor: "pointer",
                padding: 0,
                display: "flex",
                alignItems: "center",
                gap: 4,
              }}
            >
              <span>{showArtifacts ? "▲ HIDE APPLICATION ARTIFACTS" : "▼ INSPECT TEMPORARY FILES (" + (storageStats?.temp_artifacts?.length || 0) + ")"}</span>
            </button>
            <button
              id="btn-save-pruning-config"
              onClick={handleSavePruningConfig}
              className="action-btn"
              style={{ padding: "5px 14px", fontSize: 10.5 }}
            >
              SAVE PRUNING POLICY
            </button>
          </div>
        </div>

        {/* Temporary Files Inspection Table */}
        {showArtifacts && storageStats && (
          <div
            style={{
              background: "var(--bg0)",
              border: "1px solid var(--border)",
              borderRadius: "var(--r)",
              overflow: "hidden",
              animation: "fadeIn 150ms ease",
            }}
          >
            <div
              style={{
                padding: "6px 12px",
                background: "var(--bg2)",
                borderBottom: "1px solid var(--border)",
                fontSize: 9.5,
                fontWeight: 700,
                color: "var(--tx2)",
                letterSpacing: "0.06em",
                textTransform: "uppercase",
                display: "grid",
                gridTemplateColumns: "1.8fr 1fr 90px 100px 90px",
              }}
            >
              <span>File Path</span>
              <span>Category</span>
              <span>Size</span>
              <span>Created</span>
              <span>Status</span>
            </div>
            <div style={{ maxHeight: 180, overflowY: "auto" }}>
              {storageStats.temp_artifacts.map((art) => (
                <div
                  key={art.id}
                  style={{
                    padding: "6px 12px",
                    borderBottom: "1px solid var(--border)",
                    display: "grid",
                    gridTemplateColumns: "1.8fr 1fr 90px 100px 90px",
                    alignItems: "center",
                    fontSize: 10.5,
                    fontFamily: "monospace",
                    color: "var(--tx1)",
                  }}
                >
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--tx0)" }} title={art.path}>
                    {art.path}
                  </span>
                  <span style={{ textTransform: "capitalize", color: "var(--tx2)" }}>
                    {art.category.replace("_", " ")}
                  </span>
                  <span>{formatBytes(art.size_bytes)}</span>
                  <span style={{ color: "var(--tx2)" }}>{formatTimeAgo(art.created_ts)}</span>
                  <span>
                    <span
                      style={{
                        padding: "2px 6px",
                        borderRadius: "var(--r)",
                        fontSize: 9,
                        fontWeight: 700,
                        background: art.stale ? "rgba(225,29,72,0.14)" : "rgba(13,148,136,0.14)",
                        color: art.stale ? "#f43f5e" : "var(--teall)",
                      }}
                    >
                      {art.stale ? "STALE" : "ACTIVE"}
                    </span>
                  </span>
                </div>
              ))}
              {storageStats.temp_artifacts.length === 0 && (
                <div style={{ padding: 14, textAlign: "center", fontSize: 11, color: "var(--tx2)" }}>
                  No temporary files or scratch dumps found. Application directory is completely clean.
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* System Integrity & Engine Information */}
      <div style={{ background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 14 }}>
        <div style={{ fontSize: 10, color: "var(--tx2)", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 6 }}>
          ENGINE STATUS & CREDENTIALS
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, fontSize: 11 }}>
          <div>
            <span style={{ color: "var(--tx2)" }}>Architecture: </span>
            <span style={{ color: "var(--tx0)", fontWeight: 600 }}>x86_64 / aarch64</span>
          </div>
          <div>
            <span style={{ color: "var(--tx2)" }}>Runtime IPC: </span>
            <span style={{ color: "var(--teall)", fontWeight: 600 }}>Tauri v2 IPC (Active)</span>
          </div>
          <div>
            <span style={{ color: "var(--tx2)" }}>Quarantine: </span>
            <span style={{ color: "var(--tx0)", fontWeight: 600 }}>/var/lib/aegis-guard/quarantine</span>
          </div>
        </div>
      </div>
    </div>
  );
}
