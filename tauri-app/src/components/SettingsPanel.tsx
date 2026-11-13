import { useState, useEffect } from "react";
import { invoke } from "../lib/ipc/core";
import type {
  StorageStats,
  AutoPruneConfig,
  PruneResult,
  SystemSettings,
  RuntimeInfo,
} from "../types";

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
    name: "Slate Ultraviolet",
    tag: "DEFAULT",
    desc: "Balanced dark slate workspace with subtle ultraviolet focus accents.",
    previewBg: "#0e1118",
    previewAccent: "#7c3aed",
    previewText: "#b49eff",
  },
  {
    id: "dark-void",
    name: "Dark Void",
    tag: "OLED STEALTH",
    desc: "High-contrast deep obsidian surface with crisp crimson alert accents.",
    previewBg: "#08080b",
    previewAccent: "#e11d48",
    previewText: "#fafafa",
  },
  {
    id: "github-dark",
    name: "GitHub Dark",
    tag: "DEVELOPER",
    desc: "Familiar blue-gray slate palette with crisp structural 1px borders.",
    previewBg: "#161b22",
    previewAccent: "#2f81f7",
    previewText: "#f0f6fc",
  },
  {
    id: "obsidian-matrix",
    name: "Obsidian Matrix",
    tag: "TACTICAL",
    desc: "Deep tactical emerald console optimized for long monitoring shifts.",
    previewBg: "#09150e",
    previewAccent: "#10b981",
    previewText: "#a7f3d0",
  },
];

export default function SettingsPanel() {
  const [currentTheme, setCurrentTheme] = useState<ThemeId>(() => {
    return (localStorage.getItem("aegis_theme") as ThemeId) || "cyber-purple";
  });

  // Real persisted system capability & AV toggles
  const [permEBPF, setPermEBPF] = useState(true);
  const [permKill, setPermKill] = useState(true);
  const [permNetAdmin, setPermNetAdmin] = useState(true);
  const [permAutoUpdate, setPermAutoUpdate] = useState(true);
  const [permTamperProof, setPermTamperProof] = useState(true);
  const [permRealtimeAv, setPermRealtimeAv] = useState(true);
  const [savingPerms, setSavingPerms] = useState(false);

  const [runtimeInfo, setRuntimeInfo] = useState<RuntimeInfo | null>(null);
  const [statusNotice, setStatusNotice] = useState<{ text: string; isError?: boolean } | null>(null);

  // Storage & Pruner Utility state
  const [storageStats, setStorageStats] = useState<StorageStats | null>(null);
  const [autoPruneConfig, setAutoPruneConfig] = useState<AutoPruneConfig | null>(null);
  const [isPruning, setIsPruning] = useState(false);
  const [pruneResult, setPruneResult] = useState<PruneResult | null>(null);
  const [showArtifacts, setShowArtifacts] = useState(false);

  const [retentionDays, setRetentionDays] = useState(7);
  const [maxDebugEntries, setMaxDebugEntries] = useState(100);
  const [cleanTempFiles, setCleanTempFiles] = useState(true);
  const [cleanSandbox, setCleanSandbox] = useState(true);
  const [cleanPcap, setCleanPcap] = useState(true);

  const flashNotice = (text: string, isError = false) => {
    setStatusNotice({ text, isError });
    setTimeout(() => setStatusNotice(null), 3000);
  };

  async function loadAllSettings() {
    try {
      const [stats, cfg, sysCfg, rtInfo] = await Promise.all([
        invoke<StorageStats>("get_storage_stats"),
        invoke<AutoPruneConfig>("get_auto_prune_config"),
        invoke<SystemSettings>("get_system_settings"),
        invoke<RuntimeInfo>("get_runtime_info"),
      ]);
      if (stats) setStorageStats(stats);
      if (cfg) {
        setAutoPruneConfig(cfg);
        setRetentionDays(cfg.retention_days);
        setMaxDebugEntries(cfg.max_debug_entries);
        setCleanTempFiles(cfg.clean_temp_files);
        setCleanSandbox(cfg.clean_sandbox_artifacts);
        setCleanPcap(cfg.clean_pcap_buffers);
      }
      if (sysCfg) {
        setPermEBPF(Boolean(sysCfg.process_inspection_enabled));
        setPermKill(Boolean(sysCfg.active_kill_enabled));
        setPermNetAdmin(Boolean(sysCfg.net_admin_enabled));
        setPermTamperProof(Boolean(sysCfg.tamper_proof_audit));
        setPermAutoUpdate(Boolean(sysCfg.auto_update_enabled));
        setPermRealtimeAv(Boolean(sysCfg.realtime_av_enabled));
      }
      if (rtInfo) setRuntimeInfo(rtInfo);
    } catch (err) {
      console.error("Failed to load settings:", err);
    }
  }

  useEffect(() => {
    loadAllSettings();
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
      await loadAllSettings();
      setTimeout(() => setPruneResult(null), 6000);
    } catch (err: any) {
      flashNotice(`Prune failed: ${err?.message || String(err)}`, true);
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
      await loadAllSettings();
      flashNotice("Auto-pruner schedule saved");
    } catch (err: any) {
      flashNotice(`Failed to update pruner: ${err?.message || String(err)}`, true);
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
      await loadAllSettings();
      flashNotice("Storage pruning policy persisted");
    } catch (err: any) {
      flashNotice(`Failed to save policy: ${err?.message || String(err)}`, true);
    }
  }

  useEffect(() => {
    document.body.className = `theme-${currentTheme}`;
    localStorage.setItem("aegis_theme", currentTheme);
  }, [currentTheme]);

  const handleSelectTheme = (id: ThemeId) => {
    setCurrentTheme(id);
    flashNotice("Theme applied and saved");
  };

  const handleSavePerms = async () => {
    setSavingPerms(true);
    try {
      const saved = await invoke<SystemSettings>("update_system_settings", {
        process_inspection_enabled: permEBPF,
        active_kill_enabled: permKill,
        net_admin_enabled: permNetAdmin,
        tamper_proof_audit: permTamperProof,
        auto_update_enabled: permAutoUpdate,
        realtime_av_enabled: permRealtimeAv,
      });
      if (saved) {
        setPermEBPF(saved.process_inspection_enabled);
        setPermKill(saved.active_kill_enabled);
        setPermNetAdmin(saved.net_admin_enabled);
        setPermTamperProof(saved.tamper_proof_audit);
        setPermAutoUpdate(saved.auto_update_enabled);
        setPermRealtimeAv(saved.realtime_av_enabled);
      }
      flashNotice("Security & capability configuration persisted to disk");
    } catch (err: any) {
      flashNotice(`Failed to persist configuration: ${err?.message || String(err)}`, true);
    } finally {
      setSavingPerms(false);
    }
  };

  return (
    <div className="panel" id="settings-panel" style={{ overflowY: "auto", padding: 20 }}>
      {/* Top Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: 20,
          borderBottom: "1px solid var(--border)",
          paddingBottom: 14,
        }}
      >
        <div>
          <h1 style={{ fontSize: 16, fontWeight: 700, color: "var(--tx0)", margin: 0 }}>
            System Configuration &amp; Preferences
          </h1>
          <p style={{ fontSize: 12, color: "var(--tx2)", margin: "4px 0 0" }}>
            Kernel Capabilities, Real-Time Antivirus Policies, Storage Hygiene &amp; Display Themes
          </p>
        </div>
        {statusNotice && (
          <span
            style={{
              fontSize: 12,
              color: statusNotice.isError ? "var(--redl)" : "var(--teall)",
              fontWeight: 600,
            }}
          >
            {statusNotice.isError ? "✕ " : "✓ "}
            {statusNotice.text}
          </span>
        )}
      </div>

      {/* Theme Customization Section */}
      <div style={{ marginBottom: 26 }}>
        <h2 style={{ fontSize: 13, fontWeight: 700, color: "var(--tx0)", marginBottom: 12 }}>
          Appearance &amp; Workspace Theme
        </h2>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 12 }}>
          {THEMES.map((th) => {
            const isSelected = currentTheme === th.id;
            return (
              <button
                key={th.id}
                type="button"
                onClick={() => handleSelectTheme(th.id)}
                style={{
                  background: "var(--bg1)",
                  border: isSelected ? "2px solid var(--v)" : "1px solid var(--border)",
                  borderRadius: "var(--r)",
                  padding: 14,
                  textAlign: "left",
                  display: "flex",
                  flexDirection: "column",
                  gap: 8,
                  transition: "border-color 120ms, background 120ms",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", width: "100%" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div
                      style={{
                        width: 16,
                        height: 16,
                        borderRadius: "50%",
                        backgroundColor: th.previewBg,
                        border: `2px solid ${th.previewAccent}`,
                      }}
                    />
                    <span style={{ fontSize: 13, fontWeight: 600, color: isSelected ? "var(--vl)" : "var(--tx0)" }}>
                      {th.name}
                    </span>
                  </div>
                  <span
                    style={{
                      fontSize: 9,
                      fontFamily: "var(--mono)",
                      fontWeight: 600,
                      padding: "2px 6px",
                      borderRadius: 4,
                      background: isSelected ? "var(--v)" : "var(--bg2)",
                      color: isSelected ? "#fff" : "var(--tx2)",
                    }}
                  >
                    {th.tag}
                  </span>
                </div>

                <p style={{ margin: 0, fontSize: 11.5, color: "var(--tx2)", lineHeight: 1.45 }}>
                  {th.desc}
                </p>

                <div style={{ display: "flex", height: 5, width: "100%", borderRadius: 3, overflow: "hidden", marginTop: 2 }}>
                  <div style={{ flex: 2, background: th.previewBg }} />
                  <div style={{ flex: 1, background: th.previewAccent }} />
                  <div style={{ flex: 1, background: th.previewText }} />
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Kernel Privileges & Antivirus Capabilities */}
      <div style={{ marginBottom: 26 }}>
        <h2 style={{ fontSize: 13, fontWeight: 700, color: "var(--tx0)", marginBottom: 12 }}>
          Kernel Hooks, Antivirus &amp; Enforcement Policies
        </h2>

        <div style={{ background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: "4px 16px" }}>
          {[
            {
              id: "chk-perm-av",
              title: "Real-Time Process & Binary Antivirus",
              badge: "LIVE /PROC AV",
              badgeColor: "var(--teall)",
              desc: "Inspects running /proc executables and command lines against SHA-256 threat intel feeds and byte signatures.",
              checked: permRealtimeAv,
              onChange: setPermRealtimeAv,
            },
            {
              id: "chk-perm-ebpf",
              title: "Process Lineage & Behavioral Rules",
              badge: "CAP_SYS_PTRACE",
              badgeColor: "var(--vl)",
              desc: "Evaluates parent-child execution trees, volatile path launches, and obfuscated command pipelines.",
              checked: permEBPF,
              onChange: setPermEBPF,
            },
            {
              id: "chk-perm-kill",
              title: "Active Process Neutralization",
              badge: "CAP_KILL",
              badgeColor: "var(--redl)",
              desc: "Permits sending SIGTERM/SIGSTOP signals to terminate or freeze confirmed malicious processes.",
              checked: permKill,
              onChange: setPermKill,
            },
            {
              id: "chk-perm-net",
              title: "Network Socket & Packet IDS Filtering",
              badge: "CAP_NET_ADMIN",
              badgeColor: "var(--vl)",
              desc: "Enables live /proc/net socket inspection, ARP MAC collision alerts, and Go packet daemon monitoring.",
              checked: permNetAdmin,
              onChange: setPermNetAdmin,
            },
            {
              id: "chk-perm-tamper",
              title: "Cryptographic Tamper-Proof Audit Chain",
              badge: runtimeInfo?.audit_hash_algo || "SHA-256",
              badgeColor: "var(--teall)",
              desc: "Links every remediation and configuration change into a verifiable cryptographic digest chain.",
              checked: permTamperProof,
              onChange: setPermTamperProof,
            },
            {
              id: "chk-perm-update",
              title: "Automated Threat Intel & Signature Updates",
              badge: "FEED SYNC",
              badgeColor: "var(--tx1)",
              desc: "Allows background signature feed checks and rule database reloads.",
              checked: permAutoUpdate,
              onChange: setPermAutoUpdate,
            },
          ].map((row, idx, arr) => (
            <label
              key={row.id}
              htmlFor={row.id}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 16,
                padding: "12px 0",
                borderBottom: idx < arr.length - 1 ? "1px solid var(--border-dim)" : "none",
                cursor: "pointer",
              }}
            >
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, fontWeight: 600, color: "var(--tx0)" }}>
                  <span>{row.title}</span>
                  <code style={{ color: row.badgeColor, fontSize: 10 }}>{row.badge}</code>
                </div>
                <div style={{ fontSize: 11.5, color: "var(--tx2)", marginTop: 2 }}>{row.desc}</div>
              </div>
              <input
                id={row.id}
                type="checkbox"
                checked={row.checked}
                onChange={(e) => row.onChange(e.target.checked)}
                style={{ accentColor: "var(--teal)", width: 16, height: 16, cursor: "pointer", flexShrink: 0 }}
              />
            </label>
          ))}
        </div>

        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 12 }}>
          <button
            id="btn-save-system-settings"
            type="button"
            className="action-btn"
            disabled={savingPerms}
            onClick={handleSavePerms}
          >
            {savingPerms ? "Saving configuration…" : "Apply Configuration"}
          </button>
        </div>
      </div>

      {/* Storage Hygiene & Pruner */}
      <div
        id="directory-cleaner-section"
        style={{
          background: "var(--bg1)",
          border: "1px solid var(--border)",
          borderRadius: "var(--r)",
          padding: 16,
          marginBottom: 20,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14, flexWrap: "wrap", gap: 10 }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "var(--tx0)" }}>
              Storage Hygiene &amp; Forensic Log Pruner
            </div>
            <div style={{ fontSize: 11.5, color: "var(--tx2)", marginTop: 2 }}>
              Purges expired debug trace logs, quarantine artifacts, and temporary sandbox workspaces.
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {storageStats && (
              <span className="pstat" style={{ color: storageStats.total_reclaimable_bytes > 0 ? "var(--vl)" : "var(--teall)" }}>
                {storageStats.total_reclaimable_bytes > 0
                  ? `${formatBytes(storageStats.total_reclaimable_bytes)} reclaimable`
                  : "Storage clean"}
              </span>
            )}
            <button
              id="btn-run-directory-prune"
              type="button"
              className="btn-primary"
              onClick={handleRunPrune}
              disabled={isPruning}
            >
              {isPruning ? "Cleaning…" : "Clean Storage Now"}
            </button>
          </div>
        </div>

        {pruneResult && (
          <div
            style={{
              background: "rgba(13,148,136,0.12)",
              border: "1px solid var(--teal)",
              borderRadius: "var(--r)",
              padding: "10px 14px",
              marginBottom: 14,
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              fontSize: 12,
              color: "var(--teall)",
            }}
          >
            <span>
              <strong>Cleanup complete:</strong> Removed {pruneResult.pruned_debug_entries} trace entries and{" "}
              {pruneResult.pruned_temp_files} temporary files ({formatBytes(pruneResult.freed_bytes)} reclaimed).
            </span>
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 10, marginBottom: 14 }}>
          <div style={{ background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 12 }}>
            <div style={{ fontSize: 10, color: "var(--tx2)", textTransform: "uppercase", fontWeight: 600 }}>Trace Logs</div>
            <div className="mono" style={{ fontSize: 15, fontWeight: 700, color: "var(--tx0)", marginTop: 4 }}>
              {storageStats ? storageStats.debug_entries_count : 0}{" "}
              <span style={{ fontSize: 11, fontWeight: 400, color: "var(--tx2)" }}>
                ({formatBytes(storageStats ? storageStats.debug_size_bytes : 0)})
              </span>
            </div>
          </div>

          <div style={{ background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 12 }}>
            <div style={{ fontSize: 10, color: "var(--tx2)", textTransform: "uppercase", fontWeight: 600 }}>Quarantine &amp; Temp</div>
            <div className="mono" style={{ fontSize: 15, fontWeight: 700, color: "var(--tx0)", marginTop: 4 }}>
              {storageStats ? storageStats.temp_files_count : 0}{" "}
              <span style={{ fontSize: 11, fontWeight: 400, color: "var(--tx2)" }}>
                ({formatBytes(storageStats ? storageStats.temp_files_bytes : 0)})
              </span>
            </div>
          </div>

          <div style={{ background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 12 }}>
            <div style={{ fontSize: 10, color: "var(--tx2)", textTransform: "uppercase", fontWeight: 600 }}>Reclaimable</div>
            <div className="mono" style={{ fontSize: 15, fontWeight: 700, color: "var(--vl)", marginTop: 4 }}>
              {formatBytes(storageStats ? storageStats.total_reclaimable_bytes : 0)}
            </div>
          </div>

          <div style={{ background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 12 }}>
            <div style={{ fontSize: 10, color: "var(--tx2)", textTransform: "uppercase", fontWeight: 600 }}>Last Prune</div>
            <div className="mono" style={{ fontSize: 15, fontWeight: 700, color: "var(--tx0)", marginTop: 4 }}>
              {formatTimeAgo(storageStats?.last_pruned_ts ?? null)}
            </div>
          </div>
        </div>

        <div style={{ background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 14 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12, paddingBottom: 10, borderBottom: "1px solid var(--border-dim)" }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tx0)" }}>
                Automated Background Pruner
              </div>
              <div style={{ fontSize: 11, color: "var(--tx2)", marginTop: 2 }}>
                Runs cleanup cycles every {autoPruneConfig?.interval_hours || 6} hours.
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
              <label htmlFor="select-retention-days" style={{ fontSize: 11, fontWeight: 600, color: "var(--tx2)", display: "block", marginBottom: 6 }}>
                Log Retention Window
              </label>
              <select
                id="select-retention-days"
                className="filter-select"
                value={retentionDays}
                onChange={(e) => setRetentionDays(Number(e.target.value))}
                style={{ width: "100%" }}
              >
                <option value={1}>1 Day (Developer Clean)</option>
                <option value={3}>3 Days</option>
                <option value={7}>7 Days (Balanced)</option>
                <option value={14}>14 Days (Extended Forensics)</option>
                <option value={30}>30 Days (Archive)</option>
              </select>
            </div>

            <div>
              <label htmlFor="select-max-debug-entries" style={{ fontSize: 11, fontWeight: 600, color: "var(--tx2)", display: "block", marginBottom: 6 }}>
                Suppressed Trace Cap
              </label>
              <select
                id="select-max-debug-entries"
                className="filter-select"
                value={maxDebugEntries}
                onChange={(e) => setMaxDebugEntries(Number(e.target.value))}
                style={{ width: "100%" }}
              >
                <option value={25}>25 Entries</option>
                <option value={50}>50 Entries</option>
                <option value={100}>100 Entries (Default)</option>
                <option value={250}>250 Entries</option>
              </select>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10, marginTop: 12, fontSize: 11.5 }}>
            <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", color: "var(--tx1)" }}>
              <input type="checkbox" checked={cleanTempFiles} onChange={(e) => setCleanTempFiles(e.target.checked)} style={{ accentColor: "var(--teal)" }} />
              <span>Quarantine &amp; Temp Files</span>
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", color: "var(--tx1)" }}>
              <input type="checkbox" checked={cleanSandbox} onChange={(e) => setCleanSandbox(e.target.checked)} style={{ accentColor: "var(--teal)" }} />
              <span>Sandbox Scratch Workspaces</span>
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", color: "var(--tx1)" }}>
              <input type="checkbox" checked={cleanPcap} onChange={(e) => setCleanPcap(e.target.checked)} style={{ accentColor: "var(--teal)" }} />
              <span>Packet Buffers</span>
            </label>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--border-dim)" }}>
            <button
              id="btn-toggle-artifacts-list"
              type="button"
              onClick={() => setShowArtifacts((v) => !v)}
              style={{ color: "var(--vl)", fontSize: 11, fontWeight: 600 }}
            >
              {showArtifacts ? "Hide artifact files" : `Inspect artifacts (${storageStats?.temp_artifacts?.length || 0})`}
            </button>
            <button
              id="btn-save-pruning-config"
              type="button"
              onClick={handleSavePruningConfig}
              className="sm-btn sm-btn--active"
            >
              Save Pruning Policy
            </button>
          </div>
        </div>

        {showArtifacts && storageStats && (
          <div style={{ marginTop: 12, background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)", overflow: "hidden" }}>
            <div style={{ maxHeight: 180, overflowY: "auto" }}>
              {storageStats.temp_artifacts.map((art) => (
                <div
                  key={art.id}
                  className="mono"
                  style={{
                    padding: "7px 12px",
                    borderBottom: "1px solid var(--border-dim)",
                    display: "grid",
                    gridTemplateColumns: "1.8fr 1fr 90px 100px 80px",
                    alignItems: "center",
                    fontSize: 11,
                    color: "var(--tx1)",
                  }}
                >
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--tx0)" }} title={art.path}>
                    {art.path}
                  </span>
                  <span style={{ color: "var(--tx2)" }}>{art.category.replace("_", " ")}</span>
                  <span>{formatBytes(art.size_bytes)}</span>
                  <span style={{ color: "var(--tx2)" }}>{formatTimeAgo(art.created_ts)}</span>
                  <span style={{ color: art.stale ? "var(--redl)" : "var(--teall)", fontWeight: 600 }}>
                    {art.stale ? "STALE" : "ACTIVE"}
                  </span>
                </div>
              ))}
              {storageStats.temp_artifacts.length === 0 && (
                <div style={{ padding: 14, textAlign: "center", fontSize: 12, color: "var(--tx2)" }}>
                  No quarantined or temporary artifacts stored.
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Live Engine & Runtime Diagnostics */}
      <div style={{ background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 14 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: "var(--tx2)", textTransform: "uppercase", marginBottom: 10 }}>
          Runtime Environment
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 10, fontSize: 12 }}>
          <div>
            <span style={{ color: "var(--tx2)" }}>Version: </span>
            <span className="mono" style={{ color: "var(--tx0)", fontWeight: 600 }}>
              v{runtimeInfo?.app_version || "1.2.0"} ({runtimeInfo?.engine_version || "4.6.0"})
            </span>
          </div>
          <div>
            <span style={{ color: "var(--tx2)" }}>Host OS / Arch: </span>
            <span className="mono" style={{ color: "var(--tx0)", fontWeight: 600 }}>
              {runtimeInfo ? `${runtimeInfo.platform} / ${runtimeInfo.arch}` : "Linux / x64"}
            </span>
          </div>
          <div>
            <span style={{ color: "var(--tx2)" }}>IPC Transport: </span>
            <span className="mono" style={{ color: "var(--teall)", fontWeight: 600 }}>
              {runtimeInfo?.transport || "HTTP + SSE IPC"}
            </span>
          </div>
          <div>
            <span style={{ color: "var(--tx2)" }}>Audit Digest: </span>
            <span className="mono" style={{ color: "var(--vl)", fontWeight: 600 }}>
              {runtimeInfo?.audit_hash_algo || "SHA-256"}
            </span>
          </div>
          <div>
            <span style={{ color: "var(--tx2)" }}>Go Packet Bridge: </span>
            <span className="mono" style={{ color: runtimeInfo?.go_bridge_connected ? "var(--teall)" : "var(--tx1)", fontWeight: 600 }}>
              {runtimeInfo?.go_bridge_connected ? "Connected (:50053)" : "/proc/net fallback active"}
            </span>
          </div>
          <div>
            <span style={{ color: "var(--tx2)" }}>Quarantine Vault: </span>
            <span className="mono" style={{ color: "var(--tx0)", fontWeight: 600 }}>
              {runtimeInfo?.quarantine_dir || "/tmp/aegis_guard_data/quarantine"}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
