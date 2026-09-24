import { useState, useEffect } from "react";
import { invoke } from "../lib/ipc/core";
import type { DebugEntry, PruneResult, StorageStats } from "../types";
import RuleBadge from "./RuleBadge";

export default function DebugLogPanel() {
  const [entries, setEntries] = useState<DebugEntry[]>([]);
  const [offset, setOffset] = useState(0);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [isPruning, setIsPruning] = useState(false);
  const [pruneResult, setPruneResult] = useState<PruneResult | null>(null);
  const [storageStats, setStorageStats] = useState<StorageStats | null>(null);
  const PAGE = 50;

  async function load(off: number) {
    try {
      const rows = await invoke<DebugEntry[]>("list_debug_log", { limit: PAGE, offset: off });
      if (Array.isArray(rows)) {
        setEntries((prev) => (off === 0 ? rows : [...prev, ...rows]));
        setOffset(off + rows.length);
      }
      const stats = await invoke<StorageStats>("get_storage_stats");
      if (stats) setStorageStats(stats);
    } catch (err) {
      console.error("Failed to load debug log:", err);
    }
  }

  useEffect(() => {
    load(0);
  }, []);

  async function handleQuickPrune() {
    setIsPruning(true);
    try {
      const res = await invoke<PruneResult>("prune_logs", {
        clean_temp_files: true,
        max_debug_entries: 25,
      });
      setPruneResult(res);
      await load(0);
      setTimeout(() => setPruneResult(null), 4500);
    } catch (err) {
      console.error("Failed to prune logs:", err);
    } finally {
      setIsPruning(false);
    }
  }

  async function handleTestSuppression() {
    try {
      await invoke("simulate_suppression_test");
      await load(0);
    } catch (e) {
      console.error(e);
    }
  }

  const filtered = entries.filter((e) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      e.process.toLowerCase().includes(q) ||
      e.rule.toLowerCase().includes(q) ||
      e.note.toLowerCase().includes(q) ||
      (e.suppression_reason || "").toLowerCase().includes(q) ||
      (e.category || "").toLowerCase().includes(q)
    );
  });

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">SUPPRESSED EVENTS & FALSE-POSITIVE AUDIT</span>
        <span className="pstat">{entries.length} FILTERED FROM ALERTS</span>
        {storageStats && (
          <span className="pstat" style={{ color: "var(--vl)", borderColor: "var(--vd)" }}>
            LOG SIZE: {(storageStats.debug_size_bytes / 1024).toFixed(1)} KB
          </span>
        )}
        <span className="pstat" style={{ color: "var(--teall)", borderColor: "var(--teal)" }}>
          AUTO-TUNED SENSITIVITY
        </span>
        <div className="toolbar-right" style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button
            onClick={handleTestSuppression}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 5,
              padding: "4px 10px",
              background: "rgba(13,148,136,0.15)",
              border: "1px solid var(--teal)",
              borderRadius: "var(--r)",
              color: "var(--teall)",
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: "0.05em",
              cursor: "pointer",
            }}
            title="Simulate benign developer activity suppressed by smart sensitivity filter"
          >
            <span>⚡ TEST DEV SUPPRESSION</span>
          </button>
          <button
            id="btn-quick-prune-debug-logs"
            onClick={handleQuickPrune}
            disabled={isPruning}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 5,
              padding: "4px 10px",
              background: "rgba(124,58,237,0.15)",
              border: "1px solid var(--v)",
              borderRadius: "var(--r)",
              color: "var(--vl)",
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: "0.05em",
              cursor: isPruning ? "not-allowed" : "pointer",
              transition: "all 120ms ease",
            }}
            title="Prune outdated debug logs and temporary files"
          >
            <span>{isPruning ? "⚡ PRUNING..." : "🧹 PRUNE STALE LOGS"}</span>
          </button>
          <input
            className="search-input"
            type="text"
            placeholder="Search suppressed events..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {pruneResult && (
        <div
          style={{
            background: "rgba(13,148,136,0.14)",
            borderBottom: "1px solid var(--teal)",
            padding: "8px 16px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            fontSize: 11,
            color: "var(--teall)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span>✓</span>
            <span>
              <strong>Storage Maintenance Complete:</strong> Pruned {pruneResult.pruned_debug_entries} debug entries and {pruneResult.pruned_temp_files} temporary files. Reclaimed {(pruneResult.freed_bytes / 1024).toFixed(1)} KB.
            </span>
          </div>
          <span style={{ fontSize: 9.5, color: "var(--tx2)" }}>DIRECTORY CLEAN & OPTIMIZED</span>
        </div>
      )}

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "80px 120px 70px 140px 120px 1fr 60px",
          padding: "5px 14px",
          fontSize: 9,
          color: "var(--tx2)",
          letterSpacing: "0.08em",
          textTransform: "uppercase",
          borderBottom: "1px solid var(--border)",
          background: "var(--bg1)",
          flexShrink: 0,
        }}
      >
        <span>RULE</span>
        <span>PROCESS</span>
        <span>PID</span>
        <span>CATEGORY</span>
        <span>SCORE ADJUSTMENT</span>
        <span>BENIGN SUPPRESSION REASON</span>
        <span style={{ textAlign: "right" }}>TIME</span>
      </div>

      <div className="debug-list">
        {filtered.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon">⊘</span>
            NO SUPPRESSED ENTRIES MATCHING FILTER
          </div>
        ) : (
          filtered.map((e) => {
            const isExpanded = expandedId === e.id;
            return (
              <div
                key={e.id}
                style={{
                  borderBottom: "1px solid rgba(37,37,50,.45)",
                  background: isExpanded ? "var(--bg3)" : "transparent",
                }}
              >
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "80px 120px 70px 140px 120px 1fr 60px",
                    padding: "7px 14px",
                    alignItems: "center",
                    gap: 8,
                    cursor: "pointer",
                  }}
                  onClick={() => setExpandedId(isExpanded ? null : e.id)}
                >
                  <span>
                    <RuleBadge rule={e.rule} />
                  </span>
                  <span className="debug-process">{e.process}</span>
                  <span className="debug-pid">PID {e.pid}</span>
                  <span
                    style={{
                      fontSize: 9,
                      color: "var(--vl)",
                      padding: "1px 5px",
                      background: "rgba(124,58,237,.08)",
                      borderRadius: 2,
                      width: "fit-content",
                    }}
                  >
                    {e.category || "General Context"}
                  </span>
                  <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                    <span style={{ fontSize: 9, color: "var(--tx2)", textDecoration: "line-through" }}>
                      {e.original_score ?? 60}
                    </span>
                    <span style={{ fontSize: 9, color: "var(--tx2)" }}>➔</span>
                    <span style={{ fontSize: 9, fontWeight: 700, color: "var(--teall)" }}>
                      {e.adjusted_score ?? 10} pts
                    </span>
                  </div>
                  <span
                    style={{
                      fontSize: 10,
                      color: "var(--tx1)",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {e.suppression_reason || e.note}
                  </span>
                  <span className="debug-ts" style={{ textAlign: "right" }}>
                    {new Date(e.ts).toLocaleTimeString("en-GB", { hour12: false })}
                  </span>
                </div>

                {isExpanded && (
                  <div
                    style={{
                      padding: "8px 18px 12px 24px",
                      background: "rgba(7,7,10,.75)",
                      borderTop: "1px solid var(--border)",
                      display: "flex",
                      flexDirection: "column",
                      gap: 6,
                    }}
                  >
                    <div className="meta-row">
                      <span className="meta-label">SUMMARY</span>
                      <span className="meta-val">{e.note}</span>
                    </div>

                    {e.suppression_reason && (
                      <div
                        style={{
                          padding: "6px 10px",
                          background: "rgba(13,148,136,.08)",
                          borderLeft: "2px solid var(--teal)",
                          fontSize: 10,
                          color: "var(--teall)",
                          lineHeight: 1.5,
                        }}
                      >
                        <strong>Auto-Tuning Rationale:</strong> {e.suppression_reason} (Prevents false critical/high alarm)
                      </div>
                    )}

                    <div className="meta-row">
                      <span className="meta-label">TIMESTAMP</span>
                      <span className="meta-val">{new Date(e.ts).toISOString()}</span>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
        {entries.length >= PAGE && (
          <button className="load-more" onClick={() => load(offset)}>
            LOAD MORE
          </button>
        )}
      </div>
    </div>
  );
}
