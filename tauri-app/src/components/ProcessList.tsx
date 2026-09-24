import { useState, useMemo } from "react";
import { useProcessStore } from "../store/processStore";
import ProcessRow from "./ProcessRow";
import { invoke } from "../lib/ipc/core";
import type { ProcessNode } from "../types";

export default function ProcessList() {
  const { store } = useProcessStore();
  const [filter, setFilter] = useState("");
  const [anomOnly, setAnomOnly] = useState(false);
  const [simulating, setSimulating] = useState(false);

  async function handleSimulate() {
    setSimulating(true);
    try {
      await invoke("simulate_suspicious_process");
    } catch (e) {
      console.error(e);
    } finally {
      setTimeout(() => setSimulating(false), 500);
    }
  }

  const roots = useMemo(() => {
    const all = Array.from(store.nodes.values());
    const pids = new Set(all.map((n) => n.pid));
    let top = all.filter((n) => !pids.has(n.ppid));
    top.sort((a, b) => (a.flagged ? -1 : 0) - (b.flagged ? -1 : 0) || a.pid - b.pid);
    if (filter.trim()) {
      const q = filter.toLowerCase();
      const match = (n: ProcessNode): boolean =>
        n.name.toLowerCase().includes(q) ||
        n.cmdline.join(" ").toLowerCase().includes(q) ||
        String(n.pid).includes(q);
      top = top.filter(match);
    }
    if (anomOnly) {
      const has = (n: ProcessNode): boolean => n.flagged || n.children.some(has);
      top = top.filter(has);
    }
    return top;
  }, [store.nodes, filter, anomOnly]);

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title-area">
          <span className="panel-title">PROCESS LINEAGE MONITOR</span>
          <span className="pstat">{store.nodes.size || 18} RUNNING</span>
          {store.anomalies.length > 0 && (
            <span className="pstat pstat--warn">⚠ {store.anomalies.length} FLAGGED</span>
          )}
        </div>

        <div className="toolbar-right">
          <button
            className="sm-btn"
            onClick={handleSimulate}
            disabled={simulating}
            title="Simulate unlinked C2 execution anomaly"
          >
            {simulating ? "SIMULATING…" : "⚡ SIMULATE SUSPICIOUS PROCESS"}
          </button>

          <input
            className="search-input"
            placeholder="Search name, PID, or args…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />

          <div style={{ display: "flex", gap: 2 }}>
            <button
              className={`sm-btn ${!anomOnly ? "sm-btn--active" : ""}`}
              onClick={() => setAnomOnly(false)}
            >
              ALL
            </button>
            <button
              className={`sm-btn ${anomOnly ? "sm-btn--active" : ""}`}
              onClick={() => setAnomOnly(true)}
            >
              ANOMALIES ONLY
            </button>
          </div>
        </div>
      </div>

      <div className="proc-cols">
        <span>PROCESS LINEAGE / CMD</span>
        <span>PID</span>
        <span>PPID</span>
        <span>UID</span>
        <span>SECURITY STATUS</span>
      </div>

      <div className="proc-tree">
        {roots.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon">⬡</span>
            <div>
              {store.nodes.size === 0
                ? "ATTACHING DIRECT IN-PROCESS EDR HOOKS…"
                : "NO ACTIVE PROCESSES MATCH CRITERIA"}
            </div>
          </div>
        ) : (
          roots.map((n) => <ProcessRow key={n.pid} node={n} depth={0} />)
        )}
      </div>
    </div>
  );
}
