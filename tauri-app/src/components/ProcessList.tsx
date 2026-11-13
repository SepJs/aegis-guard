import { useState, useMemo } from "react";
import { useProcessStore } from "../store/processStore";
import ProcessRow from "./ProcessRow";
import type { ProcessNode } from "../types";

type ViewSortMode = "tree" | "cpu" | "mem" | "pid";
type StateFilter = "all" | "R" | "S" | "D" | "Z" | "T";

export default function ProcessList() {
  const { store } = useProcessStore();
  const [filter, setFilter] = useState("");
  const [anomOnly, setAnomOnly] = useState(false);
  const [viewMode, setViewMode] = useState<ViewSortMode>("tree");
  const [stateFilter, setStateFilter] = useState<StateFilter>("all");

  const m = store.systemMetrics;
  const isFlat = viewMode !== "tree" || stateFilter !== "all" || filter.trim().length > 0;

  const displayed = useMemo(() => {
    const all = Array.from(store.nodes.values());

    if (isFlat) {
      let list = [...all];
      if (filter.trim()) {
        const q = filter.toLowerCase();
        list = list.filter(
          (n) =>
            n.name.toLowerCase().includes(q) ||
            n.cmdline.join(" ").toLowerCase().includes(q) ||
            String(n.pid).includes(q) ||
            (n.state_label || "").toLowerCase().includes(q)
        );
      }
      if (anomOnly) {
        list = list.filter((n) => n.flagged);
      }
      if (stateFilter !== "all") {
        list = list.filter((n) => {
          const s = (n.state || "S").toUpperCase();
          if (stateFilter === "T") return s === "T";
          return s === stateFilter;
        });
      }

      if (viewMode === "cpu") {
        list.sort((a, b) => (b.cpu_pct ?? 0) - (a.cpu_pct ?? 0) || (b.mem_rss_kb ?? 0) - (a.mem_rss_kb ?? 0));
      } else if (viewMode === "mem") {
        list.sort((a, b) => (b.mem_rss_kb ?? 0) - (a.mem_rss_kb ?? 0) || (b.cpu_pct ?? 0) - (a.cpu_pct ?? 0));
      } else {
        list.sort((a, b) => (a.flagged ? -1 : 0) - (b.flagged ? -1 : 0) || a.pid - b.pid);
      }
      return list;
    }

    const pids = new Set(all.map((n) => n.pid));
    let top = all.filter((n) => !pids.has(n.ppid));
    top.sort((a, b) => (a.flagged ? -1 : 0) - (b.flagged ? -1 : 0) || a.pid - b.pid);
    if (anomOnly) {
      const has = (n: ProcessNode): boolean => n.flagged || n.children.some(has);
      top = top.filter(has);
    }
    return top;
  }, [store.nodes, filter, anomOnly, viewMode, stateFilter, isFlat]);

  const cpuPct = m?.cpu_pct ?? 0;
  const memPct = m?.mem_pct ?? 0;

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">LIVE TASK & PROCESS MONITOR</span>
        <span className="pstat">{store.nodes.size} PROCS</span>
        {m && <span className="pstat">{m.total_threads} THREADS</span>}
        {store.anomalies.length > 0 && <span className="pstat pstat--warn">⚠ {store.anomalies.length} FLAGGED</span>}

        <div className="toolbar-right">
          <select
            className="filter-select"
            aria-label="Sort or view mode"
            value={viewMode}
            onChange={(e) => setViewMode(e.target.value as ViewSortMode)}
          >
            <option value="tree">VIEW: HIERARCHY TREE</option>
            <option value="cpu">SORT: TOP CPU %</option>
            <option value="mem">SORT: TOP MEMORY</option>
            <option value="pid">SORT: PID (FLAT)</option>
          </select>

          <select
            className="filter-select"
            aria-label="Filter by process kernel state"
            value={stateFilter}
            onChange={(e) => setStateFilter(e.target.value as StateFilter)}
          >
            <option value="all">ALL STATES</option>
            <option value="R">RUNNING (R)</option>
            <option value="S">SLEEPING (S)</option>
            <option value="D">DISK WAIT (D)</option>
            <option value="Z">ZOMBIE (Z)</option>
            <option value="T">STOPPED (T)</option>
          </select>

          <input
            className="search-input"
            placeholder="Search name / PID / args…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <button className={`sm-btn ${anomOnly ? "sm-btn--active" : ""}`} onClick={() => setAnomOnly((v) => !v)}>
            ANOMALIES ONLY
          </button>
        </div>
      </div>

      {/* Real-Time Task Manager Host Telemetry Strip (/proc/stat, /proc/meminfo, /proc/loadavg) */}
      {m && (
        <div className="tm-strip">
          <div className="tm-metric">
            <span className="tm-metric-lbl">HOST CPU USAGE</span>
            <span className="tm-metric-val" style={{ color: cpuPct >= 80 ? "var(--redl)" : "var(--teall)" }}>
              {cpuPct.toFixed(1)}%
            </span>
            <div className="tm-bar">
              <div
                className="tm-bar-fill"
                style={{
                  width: `${Math.min(100, Math.max(2, cpuPct))}%`,
                  background: cpuPct >= 80 ? "var(--red)" : cpuPct >= 50 ? "var(--amber)" : "var(--teal)",
                }}
              />
            </div>
          </div>

          <div className="tm-metric" style={{ minWidth: 165 }}>
            <span className="tm-metric-lbl">PHYSICAL MEMORY (/proc/meminfo)</span>
            <span className="tm-metric-val" style={{ color: memPct >= 85 ? "var(--redl)" : "var(--vl)" }}>
              {m.mem_used_mb} / {m.mem_total_mb} MB ({memPct.toFixed(1)}%)
            </span>
            <div className="tm-bar">
              <div
                className="tm-bar-fill"
                style={{
                  width: `${Math.min(100, Math.max(2, memPct))}%`,
                  background: memPct >= 85 ? "var(--red)" : "var(--v)",
                }}
              />
            </div>
          </div>

          <div className="tm-metric">
            <span className="tm-metric-lbl">LOAD AVG (1m / 5m / 15m)</span>
            <span className="tm-metric-val">
              {m.load_1m.toFixed(2)} · {m.load_5m.toFixed(2)} · {m.load_15m.toFixed(2)}
            </span>
          </div>

          <div className="tm-states">
            <button
              type="button"
              className={`state-pill state-pill--R`}
              onClick={() => setStateFilter((s) => (s === "R" ? "all" : "R"))}
              title="Processes actively executing on CPU"
            >
              ● R RUNNING: {m.state_counts.running}
            </button>
            <button
              type="button"
              className={`state-pill state-pill--S`}
              onClick={() => setStateFilter((s) => (s === "S" ? "all" : "S"))}
              title="Processes in interruptible sleep"
            >
              S SLEEPING: {m.state_counts.sleeping}
            </button>
            <button
              type="button"
              className={`state-pill state-pill--D`}
              onClick={() => setStateFilter((s) => (s === "D" ? "all" : "D"))}
              title="Processes in uninterruptible I/O wait"
            >
              D DISK: {m.state_counts.disk_wait}
            </button>
            <button
              type="button"
              className={`state-pill state-pill--Z`}
              onClick={() => setStateFilter((s) => (s === "Z" ? "all" : "Z"))}
              title="Defunct / Zombie processes"
            >
              Z ZOMBIE: {m.state_counts.zombie}
            </button>
            <button
              type="button"
              className={`state-pill state-pill--T`}
              onClick={() => setStateFilter((s) => (s === "T" ? "all" : "T"))}
              title="Stopped / SIGSTOP frozen processes"
            >
              T STOPPED: {m.state_counts.stopped}
            </button>
          </div>
        </div>
      )}

      <div className="proc-cols">
        <span>NAME</span>
        <span>PID</span>
        <span>PPID</span>
        <span>STATE</span>
        <span>CPU %</span>
        <span>MEM RSS</span>
        <span>THR</span>
        <span>SECURITY STATUS</span>
      </div>

      <div className="proc-tree">
        {displayed.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon">⬡</span>
            {store.nodes.size === 0 ? "WAITING FOR /proc KERNEL ENGINE…" : "NO MATCHES FOR CURRENT FILTER"}
          </div>
        ) : (
          displayed.map((n) => <ProcessRow key={n.pid} node={n} depth={0} flatMode={isFlat} />)
        )}
      </div>
    </div>
  );
}
