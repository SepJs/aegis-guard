import { useState, useMemo } from "react";
import { useProcessStore } from "../store/processStore";
import ProcessRow from "./ProcessRow";
import type { ProcessNode } from "../types";

export default function ProcessList() {
  const { store } = useProcessStore();
  const [filter, setFilter] = useState("");
  const [anomOnly, setAnomOnly] = useState(false);

  const roots = useMemo(() => {
    const all = Array.from(store.nodes.values());
    const pids = new Set(all.map(n => n.pid));
    let top = all.filter(n => !pids.has(n.ppid));
    top.sort((a, b) => (a.flagged ? -1 : 0) - (b.flagged ? -1 : 0) || a.pid - b.pid);
    if (filter.trim()) {
      const q = filter.toLowerCase();
      const match = (n: ProcessNode): boolean => n.name.toLowerCase().includes(q) || n.cmdline.join(" ").toLowerCase().includes(q) || String(n.pid).includes(q);
      top = top.filter(match);
    }
    if (anomOnly) { const has = (n: ProcessNode): boolean => n.flagged || n.children.some(has); top = top.filter(has); }
    return top;
  }, [store.nodes, filter, anomOnly]);

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">LIVE PROCESS MONITOR</span>
        <span className="pstat">{store.nodes.size} RUNNING</span>
        {store.anomalies.length > 0 && <span className="pstat pstat--warn">⚠ {store.anomalies.length} FLAGGED</span>}
        <div className="toolbar-right">
          <input className="search-input" placeholder="Search name / PID / args…" value={filter} onChange={e => setFilter(e.target.value)} />
          <button className={`sm-btn ${anomOnly ? "sm-btn--active" : ""}`} onClick={() => setAnomOnly(v => !v)}>ANOMALIES ONLY</button>
        </div>
      </div>
      <div className="proc-cols"><span>NAME</span><span>PID</span><span>PPID</span><span>UID</span><span>STATUS</span></div>
      <div className="proc-tree">
        {roots.length === 0 ? (
          <div className="empty-state"><span className="empty-icon">⬡</span>{store.nodes.size === 0 ? "WAITING FOR PROCESS ENGINE…" : "NO MATCHES FOR CURRENT FILTER"}</div>
        ) : roots.map(n => <ProcessRow key={n.pid} node={n} depth={0} />)}
      </div>
    </div>
  );
}
