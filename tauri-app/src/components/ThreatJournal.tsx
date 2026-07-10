import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { ThreatIncident } from "../types";
import ConfidenceBadge from "./ConfidenceBadge";
import RuleBadge from "./RuleBadge";

type Cat = "all" | "PAR" | "PATH" | "ARG" | "ENV";
const PAGE = 50;

export default function ThreatJournal() {
  const [incidents, setIncidents] = useState<ThreatIncident[]>([]);
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [cat, setCat] = useState<Cat>("all");
  const [exporting, setExporting] = useState(false);

  const load = useCallback(async (off: number) => {
    const rows = await invoke<ThreatIncident[]>("list_incidents", { limit: PAGE, offset: off });
    setIncidents(prev => off === 0 ? rows : [...prev, ...rows]);
    setOffset(off + rows.length);
  }, []);

  useEffect(() => { load(0); }, [load]);
  useEffect(() => { const u = listen("anomaly", () => load(0)); return () => { u.then(f => f()); }; }, [load]);

  async function resolve(id: string) {
    await invoke("resolve_incident", { id });
    setIncidents(prev => prev.map(i => i.id === id ? { ...i, resolved: true } : i));
  }

  async function doExport(fmt: "markdown" | "json") {
    setExporting(true);
    const data = fmt === "markdown" ? await invoke<string>("export_markdown") : await invoke<string>("export_json");
    const mime = fmt === "markdown" ? "text/markdown" : "application/json";
    const ext = fmt === "markdown" ? "md" : "json";
    const blob = new Blob([data], { type: mime });
    const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `aegis-report-${Date.now()}.${ext}` });
    a.click();
    setExporting(false);
  }

  const counts: Record<string, number> = { all: incidents.length };
  ["PAR", "PATH", "ARG", "ENV"].forEach(c => { counts[c] = incidents.filter(i => i.rule.startsWith(c)).length; });

  const filtered = incidents.filter(i => cat === "all" || i.rule.startsWith(cat));
  const open = filtered.filter(i => !i.resolved);
  const closed = filtered.filter(i => i.resolved);

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">THREAT JOURNAL</span>
        {open.length > 0 && <span className="pstat pstat--warn">{open.length} OPEN</span>}
        <div className="toolbar-right">
          <button className="sm-btn" onClick={() => doExport("markdown")} disabled={exporting || !incidents.length}>EXPORT .MD</button>
          <button className="sm-btn" onClick={() => doExport("json")} disabled={exporting || !incidents.length}>EXPORT .JSON</button>
        </div>
      </div>

      <div className="cat-tabs">
        {(["all","PAR","PATH","ARG","ENV"] as Cat[]).map(c => (
          <div key={c} className={`cat-tab ${cat === c ? "cat-tab--active" : ""}`} onClick={() => setCat(c)}>
            {c.toUpperCase()}{counts[c] > 0 && <span className="cat-tab-count">{counts[c]}</span>}
          </div>
        ))}
      </div>

      <div className="journal-list">
        {filtered.length === 0 ? (
          <div className="empty-state"><span className="empty-icon">◈</span>NO INCIDENTS IN THIS CATEGORY</div>
        ) : (
          <>
            {open.map(inc => <IncCard key={inc.id} inc={inc} expanded={expanded === inc.id} onToggle={() => setExpanded(v => v === inc.id ? null : inc.id)} onResolve={() => resolve(inc.id)} />)}
            {closed.length > 0 && (
              <>
                <div className="section-divider">RESOLVED ({closed.length})</div>
                {closed.map(inc => <IncCard key={inc.id} inc={inc} expanded={expanded === inc.id} onToggle={() => setExpanded(v => v === inc.id ? null : inc.id)} onResolve={() => {}} />)}
              </>
            )}
            {incidents.length >= PAGE && <button className="load-more" onClick={() => load(offset)}>LOAD MORE</button>}
          </>
        )}
      </div>
    </div>
  );
}

function IncCard({ inc, expanded, onToggle, onResolve }: { inc: ThreatIncident; expanded: boolean; onToggle: () => void; onResolve: () => void }) {
  const cls = `incident-card incident-card--${inc.severity}${inc.resolved ? " incident-card--resolved" : ""}`;
  const ts = new Date(inc.ts).toLocaleTimeString("en-GB", { hour12: false });

  return (
    <div className={cls}>
      <div className="card-summary" onClick={onToggle}>
        <div className="card-left"><RuleBadge rule={inc.rule} /><span className="card-process">{inc.process}</span><ConfidenceBadge confidence={inc.confidence} /></div>
        <div className="card-right">
          <span className="card-ts">{ts}</span>
          {!inc.resolved && <button className="resolve-btn" onClick={e => { e.stopPropagation(); onResolve(); }}>DISMISS</button>}
          <span className="card-chevron">{expanded ? "▲" : "▼"}</span>
        </div>
      </div>
      {expanded && (
        <div className="card-detail">
          <div className="card-reason">{inc.reason}</div>
          {inc.exe_path && <div className="meta-row"><span className="meta-label">EXE</span><code className={`meta-code ${inc.exe_path.endsWith("(deleted)") ? "meta-code--danger" : ""}`}>{inc.exe_path}</code></div>}
          {inc.cmdline.length > 0 && <div className="meta-row"><span className="meta-label">CMDLINE</span><code className="meta-code">{inc.cmdline.join(" ")}</code></div>}
          <div className="meta-row"><span className="meta-label">KIND</span><span className="meta-val">{inc.kind.replace(/_/g, " ").toUpperCase()}</span></div>
          <div className="meta-row"><span className="meta-label">PID / PPID</span><span className="meta-val">{inc.pid} / {inc.ppid}</span></div>
          {inc.ancestors.length > 0 && <div className="meta-row"><span className="meta-label">ANCESTORS</span><span className="meta-val">{inc.ancestors.join(" → ")}</span></div>}
          <div className="meta-row"><span className="meta-label">DIGEST</span><code className="meta-code meta-code--muted">{inc.digest.slice(0, 24)}…</code></div>
        </div>
      )}
    </div>
  );
}
