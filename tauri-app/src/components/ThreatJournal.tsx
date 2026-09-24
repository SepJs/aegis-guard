import { useState, useEffect, useCallback } from "react";
import { invoke } from "../lib/ipc/core";
import { listen } from "../lib/ipc/event";
import type { ThreatIncident, Severity } from "../types";
import ConfidenceBadge from "./ConfidenceBadge";
import RuleBadge from "./RuleBadge";

type Cat = "all" | "PAR" | "PATH" | "ARG" | "ENV" | "C2";
const PAGE = 50;

export default function ThreatJournal() {
  const [incidents, setIncidents] = useState<ThreatIncident[]>([]);
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [cat, setCat] = useState<Cat>("all");
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [exporting, setExporting] = useState(false);

  const load = useCallback(async (off: number) => {
    try {
      const rows = await invoke<ThreatIncident[]>("list_incidents", { limit: PAGE, offset: off });
      if (Array.isArray(rows)) {
        setIncidents((prev) => (off === 0 ? rows : [...prev, ...rows]));
        setOffset(off + rows.length);
      }
    } catch (err) {
      console.error("Failed to load incidents:", err);
    }
  }, []);

  useEffect(() => {
    load(0);
  }, [load]);

  useEffect(() => {
    const unlistenPromise = listen("anomaly", () => load(0));
    return () => {
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, [load]);

  async function resolve(id: string) {
    await invoke("resolve_incident", { id });
    setIncidents((prev) => prev.map((i) => (i.id === id ? { ...i, resolved: true } : i)));
  }

  async function doExport(fmt: "markdown" | "json") {
    setExporting(true);
    const data = fmt === "markdown" ? await invoke<string>("export_markdown") : await invoke<string>("export_json");
    const mime = fmt === "markdown" ? "text/markdown" : "application/json";
    const ext = fmt === "markdown" ? "md" : "json";
    const blob = new Blob([data], { type: mime });
    const a = Object.assign(document.createElement("a"), {
      href: URL.createObjectURL(blob),
      download: `aegis-report-${Date.now()}.${ext}`,
    });
    a.click();
    setExporting(false);
  }

  const counts: Record<string, number> = { all: incidents.length };
  ["PAR", "PATH", "ARG", "ENV", "C2"].forEach((c) => {
    counts[c] = incidents.filter((i) => i.rule.startsWith(c) || (c === "C2" && i.kind.includes("c2"))).length;
  });

  const filtered = incidents.filter((i) => {
    if (severityFilter !== "all" && i.severity !== severityFilter) return false;
    if (cat !== "all") {
      if (cat === "C2") return i.kind.includes("c2");
      return i.rule.startsWith(cat);
    }
    return true;
  });

  const open = filtered.filter((i) => !i.resolved);
  const closed = filtered.filter((i) => i.resolved);

  async function handleSimulateIncident() {
    try {
      await invoke("simulate_threat_incident");
      await load(0);
    } catch (e) {
      console.error(e);
    }
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">THREAT JOURNAL2 & INCIDENTS</span>
        {open.length > 0 && <span className="pstat pstat--warn">{open.length} ACTIVE INCIDENTS</span>}
        <span className="pstat">MULTI-TIER EVALUATED</span>
        <div className="toolbar-right" style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button
            className="sm-btn"
            onClick={handleSimulateIncident}
            title="Inject simulated C2 interactive shell incident into Threat Journal"
          >
            ⚡ SIMULATE THREAT INCIDENT
          </button>
          <button className="sm-btn" onClick={() => doExport("markdown")} disabled={exporting || !incidents.length}>
            EXPORT .MD
          </button>
          <button className="sm-btn" onClick={() => doExport("json")} disabled={exporting || !incidents.length}>
            EXPORT .JSON
          </button>
        </div>
      </div>

      {/* Category Tabs and Severity Filters */}
      <div className="cat-tabs" style={{ display: "flex", justifyContent: "space-between" }}>
        <div style={{ display: "flex", gap: 2 }}>
          {(["all", "PAR", "PATH", "ARG", "ENV", "C2"] as Cat[]).map((c) => (
            <div key={c} className={`cat-tab ${cat === c ? "cat-tab--active" : ""}`} onClick={() => setCat(c)}>
              {c.toUpperCase()}
              {counts[c] > 0 && <span className="cat-tab-count">{counts[c]}</span>}
            </div>
          ))}
        </div>

        <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
          <span style={{ fontSize: 9, color: "var(--tx2)", letterSpacing: "0.06em" }}>SEVERITY:</span>
          {(["all", "critical", "high", "medium", "low"] as const).map((s) => (
            <button
              key={s}
              className={`sm-btn ${severityFilter === s ? "sm-btn--active" : ""}`}
              onClick={() => setSeverityFilter(s)}
              style={{ fontSize: 8, padding: "2px 6px" }}
            >
              {s.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="journal-list">
        {filtered.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon">◈</span>
            NO INCIDENTS MATCHING FILTER CRITERIA
          </div>
        ) : (
          <>
            {open.map((inc) => (
              <IncCard
                key={inc.id}
                inc={inc}
                expanded={expanded === inc.id}
                onToggle={() => setExpanded((v) => (v === inc.id ? null : inc.id))}
                onResolve={() => resolve(inc.id)}
              />
            ))}
            {closed.length > 0 && (
              <>
                <div className="section-divider">RESOLVED & SUPPRESSED ({closed.length})</div>
                {closed.map((inc) => (
                  <IncCard
                    key={inc.id}
                    inc={inc}
                    expanded={expanded === inc.id}
                    onToggle={() => setExpanded((v) => (v === inc.id ? null : inc.id))}
                    onResolve={() => {}}
                  />
                ))}
              </>
            )}
            {incidents.length >= PAGE && (
              <button className="load-more" onClick={() => load(offset)}>
                LOAD MORE
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function IncCard({
  inc,
  expanded,
  onToggle,
  onResolve,
}: {
  inc: ThreatIncident;
  expanded: boolean;
  onToggle: () => void;
  onResolve: () => void;
}) {
  const isCritical = inc.severity === "critical";
  const isHigh = inc.severity === "high";
  const isMedium = inc.severity === "medium";

  const cls = `incident-card ${
    isCritical
      ? "incident-card--high"
      : isHigh
      ? "incident-card--high"
      : isMedium
      ? "incident-card--medium"
      : "incident-card--low"
  }${inc.resolved ? " incident-card--resolved" : ""}`;

  const ts = new Date(inc.ts).toLocaleTimeString("en-GB", { hour12: false });

  return (
    <div className={cls}>
      <div className="card-summary" onClick={onToggle}>
        <div className="card-left">
          <RuleBadge rule={inc.rule} />

          {/* Risk Score Pill */}
          <span
            style={{
              fontSize: 9,
              fontWeight: 700,
              padding: "2px 7px",
              borderRadius: 2,
              background:
                inc.risk_score >= 90
                  ? "rgba(220,38,38,.2)"
                  : inc.risk_score >= 70
                  ? "rgba(234,88,12,.2)"
                  : inc.risk_score >= 45
                  ? "rgba(217,119,6,.2)"
                  : "rgba(13,148,136,.2)",
              color:
                inc.risk_score >= 90
                  ? "var(--redl)"
                  : inc.risk_score >= 70
                  ? "#fb923c"
                  : inc.risk_score >= 45
                  ? "var(--amberl)"
                  : "var(--teall)",
              border: "1px solid currentColor",
            }}
          >
            {inc.risk_score}/100 {inc.severity.toUpperCase()}
          </span>

          <span className="card-process">{inc.process}</span>
          {inc.virus_name && (
            <span
              style={{
                fontSize: 8,
                fontWeight: 700,
                padding: "1px 5px",
                borderRadius: 2,
                background: "rgba(220,38,38,.25)",
                color: "var(--redl)",
                border: "1px solid var(--red)",
                letterSpacing: "0.04em",
              }}
            >
              VIRUS: {inc.virus_family || "MALWARE"}
            </span>
          )}
          <ConfidenceBadge confidence={inc.confidence} />
          {inc.flags && inc.flags.length > 0 && (
            <span style={{ fontSize: 8, color: "var(--tx2)", fontFamily: "var(--mono)" }}>
              {inc.flags[0]}
            </span>
          )}
        </div>

        <div className="card-right">
          <span className="card-ts">{ts}</span>
          {!inc.resolved && (
            <button
              className="resolve-btn"
              onClick={(e) => {
                e.stopPropagation();
                onResolve();
              }}
            >
              DISMISS
            </button>
          )}
          <span className="card-chevron">{expanded ? "▲" : "▼"}</span>
        </div>
      </div>

      {expanded && (
        <div className="card-detail">
          {inc.virus_name && (
            <div
              style={{
                marginBottom: 8,
                padding: "8px 10px",
                background: "rgba(220,38,38,.16)",
                border: "1px solid var(--red)",
                borderRadius: 4,
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
              }}
            >
              <span style={{ fontSize: 10, fontWeight: 700, color: "var(--redl)" }}>
                ⚡ MALWARE SIGNATURE: {inc.virus_name}
              </span>
              <span
                style={{
                  fontSize: 8,
                  fontWeight: 700,
                  padding: "1px 6px",
                  borderRadius: 2,
                  background: "rgba(220,38,38,.3)",
                  color: "var(--redl)",
                }}
              >
                FAMILY: {inc.virus_family || "MALWARE"}
              </span>
            </div>
          )}

          {inc.flags && inc.flags.length > 0 && (
            <div style={{ marginBottom: 6, display: "flex", gap: 5, flexWrap: "wrap", alignItems: "center" }}>
              <span style={{ fontSize: 8, color: "var(--tx2)", fontWeight: 700, letterSpacing: "0.06em" }}>
                FLAGS:
              </span>
              {inc.flags.map((fl, fidx) => (
                <span
                  key={fidx}
                  style={{
                    fontSize: 8,
                    fontFamily: "var(--mono)",
                    padding: "1px 5px",
                    borderRadius: 2,
                    background: fl.includes("VIRUS")
                      ? "rgba(220,38,38,.2)"
                      : fl.includes("DEV") || fl.includes("DIAG")
                      ? "rgba(13,148,136,.2)"
                      : "rgba(124,58,237,.15)",
                    color: fl.includes("VIRUS")
                      ? "var(--redl)"
                      : fl.includes("DEV") || fl.includes("DIAG")
                      ? "var(--teall)"
                      : "var(--vl)",
                    border: "1px solid currentColor",
                  }}
                >
                  {fl}
                </span>
              ))}
            </div>
          )}

          <div className="card-reason">{inc.reason}</div>

          {inc.mitre_technique && (
            <div className="meta-row">
              <span className="meta-label">MITRE ATT&CK</span>
              <span style={{ fontSize: 10, color: "var(--vl)", fontWeight: 600 }}>
                {inc.mitre_tactic ? `${inc.mitre_tactic} ➔ ` : ""}
                {inc.mitre_technique}
              </span>
            </div>
          )}

          {inc.factors && inc.factors.length > 0 && (
            <div style={{ margin: "4px 0" }}>
              <div style={{ fontSize: 8, color: "var(--tx2)", letterSpacing: "0.08em", fontWeight: 700, marginBottom: 4 }}>
                SCORING FACTORS & HEURISTICS:
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                {inc.factors.map((f, idx) => (
                  <div
                    key={idx}
                    style={{
                      fontSize: 9,
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      color: f.impact > 0 ? "var(--tx0)" : "var(--teall)",
                    }}
                  >
                    <span
                      style={{
                        fontWeight: 700,
                        minWidth: 40,
                        color: f.impact > 0 ? (f.impact >= 35 ? "var(--redl)" : "var(--amberl)") : "var(--teall)",
                      }}
                    >
                      {f.impact > 0 ? `+${f.impact}` : f.impact} pts
                    </span>
                    <strong style={{ minWidth: 150 }}>{f.name}:</strong>
                    <span style={{ color: "var(--tx1)" }}>{f.desc}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {inc.movement_steps && inc.movement_steps.length > 0 && (
            <div style={{ margin: "6px 0" }}>
              <div style={{ fontSize: 8, color: "var(--tx2)", letterSpacing: "0.08em", fontWeight: 700, marginBottom: 4 }}>
                MOVEMENT TIMELINE TRACE:
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                {inc.movement_steps.map((st, sidx) => (
                  <div
                    key={sidx}
                    style={{
                      fontSize: 9,
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      padding: "2px 6px",
                      background: "rgba(255,255,255,.02)",
                      borderRadius: 2,
                    }}
                  >
                    <span style={{ color: "var(--tx2)", minWidth: 50 }}>
                      {new Date(st.ts).toLocaleTimeString("en-GB", { hour12: false })}
                    </span>
                    <span style={{ color: "var(--vl)", fontWeight: 600, minWidth: 120 }}>{st.event}</span>
                    <span style={{ color: "var(--tx1)", flex: 1 }}>{st.detail}</span>
                    <span style={{ color: "var(--amberl)", fontSize: 8 }}>+{st.delta} risk</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {inc.exe_path && (
            <div className="meta-row">
              <span className="meta-label">EXE</span>
              <code className={`meta-code ${inc.exe_path.endsWith("(deleted)") ? "meta-code--danger" : ""}`}>
                {inc.exe_path}
              </code>
            </div>
          )}
          {inc.cmdline.length > 0 && (
            <div className="meta-row">
              <span className="meta-label">CMDLINE</span>
              <code className="meta-code">{inc.cmdline.join(" ")}</code>
            </div>
          )}
          <div className="meta-row">
            <span className="meta-label">PID / PPID</span>
            <span className="meta-val">
              {inc.pid} / {inc.ppid}
            </span>
          </div>
          {inc.ancestors.length > 0 && (
            <div className="meta-row">
              <span className="meta-label">ANCESTORS</span>
              <span className="meta-val">{inc.ancestors.join(" → ")}</span>
            </div>
          )}
          <div className="meta-row">
            <span className="meta-label">DIGEST</span>
            <code className="meta-code meta-code--muted">{inc.digest.slice(0, 24)}…</code>
          </div>
        </div>
      )}
    </div>
  );
}
