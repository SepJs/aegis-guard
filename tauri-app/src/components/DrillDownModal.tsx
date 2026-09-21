import { useState } from "react";
import type { ProcessNode, ThreatIncident } from "../types";
import ConfidenceBadge from "./ConfidenceBadge";
import RuleBadge from "./RuleBadge";
import ConfirmModal from "./ConfirmModal";

type ActiveAction = "kill" | "quarantine" | "whitelist" | null;

export default function DrillDownModal({ node, onClose }: { node: ProcessNode; onClose: () => void }) {
  const [activeAction, setActiveAction] = useState<ActiveAction>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const ts = new Date(node.ts).toLocaleString("en-GB");

  const asIncident: ThreatIncident = {
    id: node.id,
    kind: "suspicious_parentage",
    severity: (node.anomaly?.severity as any) || (node.anomaly?.confidence === "high" ? "high" : "medium"),
    risk_score: node.anomaly?.risk_score ?? (node.anomaly?.confidence === "high" ? 85 : 45),
    pid: node.pid,
    ppid: node.ppid,
    process: node.name,
    cmdline: node.cmdline,
    exe_path: node.exe ?? null,
    rule: node.anomaly?.rule ?? "",
    confidence: node.anomaly?.confidence ?? "low",
    reason: node.anomaly?.reason ?? "",
    ancestors: node.anomaly?.ancestors ?? [],
    ts: new Date(node.ts).toISOString(),
    resolved: false,
    digest: "",
    mitre_tactic: node.anomaly?.mitre_tactic,
    mitre_technique: node.anomaly?.mitre_technique,
  };

  return (
    <>
      <div className="modal-backdrop" onClick={onClose}>
        <div className="modal" onClick={e => e.stopPropagation()}>
          <div className="modal-header">
            <span className="modal-proc-name">{node.name}</span>
            {node.anomaly && (
              <span
                style={{
                  fontSize: 10,
                  fontWeight: 700,
                  padding: "2px 8px",
                  borderRadius: 3,
                  background:
                    (node.anomaly.risk_score ?? 50) >= 90
                      ? "rgba(220,38,38,.2)"
                      : (node.anomaly.risk_score ?? 50) >= 70
                      ? "rgba(234,88,12,.2)"
                      : "rgba(217,119,6,.2)",
                  color:
                    (node.anomaly.risk_score ?? 50) >= 90
                      ? "var(--redl)"
                      : (node.anomaly.risk_score ?? 50) >= 70
                      ? "#fb923c"
                      : "var(--amberl)",
                  border: "1px solid currentColor",
                }}
              >
                SCORE: {node.anomaly.risk_score ?? 85}/100 [{(node.anomaly.severity ?? "high").toUpperCase()}]
              </span>
            )}
            {node.anomaly && <ConfidenceBadge confidence={node.anomaly.confidence} />}
            {node.anomaly && <RuleBadge rule={node.anomaly.rule} />}
            <button className="modal-close" onClick={onClose}>✕</button>
          </div>

          {successMsg && <div style={{ margin: "0 16px 0", padding: "8px 12px", background: "rgba(13,148,136,.1)", border: "1px solid var(--teal)", borderRadius: 4, fontSize: 10, color: "var(--teall)" }}>✓ {successMsg}</div>}

          <div className="modal-section">
            <div className="modal-section-title">IDENTITY & ATTRIBUTION</div>
            <div className="meta-row"><span className="meta-label">PID</span><span className="meta-val">{node.pid}</span></div>
            <div className="meta-row"><span className="meta-label">PPID</span><span className="meta-val">{node.ppid}</span></div>
            <div className="meta-row"><span className="meta-label">UID</span><span className="meta-val">{node.uid} ({node.uid === 0 ? "root" : node.uid < 1000 ? "system service" : "standard user"})</span></div>
            <div className="meta-row"><span className="meta-label">FIRST SEEN</span><span className="meta-val">{ts}</span></div>
          </div>

          <div className="modal-section">
            <div className="modal-section-title">EXECUTION TRACE</div>
            {node.exe && <div className="meta-row"><span className="meta-label">EXE</span><code className={`meta-code ${node.exe.endsWith("(deleted)") ? "meta-code--danger" : ""}`}>{node.exe}</code></div>}
            {node.cwd && <div className="meta-row"><span className="meta-label">CWD</span><code className="meta-code">{node.cwd}</code></div>}
            {node.cmdline.length > 0 && <div className="meta-row"><span className="meta-label">CMDLINE</span><code className="meta-code">{node.cmdline.join(" ")}</code></div>}
          </div>

          {node.anomaly && (
            <div className="modal-section modal-section--alert">
              <div className="modal-section-title">⚠ DETECTION & BEHAVIORAL ANALYSIS — {node.anomaly.rule}</div>

              {node.anomaly.virus_name && (
                <div
                  style={{
                    marginBottom: 10,
                    padding: "8px 12px",
                    background: "rgba(220,38,38,.18)",
                    border: "1px solid var(--red)",
                    borderRadius: 4,
                    display: "flex",
                    flexDirection: "column",
                    gap: 3,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontSize: 10, fontWeight: 800, color: "var(--redl)", letterSpacing: "0.06em" }}>
                      ⚡ VIRUS / MALWARE IDENTIFIED
                    </span>
                    <span
                      style={{
                        fontSize: 9,
                        fontWeight: 700,
                        padding: "1px 6px",
                        borderRadius: 2,
                        background: "rgba(220,38,38,.3)",
                        color: "var(--redl)",
                      }}
                    >
                      FAMILY: {node.anomaly.virus_family || "MALWARE"}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: "var(--tx0)" }}>
                    Signature Match: {node.anomaly.virus_name}
                  </div>
                </div>
              )}

              {/* Granular Movement Flags */}
              {node.anomaly.flags && node.anomaly.flags.length > 0 && (
                <div style={{ marginBottom: 8, display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 8, color: "var(--tx2)", letterSpacing: "0.08em", fontWeight: 700 }}>
                    MOVEMENT FLAGS:
                  </span>
                  {node.anomaly.flags.map((flag, fidx) => (
                    <span
                      key={fidx}
                      style={{
                        fontSize: 9,
                        fontFamily: "var(--mono)",
                        padding: "2px 6px",
                        borderRadius: 2,
                        background: flag.includes("VIRUS")
                          ? "rgba(220,38,38,.2)"
                          : flag.includes("DEV") || flag.includes("DIAG")
                          ? "rgba(13,148,136,.2)"
                          : "rgba(124,58,237,.15)",
                        color: flag.includes("VIRUS")
                          ? "var(--redl)"
                          : flag.includes("DEV") || flag.includes("DIAG")
                          ? "var(--teall)"
                          : "var(--vl)",
                        border: "1px solid currentColor",
                      }}
                    >
                      {flag}
                    </span>
                  ))}
                </div>
              )}

              <div className="modal-reason">{node.anomaly.reason}</div>
              {node.anomaly.mitre_technique && (
                <div className="meta-row" style={{ marginTop: 6 }}>
                  <span className="meta-label">MITRE ATT&CK</span>
                  <span className="meta-val" style={{ color: "var(--vl)", fontWeight: 600 }}>
                    {node.anomaly.mitre_tactic ? `${node.anomaly.mitre_tactic} ➔ ` : ""}
                    {node.anomaly.mitre_technique}
                  </span>
                </div>
              )}

              {/* Factors Breakdown */}
              {node.anomaly.factors && node.anomaly.factors.length > 0 && (
                <div style={{ marginTop: 8 }}>
                  <div style={{ fontSize: 8, color: "var(--tx2)", letterSpacing: "0.08em", fontWeight: 700, marginBottom: 4 }}>
                    SCORING FACTORS:
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                    {node.anomaly.factors.map((f, fidx) => (
                      <div
                        key={fidx}
                        style={{
                          fontSize: 9,
                          display: "flex",
                          alignItems: "center",
                          gap: 6,
                          padding: "2px 6px",
                          borderRadius: 2,
                          background: "var(--bg3)",
                        }}
                      >
                        <span
                          style={{
                            fontWeight: 700,
                            minWidth: 44,
                            color: f.impact > 0 ? (f.impact >= 35 ? "var(--redl)" : "var(--amberl)") : "var(--teall)",
                          }}
                        >
                          {f.impact > 0 ? `+${f.impact}` : f.impact} pts
                        </span>
                        <strong style={{ minWidth: 140 }}>{f.name}:</strong>
                        <span style={{ color: "var(--tx1)", flex: 1 }}>{f.desc}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {node.anomaly.ancestors.length > 0 && <div className="meta-row" style={{ marginTop: 6 }}><span className="meta-label">ANCESTORS</span><span className="meta-val">{node.anomaly.ancestors.join(" → ")}</span></div>}
              {node.anomaly.parent_exe && <div className="meta-row"><span className="meta-label">PARENT EXE</span><code className="meta-code">{node.anomaly.parent_exe}</code></div>}
            </div>
          )}

          <div className="modal-section">
            <div className="modal-section-title">RESPONSE ACTIONS</div>
            <div style={{ display: "flex", gap: 6, marginTop: 6, flexWrap: "wrap" }}>
              <button className="response-btn response-btn--kill" onClick={() => setActiveAction("kill")} title="SIGTERM → 5s grace → SIGKILL. IRREVERSIBLE.">✕ KILL</button>
              <button className="response-btn response-btn--quarantine" onClick={() => setActiveAction("quarantine")} title="Network namespace isolation. Reversible.">⊘ QUARANTINE</button>
              <button className="response-btn response-btn--whitelist" onClick={() => setActiveAction("whitelist")} title="Add to allowlist.">✓ WHITELIST</button>
            </div>
            <p style={{ fontSize: 9, color: "var(--tx2)", marginTop: 6, fontStyle: "italic" }}>All actions require challenge token confirmation and are audit-logged.</p>
          </div>

          <div className="modal-footer">AUDIT LOG → all actions are BLAKE3-chained and tamper-evident</div>
        </div>
      </div>

      {activeAction && <ConfirmModal incident={asIncident} action={activeAction} onClose={() => setActiveAction(null)} onSuccess={msg => { setSuccessMsg(msg); setActiveAction(null); }} />}
    </>
  );
}
