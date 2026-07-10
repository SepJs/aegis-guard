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
    id: node.id, kind: "suspicious_parentage", severity: node.anomaly?.confidence === "high" ? "high" : "medium",
    pid: node.pid, ppid: node.ppid, process: node.name, cmdline: node.cmdline, exe_path: node.exe ?? null,
    rule: node.anomaly?.rule ?? "", confidence: node.anomaly?.confidence ?? "low", reason: node.anomaly?.reason ?? "",
    ancestors: node.anomaly?.ancestors ?? [], ts: new Date(node.ts).toISOString(), resolved: false, digest: "",
  };

  return (
    <>
      <div className="modal-backdrop" onClick={onClose}>
        <div className="modal" onClick={e => e.stopPropagation()}>
          <div className="modal-header">
            <span className="modal-proc-name">{node.name}</span>
            {node.anomaly && <ConfidenceBadge confidence={node.anomaly.confidence} />}
            {node.anomaly && <RuleBadge rule={node.anomaly.rule} />}
            <button className="modal-close" onClick={onClose}>✕</button>
          </div>

          {successMsg && <div style={{ margin: "0 16px 0", padding: "8px 12px", background: "rgba(13,148,136,.1)", border: "1px solid var(--teal)", borderRadius: 4, fontSize: 10, color: "var(--teall)" }}>✓ {successMsg}</div>}

          <div className="modal-section">
            <div className="modal-section-title">IDENTITY</div>
            <div className="meta-row"><span className="meta-label">PID</span><span className="meta-val">{node.pid}</span></div>
            <div className="meta-row"><span className="meta-label">PPID</span><span className="meta-val">{node.ppid}</span></div>
            <div className="meta-row"><span className="meta-label">UID</span><span className="meta-val">{node.uid}</span></div>
            <div className="meta-row"><span className="meta-label">FIRST SEEN</span><span className="meta-val">{ts}</span></div>
          </div>

          <div className="modal-section">
            <div className="modal-section-title">EXECUTION</div>
            {node.exe && <div className="meta-row"><span className="meta-label">EXE</span><code className={`meta-code ${node.exe.endsWith("(deleted)") ? "meta-code--danger" : ""}`}>{node.exe}</code></div>}
            {node.cwd && <div className="meta-row"><span className="meta-label">CWD</span><code className="meta-code">{node.cwd}</code></div>}
            {node.cmdline.length > 0 && <div className="meta-row"><span className="meta-label">CMDLINE</span><code className="meta-code">{node.cmdline.join(" ")}</code></div>}
          </div>

          {node.anomaly && (
            <div className="modal-section modal-section--alert">
              <div className="modal-section-title">⚠ DETECTION — {node.anomaly.rule}</div>
              <div className="modal-reason">{node.anomaly.reason}</div>
              {node.anomaly.ancestors.length > 0 && <div className="meta-row"><span className="meta-label">ANCESTORS</span><span className="meta-val">{node.anomaly.ancestors.join(" → ")}</span></div>}
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
