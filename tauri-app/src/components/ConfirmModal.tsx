import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ThreatIncident } from "../types";

type ActionKind = "kill" | "quarantine" | "whitelist";

const ACTION_META: Record<ActionKind, { label: string; color: string; icon: string; warning: string; reversible: boolean }> = {
  kill: { label: "KILL PROCESS", color: "var(--red)", icon: "✕", warning: "This will send SIGTERM then SIGKILL. The action is IRREVERSIBLE.", reversible: false },
  quarantine: { label: "QUARANTINE", color: "var(--amber)", icon: "⊘", warning: "This will isolate the process from the network. Files are not affected. Reversible via Lift Quarantine.", reversible: true },
  whitelist: { label: "WHITELIST", color: "var(--teal)", icon: "✓", warning: "This process will never be flagged or acted upon again, even if it triggers detection rules.", reversible: true },
};

export default function ConfirmModal({ incident, action, onClose, onSuccess }: { incident: ThreatIncident; action: ActionKind; onClose: () => void; onSuccess: (msg: string) => void }) {
  const [challenge, setChallenge] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const meta = ACTION_META[action];
  const expected = `CONFIRM-${action.toUpperCase()}-${incident.pid}`;
  const matches = challenge.trim() === expected;

  async function execute() {
    if (!matches) return;
    setLoading(true); setError(null);
    try {
      const result = await invoke<{ message: string }>("execute_action", {
        pid: incident.pid, processName: incident.process, exePath: incident.exe_path,
        action, incidentId: incident.id, challenge: challenge.trim(),
        note: `Action via dashboard — incident ${incident.id}`,
      });
      onSuccess(result.message); onClose();
    } catch (e) { setError(String(e)); } finally { setLoading(false); }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal confirm-modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header" style={{ borderColor: meta.color }}>
          <span className="modal-proc-name" style={{ color: meta.color }}>{meta.icon} {meta.label}</span>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>

        <div className="modal-section">
          <div className="modal-section-title">TARGET PROCESS</div>
          <div className="meta-row"><span className="meta-label">PROCESS</span><span className="meta-val">{incident.process}</span></div>
          <div className="meta-row"><span className="meta-label">PID</span><span className="meta-val">{incident.pid}</span></div>
          <div className="meta-row"><span className="meta-label">RULE</span><span className="meta-val">{incident.rule}</span></div>
          {incident.exe_path && <div className="meta-row"><span className="meta-label">EXE</span><code className="meta-code">{incident.exe_path}</code></div>}
        </div>

        <div className="modal-section" style={{ borderLeft: `2px solid ${meta.color}`, background: `${meta.color}08` }}>
          <div className="modal-section-title" style={{ color: meta.color }}>⚠ WARNING</div>
          <p style={{ fontSize: 11, color: "var(--tx1)", lineHeight: 1.6 }}>{meta.warning}</p>
          {!meta.reversible && <p style={{ fontSize: 11, color: "var(--redl)", marginTop: 6, fontWeight: 700 }}>THIS ACTION CANNOT BE UNDONE.</p>}
        </div>

        <div className="modal-section">
          <div className="modal-section-title">CONFIRMATION REQUIRED</div>
          <p style={{ fontSize: 10, color: "var(--tx2)", marginBottom: 8 }}>Type the following token exactly to confirm:</p>
          <div className="challenge-token">{expected}</div>
          <input className="challenge-input" placeholder="Type token here…" value={challenge} onChange={e => setChallenge(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter" && matches) execute(); }} autoFocus
            style={{ borderColor: challenge ? (matches ? "var(--teal)" : "var(--red)") : "var(--border)" }} />
          {challenge && !matches && <p style={{ fontSize: 10, color: "var(--redl)", marginTop: 4 }}>TOKEN MISMATCH — type exactly as shown</p>}
          {matches && <p style={{ fontSize: 10, color: "var(--teall)", marginTop: 4 }}>✓ TOKEN VERIFIED</p>}
        </div>

        {error && <div style={{ margin: "0 16px 8px", padding: "8px 10px", background: "var(--redd)", border: "1px solid var(--red)", borderRadius: 4, fontSize: 10, color: "var(--redl)" }}>{error}</div>}

        <div style={{ display: "flex", gap: 8, padding: "12px 16px", justifyContent: "flex-end" }}>
          <button className="sm-btn" onClick={onClose} disabled={loading}>CANCEL</button>
          <button disabled={!matches || loading} onClick={execute}
            style={{ padding: "5px 16px", fontSize: 10, fontWeight: 700, letterSpacing: ".07em", border: `1px solid ${meta.color}`, borderRadius: 4,
              background: matches ? `${meta.color}22` : "var(--bg3)", color: matches ? meta.color : "var(--tx2)",
              cursor: matches ? "pointer" : "default", transition: "all 120ms", fontFamily: "var(--mono)" }}>
            {loading ? "EXECUTING…" : meta.label}
          </button>
        </div>
      </div>
    </div>
  );
}
