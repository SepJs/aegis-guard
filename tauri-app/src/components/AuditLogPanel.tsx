import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface AuditEntry { id: string; action: string; pid: number; process: string; incident_id: string | null; note: string; status: string; outcome: string | null; ts_before: number; ts_after: number | null; prev_digest: string; digest: string }

export default function AuditLogPanel() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [chainOk, setChainOk] = useState<boolean | null>(null);
  const [chainErrs, setChainErrs] = useState<string[]>([]);
  const [verifying, setVerifying] = useState(false);

  useEffect(() => { invoke<AuditEntry[]>("list_audit_log", { limit: 100, offset: 0 }).then(setEntries).catch(console.error); }, []);

  async function verifyChain() {
    setVerifying(true);
    try { const errs = await invoke<string[]>("verify_audit_chain"); setChainErrs(errs); setChainOk(errs.length === 0); }
    catch (e) { setChainOk(false); setChainErrs([String(e)]); } finally { setVerifying(false); }
  }

  const statusColor = (s: string) => s === "success" ? "var(--teall)" : s === "failed" ? "var(--redl)" : "var(--amberl)";

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">AUDIT LOG — ACTIVE DEFENSE ACTIONS</span>
        <span className="pstat">{entries.length} ENTRIES</span>
        {chainOk === true && <span className="pstat" style={{borderColor:"var(--teal)",color:"var(--teall)"}}>✓ CHAIN INTACT</span>}
        {chainOk === false && <span className="pstat pstat--warn">⚠ CHAIN BROKEN</span>}
        <div className="toolbar-right"><button className="sm-btn" onClick={verifyChain} disabled={verifying}>{verifying ? "VERIFYING…" : "VERIFY CHAIN"}</button></div>
      </div>
      {chainErrs.length > 0 && <div style={{ margin: "8px 14px", padding: "8px 12px", background: "var(--redd)", border: "1px solid var(--red)", borderRadius: 4, fontSize: 10, color: "var(--redl)" }}>{chainErrs.map((e, i) => <div key={i}>{e}</div>)}</div>}
      <div style={{ display: "grid", gridTemplateColumns: "80px 110px 60px 80px 1fr 70px", padding: "4px 14px", fontSize: 9, color: "var(--tx2)", letterSpacing: ".08em", textTransform: "uppercase", borderBottom: "1px solid var(--border)", background: "var(--bg1)", flexShrink: 0 }}>
        <span>ACTION</span><span>PROCESS</span><span>PID</span><span>STATUS</span><span>OUTCOME</span><span>TIME</span>
      </div>
      <div style={{ flex: 1, overflowY: "auto" }}>
        {entries.length === 0 ? <div className="empty-state"><span className="empty-icon">◈</span>NO ACTIVE DEFENSE ACTIONS YET</div> : entries.map(e => (
          <div key={e.id} style={{ display: "grid", gridTemplateColumns: "80px 110px 60px 80px 1fr 70px", padding: "5px 14px", borderBottom: "1px solid rgba(37,37,50,.45)", alignItems: "center", gap: 8, fontSize: 10 }}>
            <span style={{ fontFamily: "var(--mono)", fontSize: 9, color: e.action === "Kill" ? "var(--redl)" : e.action === "Quarantine" ? "var(--amberl)" : "var(--teall)" }}>{e.action.toUpperCase()}</span>
            <span style={{ fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.process}</span>
            <span style={{ color: "var(--tx2)", fontFamily: "var(--mono)" }}>{e.pid}</span>
            <span style={{ color: statusColor(e.status), fontSize: 9, fontWeight: 700, letterSpacing: ".05em" }}>{e.status.toUpperCase()}</span>
            <span style={{ color: "var(--tx2)", fontSize: 9, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.outcome ?? "—"}</span>
            <span style={{ color: "var(--tx2)", fontSize: 9, fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{new Date(e.ts_before).toLocaleTimeString("en-GB", { hour12: false })}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
