import type { ProcessNode } from "../types";
import ConfidenceBadge     from "./ConfidenceBadge";
import RuleBadge           from "./RuleBadge";

interface Props { node: ProcessNode; onClose: () => void; }

export default function DrillDownModal({ node, onClose }: Props) {
  const ts = new Date(node.ts).toLocaleString("en-GB");
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>

        <div className="modal-header">
          <span className="modal-proc-name">{node.name}</span>
          {node.anomaly && <ConfidenceBadge confidence={node.anomaly.confidence} />}
          {node.anomaly && <RuleBadge rule={node.anomaly.rule} />}
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>

        <div className="modal-section">
          <div className="modal-section-title">IDENTITY</div>
          <div className="meta-row"><span className="meta-label">PID</span><span className="meta-val">{node.pid}</span></div>
          <div className="meta-row"><span className="meta-label">PPID</span><span className="meta-val">{node.ppid}</span></div>
          <div className="meta-row"><span className="meta-label">UID</span><span className="meta-val">{node.uid}</span></div>
          <div className="meta-row"><span className="meta-label">FIRST SEEN</span><span className="meta-val">{ts}</span></div>
        </div>

        <div className="modal-section">
          <div className="modal-section-title">EXECUTION</div>
          {node.exe && (
            <div className="meta-row">
              <span className="meta-label">EXE</span>
              <code className={`meta-code ${node.exe.endsWith("(deleted)") ? "meta-code--danger" : ""}`}>
                {node.exe}
              </code>
            </div>
          )}
          {node.cwd && (
            <div className="meta-row">
              <span className="meta-label">CWD</span>
              <code className="meta-code">{node.cwd}</code>
            </div>
          )}
          {node.cmdline.length > 0 && (
            <div className="meta-row">
              <span className="meta-label">CMDLINE</span>
              <code className="meta-code">{node.cmdline.join(" ")}</code>
            </div>
          )}
        </div>

        {node.anomaly && (
          <div className="modal-section modal-section--alert">
            <div className="modal-section-title">⚠ DETECTION — {node.anomaly.rule}</div>
            <div className="modal-reason">{node.anomaly.reason}</div>
            {node.anomaly.ancestors.length > 0 && (
              <div className="meta-row">
                <span className="meta-label">ANCESTORS</span>
                <span className="meta-val">{node.anomaly.ancestors.join(" → ")}</span>
              </div>
            )}
            {node.anomaly.parent_exe && (
              <div className="meta-row">
                <span className="meta-label">PARENT EXE</span>
                <code className="meta-code">{node.anomaly.parent_exe}</code>
              </div>
            )}
          </div>
        )}

        <div className="modal-footer">
          RESPONSE ACTIONS (KILL · QUARANTINE · WHITELIST) — PHASE 3
        </div>
      </div>
    </div>
  );
}
