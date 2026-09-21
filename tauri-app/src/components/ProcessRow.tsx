import { useState } from "react";
import type { ProcessNode } from "../types";
import ConfidenceBadge from "./ConfidenceBadge";
import RuleBadge from "./RuleBadge";
import DrillDownModal from "./DrillDownModal";

export default function ProcessRow({ node, depth }: { node: ProcessNode; depth: number }) {
  const [open, setOpen] = useState(false);
  const [exp, setExp] = useState(true);
  const has = node.children.length > 0;
  const rowCls = node.flagged
    ? node.anomaly?.confidence === "high" ? "proc-row proc-row--high"
    : node.anomaly?.confidence === "medium" ? "proc-row proc-row--medium" : "proc-row proc-row--low"
    : "proc-row";

  return (
    <>
      <div className={rowCls} style={{ paddingLeft: 12 + depth * 18 }} onClick={() => setOpen(true)}>
        <div className="proc-name-cell">
          {has ? <button className="chevron" onClick={e => { e.stopPropagation(); setExp(v => !v); }}>{exp ? "▾" : "▸"}</button> : <span className="chevron-sp" />}
          <span className="pname">{node.name}</span>
        </div>
        <span className="pid-v">{node.pid}</span>
        <span className="ppid-v">{node.ppid}</span>
        <span className="uid-v">{node.uid}</span>
        <div className="status-cell">
          {node.anomaly && (
            <span
              style={{
                fontSize: 8,
                fontWeight: 700,
                padding: "1px 5px",
                borderRadius: 2,
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
              {node.anomaly.risk_score ?? 85} PTS
            </span>
          )}
          {node.anomaly && <ConfidenceBadge confidence={node.anomaly.confidence} />}
          {node.anomaly?.virus_name && (
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
              title={`Virus: ${node.anomaly.virus_name} (${node.anomaly.virus_family || "Malware"})`}
            >
              VIRUS: {node.anomaly.virus_family || "MALWARE"}
            </span>
          )}
          {node.anomaly && <RuleBadge rule={node.anomaly.rule} />}
          {node.anomaly?.flags && node.anomaly.flags.length > 0 && (
            <span
              style={{
                fontSize: 8,
                color: "var(--tx2)",
                fontFamily: "var(--mono)",
              }}
            >
              {node.anomaly.flags[0]}
            </span>
          )}
        </div>
      </div>
      {exp && node.children.map(c => <ProcessRow key={c.pid} node={c} depth={depth + 1} />)}
      {open && <DrillDownModal node={node} onClose={() => setOpen(false)} />}
    </>
  );
}
