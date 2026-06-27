import { useState }        from "react";
import type { ProcessNode } from "../types";
import ConfidenceBadge     from "./ConfidenceBadge";
import RuleBadge           from "./RuleBadge";
import DrillDownModal      from "./DrillDownModal";

interface Props { node: ProcessNode; depth: number; }

export default function ProcessRow({ node, depth }: Props) {
  const [open,  setOpen]  = useState(false);
  const [exp,   setExp]   = useState(true);
  const has = node.children.length > 0;
  const rowCls = node.flagged
    ? node.anomaly?.confidence === "high"   ? "proc-row proc-row--high"
    : node.anomaly?.confidence === "medium" ? "proc-row proc-row--medium"
    : "proc-row proc-row--low"
    : "proc-row";

  return (
    <>
      <div className={rowCls} style={{ paddingLeft: 12 + depth * 18 }}
           onClick={() => setOpen(true)}>
        <div className="proc-name-cell">
          {has
            ? <button className="chevron"
                onClick={e => { e.stopPropagation(); setExp(v => !v); }}>
                {exp ? "▾" : "▸"}
              </button>
            : <span className="chevron-sp" />
          }
          <span className="pname">{node.name}</span>
        </div>
        <span className="pid-v">{node.pid}</span>
        <span className="ppid-v">{node.ppid}</span>
        <span className="uid-v">{node.uid}</span>
        <div className="status-cell">
          {node.anomaly && <ConfidenceBadge confidence={node.anomaly.confidence} />}
          {node.anomaly && <RuleBadge rule={node.anomaly.rule} />}
        </div>
      </div>

      {exp && node.children.map(c =>
        <ProcessRow key={c.pid} node={c} depth={depth + 1} />
      )}

      {open && <DrillDownModal node={node} onClose={() => setOpen(false)} />}
    </>
  );
}
