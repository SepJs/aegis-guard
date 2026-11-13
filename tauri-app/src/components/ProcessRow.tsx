import { useState } from "react";
import type { ProcessNode } from "../types";
import ConfidenceBadge from "./ConfidenceBadge";
import RuleBadge from "./RuleBadge";
import DrillDownModal from "./DrillDownModal";

export default function ProcessRow({
  node,
  depth,
  flatMode = false,
}: {
  node: ProcessNode;
  depth: number;
  flatMode?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [exp, setExp] = useState(true);
  const has = !flatMode && node.children.length > 0;
  const riskScore = node.anomaly?.risk_score ?? 45;

  const rowCls = node.flagged
    ? riskScore >= 70 || node.anomaly?.confidence === "high"
      ? "proc-row proc-row--high"
      : riskScore >= 35 || node.anomaly?.confidence === "medium"
      ? "proc-row proc-row--medium"
      : "proc-row proc-row--low"
    : "proc-row";

  const st = (node.state || "S").charAt(0);
  const stCls =
    st === "R" || st === "S" || st === "D" || st === "Z" || st === "T" ? `state-pill--${st}` : "state-pill--I";
  const stLabel = node.state_label || (st === "R" ? "Running" : st === "Z" ? "Zombie" : st === "T" ? "Stopped" : st === "D" ? "Disk Wait" : "Sleeping");
  const cpuPct = node.cpu_pct ?? 0;
  const memMb = ((node.mem_rss_kb ?? 0) / 1024).toFixed(1);
  const threads = node.threads ?? 1;

  return (
    <>
      <div
        className={rowCls}
        style={{ paddingLeft: flatMode ? 12 : 12 + depth * 16 }}
        onClick={() => setOpen(true)}
      >
        <div className="proc-name-cell">
          {has ? (
            <button
              className="chevron"
              onClick={(e) => {
                e.stopPropagation();
                setExp((v) => !v);
              }}
            >
              {exp ? "▾" : "▸"}
            </button>
          ) : (
            <span className="chevron-sp" />
          )}
          <span className="pname" title={node.cmdline.join(" ")}>
            {node.name}
          </span>
        </div>

        <span className="pid-v">{node.pid}</span>
        <span className="ppid-v">{node.ppid}</span>

        <div>
          <span className={`state-pill ${stCls}`} title={`Kernel state '${st}' (${stLabel})`}>
            {st === "R" ? "● " : ""}{stLabel}
          </span>
        </div>

        <span
          className="tm-cell"
          style={{
            color: cpuPct >= 25 ? "var(--redl)" : cpuPct >= 5 ? "var(--amberl)" : cpuPct > 0 ? "var(--teall)" : "var(--tx2)",
            fontWeight: cpuPct > 0 ? 700 : 400,
          }}
        >
          {cpuPct.toFixed(1)}%
        </span>

        <span className="tm-cell" style={{ color: (node.mem_rss_kb ?? 0) > 100 * 1024 ? "var(--vl)" : "var(--tx1)" }}>
          {memMb} MB
        </span>

        <span className="tm-cell">{threads}</span>

        <div className="status-cell">
          {!node.anomaly ? (
            <span style={{ fontSize: 8, color: "var(--teall)", opacity: 0.75, letterSpacing: "0.04em" }}>
              ✓ CLEAN
            </span>
          ) : (
            <>
              <span
                style={{
                  fontSize: 8,
                  fontWeight: 700,
                  padding: "1px 5px",
                  borderRadius: 2,
                  background:
                    riskScore >= 90
                      ? "rgba(220,38,38,.2)"
                      : riskScore >= 70
                      ? "rgba(234,88,12,.2)"
                      : "rgba(217,119,6,.2)",
                  color:
                    riskScore >= 90
                      ? "var(--redl)"
                      : riskScore >= 70
                      ? "#fb923c"
                      : "var(--amberl)",
                  border: "1px solid currentColor",
                }}
              >
                {riskScore} PTS
              </span>
              <ConfidenceBadge confidence={node.anomaly.confidence} />
              {node.anomaly.virus_name && (
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
              <RuleBadge rule={node.anomaly.rule} />
            </>
          )}
        </div>
      </div>
      {!flatMode && exp && node.children.map((c) => <ProcessRow key={c.pid} node={c} depth={depth + 1} flatMode={false} />)}
      {open && <DrillDownModal node={node} onClose={() => setOpen(false)} />}
    </>
  );
}
