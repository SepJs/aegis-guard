import { useState, useEffect } from "react";
import { invoke }          from "@tauri-apps/api/core";
import type { DebugEntry } from "../types";
import RuleBadge           from "./RuleBadge";

export default function DebugLogPanel() {
  const [entries, setEntries] = useState<DebugEntry[]>([]);
  const [offset,  setOffset]  = useState(0);
  const PAGE = 50;

  async function load(off: number) {
    const rows = await invoke<DebugEntry[]>("list_debug_log", { limit: PAGE, offset: off });
    setEntries(prev => off === 0 ? rows : [...prev, ...rows]);
    setOffset(off + rows.length);
  }
  useEffect(() => { load(0); }, []);

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">DEBUG LOG — FALSE POSITIVES</span>
        <span className="pstat">{entries.length} ENTRIES</span>
        <div className="toolbar-right">
          <span style={{ fontSize:9, color:"var(--tx2)", letterSpacing:".06em" }}>
            BENIGN EVENTS THAT TRIGGERED DETECTION RULES
          </span>
        </div>
      </div>

      <div className="debug-cols">
        <span>RULE</span>
        <span>PROCESS</span>
        <span>PID</span>
        <span>NOTE</span>
        <span>TIME</span>
      </div>

      <div className="debug-list">
        {entries.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon">⊘</span>
            NO DEBUG ENTRIES YET
          </div>
        ) : (
          entries.map(e => (
            <div key={e.id} className="debug-row">
              <span className="debug-rule"><RuleBadge rule={e.rule} /></span>
              <span className="debug-process">{e.process}</span>
              <span className="debug-pid">PID {e.pid}</span>
              <span className="debug-note">{e.note}</span>
              <span className="debug-ts">
                {new Date(e.ts).toLocaleTimeString("en-GB", { hour12: false })}
              </span>
            </div>
          ))
        )}
        {entries.length >= PAGE && (
          <button className="load-more" onClick={() => load(offset)}>LOAD MORE</button>
        )}
      </div>
    </div>
  );
}
