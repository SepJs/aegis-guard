import { useState, useCallback, useRef } from "react";
import { invoke }    from "@tauri-apps/api/core";
import type { ScanSummary, FileScanResult } from "../types";

function fmtBytes(n: number) {
  if (n < 1024)         return `${n} B`;
  if (n < 1024 * 1024)  return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function EntropyBar({ value }: { value: number }) {
  const pct  = Math.min((value / 8) * 100, 100);
  const cls  = value > 7.5 ? "ef--high" : value > 6.5 ? "ef--medium"
             : value > 4.0 ? "ef--normal" : "ef--low";
  return (
    <div className="entropy-track">
      <div className={`entropy-fill ${cls}`} style={{ width: `${pct.toFixed(1)}%` }} />
    </div>
  );
}

function ResultRow({ r }: { r: FileScanResult }) {
  const [open, setOpen] = useState(false);
  const fname = r.path.split("/").pop() ?? r.path;
  const rowCls = `result-row result-row--${r.risk}`;
  const rpCls  = `risk-pill rp--${r.risk === "skipped" ? "skip" : r.risk}`;

  return (
    <>
      <div className={rowCls} onClick={() => setOpen(v => !v)}>
        <span className="result-name" title={r.path}>{fname}</span>
        {r.entropy != null ? <EntropyBar value={r.entropy} /> : <div style={{flex:1}} />}
        <span className="entropy-val">{r.entropy?.toFixed(3) ?? "—"}</span>
        <span className="result-mime">{r.mime_guess}</span>
        <span className="result-size">{fmtBytes(r.size_bytes)}</span>
        <span className={rpCls}>{r.risk.toUpperCase()}</span>
      </div>
      {open && (
        <div className="result-detail">
          <div className="meta-row">
            <span className="meta-label">PATH</span>
            <code className="meta-code">{r.path}</code>
          </div>
          <div className="meta-row">
            <span className="meta-label">NOTE</span>
            <span className="meta-val">{r.note}</span>
          </div>
        </div>
      )}
    </>
  );
}

export default function ForensicsPanel() {
  const [summary,  setSummary]  = useState<ScanSummary | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error,    setError]    = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [filter,   setFilter]   = useState("all");
  const inputRef = useRef<HTMLInputElement>(null);

  const runScan = useCallback(async (path: string) => {
    setScanning(true); setError(null); setSummary(null);
    try {
      const r = await invoke<ScanSummary>("scan_entropy", {
        request: { path, max_bytes: 33554432, recursive: true },
      });
      setSummary(r);
    } catch (e) { setError(String(e)); }
    finally { setScanning(false); }
  }, []);

  const displayed = summary?.results.filter(r =>
    filter === "all" ? true : r.risk === filter
  ) ?? [];

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">FILE FORENSICS — ENTROPY SCANNER</span>
        {summary && (
          <>
            <span className="pstat">{summary.scanned_files} SCANNED</span>
            {summary.high_risk > 0 && (
              <span className="pstat pstat--warn">⚠ {summary.high_risk} HIGH-RISK</span>
            )}
            <span className="scan-time">{summary.elapsed_ms}ms</span>
          </>
        )}
        <div className="toolbar-right">
          {summary && (
            <select className="filter-select" value={filter}
                    onChange={e => setFilter(e.target.value)}>
              <option value="all">ALL RESULTS</option>
              <option value="high">HIGH RISK</option>
              <option value="medium">MEDIUM RISK</option>
              <option value="normal">NORMAL</option>
              <option value="skipped">SKIPPED</option>
            </select>
          )}
          <input ref={inputRef} type="file" style={{ display:"none" }}
            onChange={e => {
              const f = e.target.files?.[0];
              if (f) runScan((f as any).path ?? f.name);
            }} />
          <button className="sm-btn" onClick={() => inputRef.current?.click()}
                  disabled={scanning}>
            BROWSE FILE…
          </button>
          {summary && (
            <button className="sm-btn" onClick={() => { setSummary(null); setFilter("all"); }}>
              NEW SCAN
            </button>
          )}
        </div>
      </div>

      {!scanning && !summary && !error && (
        <div
          className={`drop-zone ${dragOver ? "drop-zone--active" : ""}`}
          onDragOver={e => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={e => {
            e.preventDefault(); setDragOver(false);
            const f = e.dataTransfer.files[0];
            if (f) runScan((f as any).path ?? f.name);
          }}
          onClick={() => inputRef.current?.click()}
        >
          <div className="drop-icon-box">+</div>
          <div className="drop-title">DROP FILE OR DIRECTORY HERE</div>
          <div className="drop-sub">
            Shannon entropy analysis — packed binaries and encrypted blobs
            score near 8.0 bits/byte. No files are modified.
          </div>
          <div className="drop-sub drop-passive">PASSIVE ANALYSIS ONLY</div>
        </div>
      )}

      {scanning && (
        <div className="empty-state">
          <div className="spinner" />
          <span>SCANNING…</span>
        </div>
      )}

      {error && (
        <div className="empty-state" style={{ color:"var(--redl)" }}>
          <span className="empty-icon" style={{ color:"var(--red)" }}>✕</span>
          {error}
        </div>
      )}

      {summary && !scanning && (
        <>
          <div className="scan-summary-bar">
            <div className="sum-pill"><span className="sum-pill-val">{summary.total_files}</span><span className="sum-pill-label">TOTAL</span></div>
            <div className="sum-pill"><span className="sum-pill-val">{summary.scanned_files}</span><span className="sum-pill-label">SCANNED</span></div>
            <div className="sum-pill sum-pill--high"><span className="sum-pill-val" style={{color:"var(--redl)"}}>{summary.high_risk}</span><span className="sum-pill-label">HIGH</span></div>
            <div className="sum-pill sum-pill--medium"><span className="sum-pill-val" style={{color:"var(--amberl)"}}>{summary.medium_risk}</span><span className="sum-pill-label">MEDIUM</span></div>
            <div className="sum-pill"><span className="sum-pill-val">{summary.skipped_files}</span><span className="sum-pill-label">SKIPPED</span></div>
          </div>
          <div className="result-list">
            {displayed.length === 0
              ? <div className="empty-state">NO RESULTS MATCH FILTER</div>
              : displayed.map((r, i) => <ResultRow key={i} r={r} />)
            }
          </div>
        </>
      )}
    </div>
  );
}
