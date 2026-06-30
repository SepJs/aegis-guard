// CanaryPanel.tsx — Phase 5: canary token management

import { useState, useEffect } from "react";
import { invoke }              from "@tauri-apps/api/core";

interface CanaryToken {
  id:          string;
  token:       string;
  file_path:   string;
  description: string;
  created_ts:  number;
  triggered:   boolean;
}

export default function CanaryPanel() {
  const [tokens,   setTokens]   = useState<CanaryToken[]>([]);
  const [filePath, setFilePath] = useState("");
  const [desc,     setDesc]     = useState("");
  const [creating, setCreating] = useState(false);
  const [error,    setError]    = useState<string | null>(null);

  async function load() {
    try {
      const t = await invoke<CanaryToken[]>("list_canaries");
      setTokens(t);
    } catch (e) { console.error(e); }
  }

  useEffect(() => { load(); }, []);

  async function create() {
    if (!filePath.trim()) return;
    setCreating(true); setError(null);
    try {
      await invoke("create_canary", { filePath: filePath.trim(), description: desc.trim() });
      setFilePath(""); setDesc("");
      await load();
    } catch (e) { setError(String(e)); }
    finally { setCreating(false); }
  }

  async function remove(id: string) {
    try {
      await invoke("delete_canary", { id });
      await load();
    } catch (e) { console.error(e); }
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">CANARY TOKENS</span>
        <span className="pstat">{tokens.length} ACTIVE</span>
        {tokens.some(t => t.triggered) && (
          <span className="pstat pstat--warn">
            ⚠ {tokens.filter(t => t.triggered).length} TRIGGERED
          </span>
        )}
      </div>

      {/* Create new canary */}
      <div style={{
        padding: "14px 16px",
        borderBottom: "1px solid var(--border)",
        display: "flex", flexDirection: "column", gap: 8,
      }}>
        <div style={{ fontSize: 9, color: "var(--tx2)", letterSpacing: ".1em",
                      textTransform: "uppercase" }}>
          Embed Canary Token in File
        </div>
        <div style={{ fontSize: 10, color: "var(--tx2)", lineHeight: 1.6 }}>
          A unique token is embedded in your file as a comment.
          If this token appears in outbound network traffic, data exfiltration is detected.
        </div>
        <input
          className="search-input"
          style={{ width: "100%" }}
          placeholder="File path — e.g. /home/user/.ssh/config"
          value={filePath}
          onChange={e => setFilePath(e.target.value)}
        />
        <input
          className="search-input"
          style={{ width: "100%" }}
          placeholder="Description — e.g. SSH config canary"
          value={desc}
          onChange={e => setDesc(e.target.value)}
        />
        {error && (
          <div style={{ fontSize: 10, color: "var(--redl)" }}>{error}</div>
        )}
        <button
          className="action-btn"
          style={{ width: "fit-content" }}
          onClick={create}
          disabled={creating || !filePath.trim()}
        >
          {creating ? "CREATING…" : "CREATE CANARY TOKEN"}
        </button>
      </div>

      {/* Token list */}
      <div style={{ flex: 1, overflowY: "auto" }}>
        {tokens.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon">⬟</span>
            NO CANARY TOKENS — create one above
          </div>
        ) : (
          tokens.map(t => (
            <div key={t.id} style={{
              padding: "10px 16px",
              borderBottom: "1px solid var(--border)",
              borderLeft: `2px solid ${t.triggered ? "var(--red)" : "var(--teal)"}`,
              display: "flex", flexDirection: "column", gap: 5,
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{
                  fontSize: 9, fontWeight: 700,
                  color:    t.triggered ? "var(--redl)" : "var(--teall)",
                  padding:  "1px 6px",
                  border:   `1px solid ${t.triggered ? "rgba(220,38,38,.4)" : "rgba(13,148,136,.4)"}`,
                  borderRadius: 2,
                }}>
                  {t.triggered ? "⚠ TRIGGERED" : "ACTIVE"}
                </span>
                <span style={{ flex: 1, fontSize: 11, color: "var(--tx0)",
                               fontWeight: 600 }}>
                  {t.description || t.file_path}
                </span>
                <button
                  className="sm-btn"
                  style={{ fontSize: 9 }}
                  onClick={() => remove(t.id)}
                >
                  REMOVE
                </button>
              </div>
              <div className="meta-row">
                <span className="meta-label">FILE</span>
                <code className="meta-code">{t.file_path}</code>
              </div>
              <div className="meta-row">
                <span className="meta-label">TOKEN</span>
                <code className="meta-code" style={{ color: "var(--tx2)", fontSize: 9 }}>
                  {t.token.slice(0, 20)}…
                </code>
              </div>
              <div className="meta-row">
                <span className="meta-label">CREATED</span>
                <span className="meta-val">
                  {new Date(t.created_ts).toLocaleString("en-GB")}
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
