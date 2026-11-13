import { useState, useEffect, useRef } from "react";
import { invoke } from "../lib/ipc/core";
import { listen } from "../lib/ipc/event";
import type { SandboxAnalysisReport } from "../types";

export default function SandboxPanel() {
  const [reports, setReports] = useState<SandboxAnalysisReport[]>([]);
  const [selectedJailId, setSelectedJailId] = useState<string | null>(null);
  const [filePath, setFilePath] = useState("");
  const [uploadedName, setUploadedName] = useState<string | null>(null);
  const [uploadedBytes, setUploadedBytes] = useState<number[] | null>(null);
  const [isolationType, setIsolationType] = useState<"ReadOnly-Byte-Jail" | "Namespace-Cgroup-v2" | "Chroot-Isolated-RAMFS">("ReadOnly-Byte-Jail");
  const [networkConfinement, setNetworkConfinement] = useState<"OFFLINE" | "AIR-GAPPED (Loopback Sinkhole)">("OFFLINE");
  const [spawning, setSpawning] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  async function loadReports() {
    try {
      const data = await invoke<SandboxAnalysisReport[]>("list_sandbox_reports");
      if (data) {
        setReports(data);
        if (!selectedJailId && data.length > 0) {
          setSelectedJailId(data[0].jail_id);
        }
      }
    } catch (err) {
      console.error("Failed to load sandbox reports:", err);
    }
  }

  useEffect(() => {
    loadReports();

    const unsub = listen<{ reports: SandboxAnalysisReport[] }>("sandbox-update", (ev) => {
      if (ev.payload?.reports) {
        setReports([...ev.payload.reports]);
      }
    });

    return () => {
      unsub.then((f) => f && f());
    };
  }, []);

  async function handleFileUpload(file: File) {
    try {
      const buf = await file.arrayBuffer();
      const bytes = Array.from(new Uint8Array(buf).slice(0, 4 * 1024 * 1024));
      setUploadedName(file.name);
      setUploadedBytes(bytes);
      setFilePath(file.name);
      setErrorMsg(null);
    } catch (err: any) {
      setErrorMsg(`Failed reading file: ${err?.message || err}`);
    }
  }

  async function handleLaunchJail() {
    if (!filePath.trim() && !uploadedBytes) {
      setErrorMsg("Enter a real file path on disk or upload a file to inspect.");
      return;
    }
    setSpawning(true);
    setErrorMsg(null);
    setNotice(null);
    try {
      const res = await invoke<SandboxAnalysisReport>("launch_sandbox_jail", {
        filePath: filePath.trim() || uploadedName || "uploaded_sample.bin",
        content: uploadedBytes || undefined,
        isolationType,
        networkConfinement,
      });
      if (res) {
        setNotice(`Read-only sandbox jail ${res.jail_id} created. Inspected ELF/shebang, entropy, SHA-256, and byte signatures.`);
        setSelectedJailId(res.jail_id);
        setUploadedBytes(null);
        setUploadedName(null);
        loadReports();
      }
    } catch (err: any) {
      setErrorMsg(String(err?.message || err || "Failed to inspect target file."));
    } finally {
      setSpawning(false);
    }
  }

  async function handleTerminateJail(jailId: string) {
    try {
      await invoke("terminate_sandbox_jail", { jailId });
      setNotice(`Sandbox Jail ${jailId} purged and wiped from host store.`);
      loadReports();
    } catch (err) {
      console.error("Failed to terminate jail:", err);
    }
  }

  const selectedReport = reports.find((r) => r.jail_id === selectedJailId) || reports[0];

  return (
    <div className="panel" id="sandbox-panel" style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      {/* Top Header */}
      <div className="panel-header" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 16px", borderBottom: "1px solid var(--border)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span className="panel-title" style={{ fontWeight: 700, letterSpacing: "0.08em" }}>
            ISOLATED FILE SANDBOX &amp; STATIC BYTE JAIL
          </span>
          <span className="pstat" style={{ background: "rgba(13,148,136,0.15)", color: "var(--teall)", border: "1px solid var(--teal)", padding: "2px 8px", borderRadius: 4, fontSize: 10 }}>
            STATIC &amp; ISOLATED BYTE INSPECTION
          </span>
          <span className="pstat" style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, background: "var(--bg1)" }}>
            {reports.length} JAILS
          </span>
        </div>

        {notice && (
          <div style={{ fontSize: 11, color: "var(--teall)", background: "rgba(13,148,136,0.1)", padding: "3px 10px", borderRadius: 4, border: "1px solid var(--teal)" }}>
            {notice}
          </div>
        )}
      </div>

      {/* Control Banner for Inspecting a Real File in Isolated Jail */}
      <div style={{ padding: "12px 16px", background: "var(--bg1)", borderBottom: "1px solid var(--border)", display: "flex", flexWrap: "wrap", gap: 12, alignItems: "flex-end" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <label style={{ fontSize: 9, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            TARGET FILE PATH ON HOST (OR BROWSE BELOW)
          </label>
          <input
            type="text"
            className="search-input"
            placeholder="e.g. /usr/bin/curl or /tmp/suspicious.sh"
            value={filePath}
            onChange={(e) => {
              setFilePath(e.target.value);
              if (uploadedBytes) {
                setUploadedBytes(null);
                setUploadedName(null);
              }
            }}
            style={{ width: 280, padding: "5px 9px", fontSize: 11, background: "var(--bg)", border: "1px solid var(--border)", borderRadius: 4, color: "var(--tx)" }}
          />
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <label style={{ fontSize: 9, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            UPLOAD FILE BYTES
          </label>
          <input
            ref={fileInputRef}
            type="file"
            style={{ display: "none" }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) handleFileUpload(f);
            }}
          />
          <button
            className="sm-btn"
            onClick={() => fileInputRef.current?.click()}
            style={{ padding: "5px 10px", fontSize: 11 }}
          >
            {uploadedName ? `✓ ${uploadedName}` : "CHOOSE LOCAL FILE…"}
          </button>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <label style={{ fontSize: 9, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.06em" }}>ISOLATION MODE</label>
          <select
            value={isolationType}
            onChange={(e) => setIsolationType(e.target.value as any)}
            style={{ padding: "5px 8px", fontSize: 11, background: "var(--bg)", border: "1px solid var(--border)", borderRadius: 4, color: "var(--tx)" }}
          >
            <option value="ReadOnly-Byte-Jail">Read-Only Jail (chmod 0400 + Static Analysis)</option>
            <option value="Namespace-Cgroup-v2">Namespace + Cgroup Boundary</option>
            <option value="Chroot-Isolated-RAMFS">Ephemeral Vault Isolation</option>
          </select>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <label style={{ fontSize: 9, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.06em" }}>NETWORK CONFINEMENT</label>
          <select
            value={networkConfinement}
            onChange={(e) => setNetworkConfinement(e.target.value as any)}
            style={{ padding: "5px 8px", fontSize: 11, background: "var(--bg)", border: "1px solid var(--border)", borderRadius: 4, color: "var(--tx)" }}
          >
            <option value="OFFLINE">OFFLINE (Zero Execution / Zero Sockets)</option>
            <option value="AIR-GAPPED (Loopback Sinkhole)">AIR-GAPPED (Loopback Sinkhole)</option>
          </select>
        </div>

        <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "flex-end" }}>
          <button
            className="action-btn action-btn--primary"
            onClick={handleLaunchJail}
            disabled={spawning || (!filePath.trim() && !uploadedBytes)}
          >
            {spawning ? "INSPECTING…" : "⊕ ISOLATE & INSPECT FILE"}
          </button>
        </div>
      </div>

      {errorMsg && (
        <div style={{ padding: "8px 16px", background: "rgba(220,38,38,0.12)", borderBottom: "1px solid var(--red)", color: "var(--redl)", fontSize: 11 }}>
          ⚠ {errorMsg}
        </div>
      )}

      {/* Main Split Body: Jails List on Left, Real Static Inspection Report on Right */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {/* Left Sidebar: Jails List */}
        <div style={{ width: 310, borderRight: "1px solid var(--border)", display: "flex", flexDirection: "column", background: "var(--bg0)", overflowY: "auto" }}>
          <div style={{ padding: "8px 12px", fontSize: 10, color: "var(--tx2)", fontWeight: 600, letterSpacing: "0.05em", borderBottom: "1px solid var(--border)", background: "var(--bg1)" }}>
            CONTAINED SAMPLE JAILS ({reports.length})
          </div>

          {reports.length === 0 ? (
            <div style={{ padding: 24, textAlign: "center", color: "var(--tx2)", fontSize: 11 }}>
              No isolated files inspected yet. Enter a real path or upload a file above.
            </div>
          ) : (
            reports.map((r) => {
              const isSelected = r.jail_id === selectedJailId;
              return (
                <div
                  key={r.jail_id}
                  onClick={() => setSelectedJailId(r.jail_id)}
                  style={{
                    padding: "10px 14px",
                    borderBottom: "1px solid var(--border)",
                    cursor: "pointer",
                    background: isSelected ? "rgba(13,148,136,0.12)" : "transparent",
                    borderLeft: isSelected ? "3px solid var(--teal)" : "3px solid transparent",
                    transition: "all 0.15s ease",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: isSelected ? "var(--teall)" : "var(--tx)" }}>
                      {r.sample_name}
                    </span>
                    <span
                      style={{
                        fontSize: 9,
                        padding: "1px 6px",
                        borderRadius: 3,
                        background: r.status === "analyzed" ? "rgba(13,148,136,0.2)" : "rgba(225,29,72,0.2)",
                        color: r.status === "analyzed" ? "var(--teall)" : "var(--redl)",
                        fontWeight: 700,
                      }}
                    >
                      {r.status.toUpperCase()}
                    </span>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 10, color: "var(--tx2)" }}>
                    <span>{r.family}</span>
                    <span>•</span>
                    <span style={{ color: r.blueprint.dynamic_risk_rating >= 90 ? "var(--redl)" : r.blueprint.dynamic_risk_rating >= 70 ? "#fb923c" : "var(--teall)", fontWeight: 700 }}>
                      RISK {r.blueprint.dynamic_risk_rating}/100
                    </span>
                  </div>

                  <div style={{ fontSize: 9, color: "var(--tx3)", marginTop: 4, fontFamily: "var(--mono)" }}>
                    {r.jail_id} · {r.isolation_type.split(" ")[0]}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right Area: Real Byte & IOC Report */}
        {selectedReport ? (
          <div style={{ flex: 1, display: "flex", flexDirection: "column", overflowY: "auto", padding: "16px 20px", gap: 16 }}>
            <div
              style={{
                padding: "14px 18px",
                background: "var(--bg1)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
              }}
            >
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                  <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: "var(--tx)" }}>
                    {selectedReport.sample_name}
                  </h3>
                  <span
                    style={{
                      padding: "2px 8px",
                      borderRadius: 4,
                      fontSize: 10,
                      fontWeight: 700,
                      background: selectedReport.blueprint.threat_level === "CRITICAL" ? "rgba(225,29,72,0.18)" : "rgba(13,148,136,0.18)",
                      color: selectedReport.blueprint.threat_level === "CRITICAL" ? "var(--redl)" : "var(--teall)",
                      border: `1px solid ${selectedReport.blueprint.threat_level === "CRITICAL" ? "var(--red)" : "var(--teal)"}`,
                    }}
                  >
                    {selectedReport.blueprint.threat_level}
                  </span>
                  <span style={{ fontSize: 11, color: "var(--tx2)" }}>
                    Type: <strong>{selectedReport.family}</strong>
                  </span>
                </div>

                <div style={{ fontSize: 11, color: "var(--tx2)", fontFamily: "var(--mono)", display: "flex", gap: 16, flexWrap: "wrap" }}>
                  <span>JAIL: {selectedReport.jail_id}</span>
                  <span>ISOLATION: {selectedReport.isolation_type}</span>
                  <span>CONFINEMENT: {selectedReport.network_confinement}</span>
                  <span>SHA-256: {selectedReport.sha256.slice(0, 24)}…</span>
                </div>
              </div>

              <div style={{ display: "flex", gap: 8 }}>
                {selectedReport.status !== "terminated" && (
                  <button
                    className="action-btn action-btn--danger"
                    onClick={() => handleTerminateJail(selectedReport.jail_id)}
                  >
                    PURGE JAIL COPY
                  </button>
                )}
              </div>
            </div>

            <div style={{ padding: "14px 18px", background: "rgba(13,148,136,0.06)", border: "1px solid rgba(13,148,136,0.3)", borderRadius: 6 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: "var(--teall)", letterSpacing: "0.06em", textTransform: "uppercase" }}>
                  STATIC &amp; ISOLATED BYTE INSPECTION SUMMARY
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, color: selectedReport.blueprint.dynamic_risk_rating >= 90 ? "var(--redl)" : "var(--teall)" }}>
                  RISK RATING: {selectedReport.blueprint.dynamic_risk_rating} / 100
                </span>
              </div>

              <p style={{ margin: "0 0 10px 0", fontSize: 12, lineHeight: 1.5, color: "var(--tx)" }}>
                {selectedReport.blueprint.threat_summary}
              </p>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 12, marginTop: 12, paddingTop: 10, borderTop: "1px solid rgba(13,148,136,0.2)" }}>
                <div>
                  <div style={{ fontSize: 10, color: "var(--tx2)", textTransform: "uppercase" }}>ANALYSIS STAGE</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tx)", marginTop: 2 }}>
                    {selectedReport.blueprint.killchain_phase}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: 10, color: "var(--tx2)", textTransform: "uppercase" }}>OBFUSCATION / ENTROPY</div>
                  <div style={{ fontSize: 11, color: "var(--tx)", marginTop: 2 }}>
                    {selectedReport.blueprint.evasion_mechanisms.join(" • ")}
                  </div>
                </div>
              </div>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: "var(--tx2)", letterSpacing: "0.06em", textTransform: "uppercase" }}>
                VERIFIED BYTE OBSERVATIONS
              </span>

              <div style={{ border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden", background: "var(--bg)" }}>
                {selectedReport.observed_behaviors.map((b, idx) => (
                  <div
                    key={idx}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "110px 90px 180px 1fr",
                      padding: "8px 12px",
                      fontSize: 11,
                      borderBottom: "1px solid var(--border)",
                      gap: 8,
                    }}
                  >
                    <span style={{ color: "var(--tx2)", textTransform: "uppercase", fontSize: 10 }}>{b.category}</span>
                    <span style={{ color: b.risk === "critical" ? "var(--redl)" : b.risk === "high" ? "#fb923c" : "var(--teall)", fontWeight: 700, fontSize: 10 }}>
                      {String(b.risk || "low").toUpperCase()}
                    </span>
                    <span style={{ fontFamily: "var(--mono)", color: "var(--tx)", fontSize: 10 }}>{b.operation}</span>
                    <span style={{ color: "var(--tx1)", fontSize: 10 }}>{b.description || b.target}</span>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 12 }}>
              <div style={{ padding: "12px 14px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6 }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: "var(--tx2)", textTransform: "uppercase" }}>
                  EMBEDDED IPS &amp; DOMAINS EXTRACTED FROM BYTES
                </span>
                <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
                  {selectedReport.extracted_iocs.ips.concat(selectedReport.extracted_iocs.domains).map((net, i) => (
                    <div key={i} style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--amberl)", background: "var(--bg0)", padding: "3px 8px", borderRadius: 3 }}>
                      {net}
                    </div>
                  ))}
                  {selectedReport.extracted_iocs.ips.length === 0 && selectedReport.extracted_iocs.domains.length === 0 && (
                    <div style={{ fontSize: 11, color: "var(--tx2)" }}>No IPv4 literals or URLs found in file bytes</div>
                  )}
                </div>
              </div>

              <div style={{ padding: "12px 14px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6 }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: "var(--tx2)", textTransform: "uppercase" }}>
                  ISOLATED COPY PATH (chmod 0400)
                </span>
                <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
                  {selectedReport.extracted_iocs.dropped_files.map((f, i) => (
                    <div key={i} style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--teall)", background: "var(--bg0)", padding: "3px 8px", borderRadius: 3, wordBreak: "break-all" }}>
                      {f}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--tx2)", fontSize: 12 }}>
            Provide a real host file path or upload a file to run read-only isolated byte inspection.
          </div>
        )}
      </div>
    </div>
  );
}
