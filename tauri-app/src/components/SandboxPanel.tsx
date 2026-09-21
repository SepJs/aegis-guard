import { useState, useEffect } from "react";
import { invoke } from "../lib/ipc/core";
import { listen } from "../lib/ipc/event";
import type { SandboxAnalysisReport, MalwareFamily } from "../types";

export default function SandboxPanel() {
  const [reports, setReports] = useState<SandboxAnalysisReport[]>([]);
  const [selectedJailId, setSelectedJailId] = useState<string | null>(null);
  const [sampleName, setSampleName] = useState("Ransomware.Linux.LockBit3");
  const [sampleFamily, setSampleFamily] = useState<MalwareFamily>("Ransomware");
  const [isolationType, setIsolationType] = useState<"Namespace-Cgroup-v2" | "Seccomp-BPF-Virtual" | "Chroot-Isolated-RAMFS">("Namespace-Cgroup-v2");
  const [networkConfinement, setNetworkConfinement] = useState<"AIR-GAPPED (Loopback Sinkhole)" | "HONEYPOT-INTERCEPT" | "OFFLINE">("AIR-GAPPED (Loopback Sinkhole)");
  const [spawning, setSpawning] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

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

  async function handleLaunchJail() {
    setSpawning(true);
    try {
      const res = await invoke<SandboxAnalysisReport>("launch_sandbox_jail", {
        sample_name: sampleName,
        family: sampleFamily,
        isolation_type: isolationType,
        network_confinement: networkConfinement,
      });
      if (res) {
        setNotice(`◈ Sandbox Jail ${res.jail_id} spawned successfully. Complete behavioral blueprint synthesized.`);
        setSelectedJailId(res.jail_id);
        loadReports();
      }
    } catch (err: any) {
      console.error("Failed to launch sandbox jail:", err);
    } finally {
      setSpawning(false);
    }
  }

  async function handleTerminateJail(jailId: string) {
    try {
      await invoke("terminate_sandbox_jail", { jail_id: jailId });
      setNotice(`◈ Sandbox Jail ${jailId} purged & wiped from system.`);
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
            ISOLATED MALWARE SANDBOX & LIVE DETONATION JAIL
          </span>
          <span className="pstat" style={{ background: "rgba(13,148,136,0.15)", color: "var(--teall)", border: "1px solid var(--teal)", padding: "2px 8px", borderRadius: 4, fontSize: 10 }}>
            DEVELOPER SECURITY ENVIRONMENT
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

      {/* Control Banner for Spawning New Isolated Malware Jails */}
      <div style={{ padding: "12px 16px", background: "var(--bg1)", borderBottom: "1px solid var(--border)", display: "flex", flexWrap: "wrap", gap: 12, alignItems: "center" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <label style={{ fontSize: 9, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.06em" }}>SAMPLE / VIRUS NAME</label>
          <input
            type="text"
            className="search-input"
            value={sampleName}
            onChange={(e) => setSampleName(e.target.value)}
            style={{ width: 230, padding: "5px 9px", fontSize: 12, background: "var(--bg)", border: "1px solid var(--border)", borderRadius: 4, color: "var(--tx)" }}
          />
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <label style={{ fontSize: 9, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.06em" }}>MALWARE FAMILY</label>
          <select
            value={sampleFamily}
            onChange={(e) => setSampleFamily(e.target.value as MalwareFamily)}
            style={{ padding: "5px 8px", fontSize: 11, background: "var(--bg)", border: "1px solid var(--border)", borderRadius: 4, color: "var(--tx)" }}
          >
            <option value="Ransomware">Ransomware (Locker / Encryptor)</option>
            <option value="Rootkit">Rootkit (Kernel Syscall Hook)</option>
            <option value="WebShell">WebShell (Remote Code Exec)</option>
            <option value="CoinMiner">CoinMiner (Stratum Mining)</option>
            <option value="Trojan">Trojan / Staged Dropper</option>
            <option value="Backdoor">Backdoor / Reverse C2</option>
            <option value="InfoStealer">InfoStealer (Credential Harvester)</option>
            <option value="Spyware">Spyware (Keylogger / Event Sniffer)</option>
          </select>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <label style={{ fontSize: 9, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.06em" }}>ISOLATION BOUNDARY</label>
          <select
            value={isolationType}
            onChange={(e) => setIsolationType(e.target.value as any)}
            style={{ padding: "5px 8px", fontSize: 11, background: "var(--bg)", border: "1px solid var(--border)", borderRadius: 4, color: "var(--tx)" }}
          >
            <option value="Namespace-Cgroup-v2">Namespace + Cgroups v2 (RAM/CPU Limit)</option>
            <option value="Seccomp-BPF-Virtual">Seccomp-BPF Syscall Filter Jail</option>
            <option value="Chroot-Isolated-RAMFS">Chroot Ephemeral RAMFS Sinkhole</option>
          </select>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <label style={{ fontSize: 9, color: "var(--tx2)", textTransform: "uppercase", letterSpacing: "0.06em" }}>NETWORK CONFINEMENT</label>
          <select
            value={networkConfinement}
            onChange={(e) => setNetworkConfinement(e.target.value as any)}
            style={{ padding: "5px 8px", fontSize: 11, background: "var(--bg)", border: "1px solid var(--border)", borderRadius: 4, color: "var(--tx)" }}
          >
            <option value="AIR-GAPPED (Loopback Sinkhole)">AIR-GAPPED (Loopback Sinkhole)</option>
            <option value="HONEYPOT-INTERCEPT">HONEYPOT-INTERCEPT (Fake Responses)</option>
            <option value="OFFLINE">OFFLINE (Zero Sockets Allowed)</option>
          </select>
        </div>

        <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "flex-end" }}>
          <button
            className="action-btn"
            style={{
              padding: "6px 14px",
              fontSize: 11,
              fontWeight: 600,
              background: "var(--teal)",
              color: "#fff",
              border: "none",
              borderRadius: 4,
              cursor: spawning ? "not-allowed" : "pointer",
            }}
            onClick={handleLaunchJail}
            disabled={spawning}
          >
            {spawning ? "DETONATING & ANALYZING…" : "⚡ DETONATE IN ISOLATED JAIL"}
          </button>
        </div>
      </div>

      {/* Main Split Body: Jails List on Left, Comprehensive Behavioral Blueprint on Right */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {/* Left Sidebar: Jails List */}
        <div style={{ width: 310, borderRight: "1px solid var(--border)", display: "flex", flexDirection: "column", background: "var(--bg0)", overflowY: "auto" }}>
          <div style={{ padding: "8px 12px", fontSize: 10, color: "var(--tx2)", fontWeight: 600, letterSpacing: "0.05em", borderBottom: "1px solid var(--border)", background: "var(--bg1)" }}>
            CONTAINED SAMPLE JAILS ({reports.length})
          </div>

          {reports.map((r) => {
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
                  <span style={{ color: r.blueprint.dynamic_risk_rating > 90 ? "var(--redl)" : "var(--orangel)", fontWeight: 700 }}>
                    RISK {r.blueprint.dynamic_risk_rating}/100
                  </span>
                </div>

                <div style={{ fontSize: 9, color: "var(--tx3)", marginTop: 4, fontFamily: "monospace" }}>
                  {r.jail_id} // {r.isolation_type.split("-")[0]}
                </div>
              </div>
            );
          })}
        </div>

        {/* Right Area: Deep Behavioral Analysis & Blueprint */}
        {selectedReport ? (
          <div style={{ flex: 1, display: "flex", flexDirection: "column", overflowY: "auto", padding: "16px 20px", gap: 16 }}>
            {/* Report Header Card */}
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
                      background: selectedReport.blueprint.threat_level === "CATASTROPHIC" ? "rgba(225,29,72,0.18)" : "rgba(245,158,11,0.18)",
                      color: selectedReport.blueprint.threat_level === "CATASTROPHIC" ? "var(--redl)" : "var(--orangel)",
                      border: `1px solid ${selectedReport.blueprint.threat_level === "CATASTROPHIC" ? "var(--red)" : "var(--orange)"}`,
                    }}
                  >
                    {selectedReport.blueprint.threat_level}
                  </span>
                  <span style={{ fontSize: 11, color: "var(--tx2)" }}>
                    Family: <strong>{selectedReport.family}</strong>
                  </span>
                </div>

                <div style={{ fontSize: 11, color: "var(--tx2)", fontFamily: "monospace", display: "flex", gap: 16, flexWrap: "wrap" }}>
                  <span>JAIL: {selectedReport.jail_id}</span>
                  <span>ISOLATION: {selectedReport.isolation_type}</span>
                  <span>CONFINEMENT: {selectedReport.network_confinement}</span>
                  <span>SHA-256: {selectedReport.sha256.slice(0, 16)}…</span>
                </div>
              </div>

              <div style={{ display: "flex", gap: 8 }}>
                {selectedReport.status !== "terminated" && (
                  <button
                    className="action-btn"
                    style={{
                      background: "rgba(225,29,72,0.12)",
                      border: "1px solid var(--red)",
                      color: "var(--redl)",
                      padding: "6px 12px",
                      fontSize: 11,
                      borderRadius: 4,
                      cursor: "pointer",
                    }}
                    onClick={() => handleTerminateJail(selectedReport.jail_id)}
                  >
                    DESTROY JAIL & RESTORE
                  </button>
                )}
              </div>
            </div>

            {/* Dynamic Behavioral Blueprint Box */}
            <div style={{ padding: "14px 18px", background: "rgba(13,148,136,0.06)", border: "1px solid rgba(13,148,136,0.3)", borderRadius: 6 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: "var(--teall)", letterSpacing: "0.06em", textTransform: "uppercase" }}>
                  ◈ AUTOMATED VIRUS BLUEPRINT & THREAT SUMMARY
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, color: selectedReport.blueprint.dynamic_risk_rating > 90 ? "var(--redl)" : "var(--orangel)" }}>
                  DYNAMIC RISK RATING: {selectedReport.blueprint.dynamic_risk_rating} / 100
                </span>
              </div>

              <p style={{ margin: "0 0 10px 0", fontSize: 12, lineHeight: 1.5, color: "var(--tx)" }}>
                {selectedReport.blueprint.threat_summary}
              </p>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 12, marginTop: 12, paddingTop: 10, borderTop: "1px solid rgba(13,148,136,0.2)" }}>
                <div>
                  <div style={{ fontSize: 10, color: "var(--tx2)", textTransform: "uppercase" }}>KILLCHAIN PHASE</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tx)", marginTop: 2 }}>
                    {selectedReport.blueprint.killchain_phase}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: 10, color: "var(--tx2)", textTransform: "uppercase" }}>EVASION MECHANISMS DETECTED</div>
                  <div style={{ fontSize: 11, color: "var(--tx)", marginTop: 2 }}>
                    {selectedReport.blueprint.evasion_mechanisms.join(" • ")}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: 10, color: "var(--tx2)", textTransform: "uppercase" }}>UNPACKING / SELF-INJECTION</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: selectedReport.blueprint.unpacking_detected ? "var(--redl)" : "var(--teall)", marginTop: 2 }}>
                    {selectedReport.blueprint.unpacking_detected ? "POSITIVE (Payload Decrypted in RAM)" : "NEGATIVE (Plain Executable)"}
                  </div>
                </div>
              </div>

              <div style={{ marginTop: 12, background: "var(--bg0)", padding: "8px 12px", borderRadius: 4, border: "1px solid var(--border)" }}>
                <span style={{ fontSize: 10, color: "var(--tx2)", textTransform: "uppercase" }}>RECOMMENDED REMEDIATION SCRIPT: </span>
                <code style={{ fontSize: 11, color: "var(--teall)", fontFamily: "monospace", display: "inline-block", marginLeft: 8 }}>
                  {selectedReport.blueprint.remediation_command}
                </code>
              </div>
            </div>

            {/* Observed Live Behaviors Feed */}
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: "var(--tx2)", letterSpacing: "0.06em", textTransform: "uppercase" }}>
                INTERCEPTED SYSTEM CALLS & MOVEMENTS INSIDE JAIL
              </span>

              <div style={{ border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden", background: "var(--bg)" }}>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "110px 100px 220px 1fr 90px",
                    padding: "7px 12px",
                    fontSize: 9,
                    color: "var(--tx2)",
                    background: "var(--bg1)",
                    borderBottom: "1px solid var(--border)",
                    fontWeight: 600,
                  }}
                >
                  <span>CATEGORY</span>
                  <span>RISK</span>
                  <span>OPERATION / SYSCALL</span>
                  <span>TARGET OBJECT</span>
                  <span style={{ textAlign: "right" }}>CONTAINMENT</span>
                </div>

                {selectedReport.observed_behaviors.map((b, idx) => (
                  <div
                    key={idx}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "110px 100px 220px 1fr 90px",
                      padding: "8px 12px",
                      fontSize: 11,
                      borderBottom: "1px solid var(--border)",
                      background: idx % 2 === 0 ? "transparent" : "rgba(255,255,255,0.015)",
                    }}
                  >
                    <span style={{ color: "var(--tx2)", textTransform: "uppercase", fontSize: 10 }}>{b.category}</span>
                    <span>
                      <span
                        style={{
                          fontSize: 9,
                          padding: "1px 5px",
                          borderRadius: 3,
                          fontWeight: 700,
                          background: b.risk === "critical" ? "rgba(225,29,72,0.18)" : b.risk === "high" ? "rgba(245,158,11,0.18)" : "rgba(13,148,136,0.18)",
                          color: b.risk === "critical" ? "var(--redl)" : b.risk === "high" ? "var(--orangel)" : "var(--teall)",
                        }}
                      >
                        {b.risk.toUpperCase()}
                      </span>
                    </span>
                    <span style={{ fontFamily: "monospace", color: "var(--tx)", fontSize: 10 }}>{b.operation}</span>
                    <span style={{ color: "var(--tx2)", fontFamily: "monospace", fontSize: 10, wordBreak: "break-all" }}>{b.target}</span>
                    <span style={{ textAlign: "right", color: "var(--teall)", fontSize: 10, fontWeight: 600 }}>INTERCEPTED</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Extracted Indicators of Compromise (IOCs) */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 12 }}>
              <div style={{ padding: "12px 14px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6 }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: "var(--tx2)", textTransform: "uppercase" }}>
                  EXTRACTED C2 IPS & DOMAINS
                </span>
                <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
                  {selectedReport.extracted_iocs.ips.concat(selectedReport.extracted_iocs.domains).map((net, i) => (
                    <div key={i} style={{ fontSize: 11, fontFamily: "monospace", color: "var(--redl)", background: "var(--bg0)", padding: "3px 8px", borderRadius: 3 }}>
                      {net} [FLAGGED]
                    </div>
                  ))}
                  {selectedReport.extracted_iocs.ips.length === 0 && selectedReport.extracted_iocs.domains.length === 0 && (
                    <div style={{ fontSize: 11, color: "var(--tx3)" }}>No external sockets or domains discovered</div>
                  )}
                </div>
              </div>

              <div style={{ padding: "12px 14px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6 }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: "var(--tx2)", textTransform: "uppercase" }}>
                  DROPPED FILES & MUTEX LOCKS
                </span>
                <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
                  {selectedReport.extracted_iocs.dropped_files.concat(selectedReport.extracted_iocs.mutex_or_pipes).map((f, i) => (
                    <div key={i} style={{ fontSize: 11, fontFamily: "monospace", color: "var(--orangel)", background: "var(--bg0)", padding: "3px 8px", borderRadius: 3 }}>
                      {f}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* MITRE ATT&CK Matrix Techniques */}
            <div style={{ padding: "12px 14px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6 }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: "var(--tx2)", textTransform: "uppercase" }}>
                OBSERVED MITRE ATT&CK TECHNIQUES
              </span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 8 }}>
                {selectedReport.mitre_techniques_observed.map((t, idx) => (
                  <span
                    key={idx}
                    style={{
                      fontSize: 10,
                      padding: "3px 8px",
                      borderRadius: 4,
                      background: "rgba(225,29,72,0.1)",
                      border: "1px solid rgba(225,29,72,0.3)",
                      color: "var(--redl)",
                      fontWeight: 600,
                    }}
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--tx2)" }}>
            Select or launch a malware jail sample to inspect behavioral blueprints.
          </div>
        )}
      </div>
    </div>
  );
}
