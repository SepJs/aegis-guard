import { useState, useEffect } from "react";
import { invoke } from "../lib/ipc/core";
import { listen } from "../lib/ipc/event";
import type { NetworkConnection, DnsQuery, NetworkAttackEvent, NetworkDefenseConfig } from "../types";
import ProtocolDistributionChart from "./ProtocolDistributionChart";

export default function NetworkObserverPanel() {
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [dnsQueries, setDnsQueries] = useState<DnsQuery[]>([]);
  const [attacks, setAttacks] = useState<NetworkAttackEvent[]>([]);
  const [config, setConfig] = useState<NetworkDefenseConfig>({
    ids_enabled: true,
    auto_drop_attackers: true,
    sniffing_detection_active: true,
    anti_port_scan_filter: true,
    dns_tunneling_guard: true,
    blocked_ip_list: [],
  });

  const [search, setSearch] = useState("");
  const [threatOnly, setThreatOnly] = useState(false);
  const [subTab, setSubTab] = useState<"connections" | "attacks" | "dns" | "distribution" | "config" | "ebpf">("connections");
  const [simulating, setSimulating] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [manualIp, setManualIp] = useState("");
  const [ebpfStatus, setEbpfStatus] = useState<any>(null);
  const [ebpfRules, setEbpfRules] = useState<any[]>([]);
  const [ebpfPackets, setEbpfPackets] = useState<any[]>([]);
  const [lastTestedPacket, setLastTestedPacket] = useState<any>(null);

  async function loadEbpfData() {
    try {
      const status = await invoke("ebpf_get_status");
      const rules = await invoke("ebpf_list_rules");
      const pkts = await invoke("ebpf_get_inspected_packets", { limit: 50 });
      if (status) setEbpfStatus(status);
      if (rules) setEbpfRules(rules as any[]);
      if (pkts) setEbpfPackets(pkts as any[]);
    } catch (e) {
      console.error("Failed to load eBPF data:", e);
    }
  }

  async function testEbpfPacket(sample: string) {
    try {
      setSimulating(true);
      const res = await invoke("ebpf_simulate_packet", { sample_type: sample });
      setLastTestedPacket(res);
      await loadEbpfData();
      setStatusMsg(`⚡ eBPF Packet Filtered: [${(res as any).verdict.toUpperCase()}] ${(res as any).reason}`);
      setTimeout(() => setStatusMsg(null), 5000);
    } catch (e) {
      console.error(e);
    } finally {
      setSimulating(false);
    }
  }

  async function loadData() {
    try {
      const conns = await invoke<NetworkConnection[]>("list_network_connections");
      const dns = await invoke<DnsQuery[]>("list_dns_queries");
      const atks = await invoke<NetworkAttackEvent[]>("list_network_attacks");
      const cfg = await invoke<NetworkDefenseConfig>("get_network_defense_config");
      if (conns) setConnections(conns);
      if (dns) setDnsQueries(dns);
      if (atks) setAttacks(atks);
      if (cfg) setConfig(cfg);
      loadEbpfData();
    } catch (err) {
      console.error("Failed to load network data:", err);
    }
  }

  useEffect(() => {
    loadData();

    // Listen for live network updates from observer engine
    const unsubNet = listen<{ connections: NetworkConnection[] }>("net-update", (ev) => {
      if (ev.payload?.connections) {
        setConnections([...ev.payload.connections]);
      }
    });

    const unsubAtk = listen<NetworkAttackEvent>("net-attack", (ev) => {
      if (ev.payload) {
        setAttacks((prev) => [ev.payload, ...prev]);
        setStatusMsg(`🚨 INCOMING THREAT DETECTED & CONTAINED: ${ev.payload.attack_type} from ${ev.payload.source_ip}`);
      }
    });

    return () => {
      unsubNet.then((f) => f && f());
      unsubAtk.then((f) => f && f());
    };
  }, []);

  async function handleBlockIp(ip: string) {
    if (ip === "*" || ip === "0.0.0.0" || ip === "127.0.0.1") return;
    try {
      await invoke("block_remote_ip", { ip });
      setStatusMsg(`Remote endpoint IP ${ip} dropped & null-routed across all network interfaces.`);
      setTimeout(() => setStatusMsg(null), 4000);
      loadData();
    } catch (err: any) {
      console.error("Error blocking IP:", err);
    }
  }

  async function handleUnblockIp(ip: string) {
    try {
      await invoke("unblock_remote_ip", { ip });
      setStatusMsg(`Firewall restriction lifted: IP ${ip} unblocked.`);
      setTimeout(() => setStatusMsg(null), 4000);
      loadData();
    } catch (err: any) {
      console.error("Error unblocking IP:", err);
    }
  }

  async function handleSimulateAttack(type: NetworkAttackEvent["attack_type"]) {
    setSimulating(true);
    try {
      const res: any = await invoke("simulate_network_attack", { attack_type: type });
      setStatusMsg(`Attack '${type}' simulated from ${res.source_ip}. Defense applied: ${res.defense_action}`);
      setTimeout(() => setStatusMsg(null), 5000);
      loadData();
    } catch (err: any) {
      console.error("Simulation error:", err);
    } finally {
      setSimulating(false);
    }
  }

  async function toggleConfigOption(key: keyof NetworkDefenseConfig) {
    if (typeof config[key] !== "boolean") return;
    const newConfig = {
      ...config,
      [key]: !config[key],
    };
    try {
      const updated = await invoke<NetworkDefenseConfig>("update_network_defense_config", { config: newConfig });
      if (updated) setConfig(updated);
      setStatusMsg(`Network defense policy synchronized.`);
      setTimeout(() => setStatusMsg(null), 3000);
    } catch (err) {
      console.error("Config update error:", err);
    }
  }

  // Filtered connections
  const filteredConns = connections.filter((c) => {
    if (threatOnly && c.threat === "safe") return false;
    if (!search) return true;
    const s = search.toLowerCase();
    return (
      c.process_name.toLowerCase().includes(s) ||
      c.remote_addr.toLowerCase().includes(s) ||
      c.local_addr.toLowerCase().includes(s) ||
      String(c.local_port).includes(s) ||
      String(c.remote_port).includes(s) ||
      String(c.pid).includes(s)
    );
  });

  const suspiciousCount = connections.filter((c) => c.threat !== "safe").length;
  const establishedCount = connections.filter((c) => c.state === "ESTABLISHED").length;
  const totalTx = connections.reduce((acc, c) => acc + c.bytes_tx, 0);
  const totalRx = connections.reduce((acc, c) => acc + c.bytes_rx, 0);

  return (
    <div className="panel" id="network-observer-panel" style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      {/* Panel Top Header */}
      <div className="panel-header" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 16px", borderBottom: "1px solid var(--border)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className="panel-title" style={{ fontWeight: 700, letterSpacing: "0.08em" }}>
            NETWORK IDS & ATTACK / EAVESDROPPING OBSERVER
          </span>
          <span className="pstat" style={{ background: "rgba(13,148,136,0.15)", color: "var(--teall)", border: "1px solid var(--teal)", padding: "2px 8px", borderRadius: 4, fontSize: 10 }}>
            eBPF SOCKET IDS ACTIVE
          </span>
          <span className="pstat" style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, background: "var(--bg1)" }}>
            {connections.length} SOCKETS ({establishedCount} ESTABLISHED)
          </span>
          {suspiciousCount > 0 && (
            <span className="pstat" style={{ background: "rgba(225,29,72,0.15)", color: "var(--redl)", border: "1px solid var(--red)", padding: "2px 8px", borderRadius: 4, fontSize: 10 }}>
              {suspiciousCount} THREATS
            </span>
          )}
        </div>

        <div className="toolbar-right" style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <input
            type="text"
            className="search-input"
            placeholder="Search IP, Port, Process…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ width: 180, padding: "5px 8px", fontSize: 11, background: "var(--bg)", border: "1px solid var(--border)", borderRadius: 4, color: "var(--tx)" }}
          />
          <button
            className={`sm-btn ${threatOnly ? "sm-btn--active" : ""}`}
            onClick={() => setThreatOnly(!threatOnly)}
            style={{ fontSize: 11, padding: "5px 10px", borderRadius: 4 }}
          >
            {threatOnly ? "THREATS ONLY [ON]" : "ALL SOCKETS"}
          </button>
        </div>
      </div>

      {/* Real-time Network Metrics Strip & Attack Simulators */}
      <div className="scan-summary-bar" style={{ display: "flex", flexWrap: "wrap", gap: 12, padding: "8px 16px", alignItems: "center", background: "var(--bg1)", borderBottom: "1px solid var(--border)" }}>
        <div className="sum-pill" style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", background: "var(--bg0)", borderRadius: 4, border: "1px solid var(--border)" }}>
          <span className="sum-pill-val" style={{ fontSize: 12, fontWeight: 700, color: "var(--teall)" }}>
            {(totalTx / 1024).toFixed(1)} KB
          </span>
          <span className="sum-pill-label" style={{ fontSize: 9, color: "var(--tx2)", textTransform: "uppercase" }}>OUTBOUND TX</span>
        </div>

        <div className="sum-pill" style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", background: "var(--bg0)", borderRadius: 4, border: "1px solid var(--border)" }}>
          <span className="sum-pill-val" style={{ fontSize: 12, fontWeight: 700, color: "var(--vl)" }}>
            {(totalRx / 1024).toFixed(1)} KB
          </span>
          <span className="sum-pill-label" style={{ fontSize: 9, color: "var(--tx2)", textTransform: "uppercase" }}>INBOUND RX</span>
        </div>

        <div className="sum-pill" style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", background: "var(--bg0)", borderRadius: 4, border: "1px solid var(--border)" }}>
          <span className="sum-pill-val" style={{ fontSize: 12, fontWeight: 700, color: attacks.length > 0 ? "var(--redl)" : "var(--tx2)" }}>
            {attacks.length}
          </span>
          <span className="sum-pill-label" style={{ fontSize: 9, color: "var(--tx2)", textTransform: "uppercase" }}>ATTACKS INTERCEPTED</span>
        </div>

        <div
          onClick={() => setSubTab("distribution")}
          className="sum-pill"
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            padding: "4px 10px",
            background: subTab === "distribution" ? "rgba(139, 92, 246, 0.22)" : "var(--bg0)",
            borderRadius: 4,
            border: subTab === "distribution" ? "1px solid #8b5cf6" : "1px solid var(--border)",
            cursor: "pointer",
          }}
          title="Open real-time packet protocol distribution visualization"
        >
          <span style={{ fontSize: 11 }}>📊</span>
          <span className="sum-pill-label" style={{ fontSize: 9, color: subTab === "distribution" ? "#c4b5fd" : "var(--tx1)", fontWeight: 700, textTransform: "uppercase" }}>
            PROTOCOL CHARTS (TCP/UDP/ICMP)
          </span>
        </div>

        {/* Attack Simulation Quick Buttons for Verification */}
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginLeft: "auto" }}>
          <span style={{ fontSize: 10, color: "var(--tx2)", textTransform: "uppercase" }}>TEST ATTACK:</span>
          <button
            className="action-btn"
            style={{ fontSize: 10, padding: "4px 8px", background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: 3, cursor: "pointer", color: "var(--redl)" }}
            onClick={() => handleSimulateAttack("ARP_POISON_SNIFF")}
            disabled={simulating}
          >
            ARP SNIFF (MITM)
          </button>
          <button
            className="action-btn"
            style={{ fontSize: 10, padding: "4px 8px", background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: 3, cursor: "pointer", color: "var(--orangel)" }}
            onClick={() => handleSimulateAttack("PORT_SCAN_RECON")}
            disabled={simulating}
          >
            PORT SCAN
          </button>
          <button
            className="action-btn"
            style={{ fontSize: 10, padding: "4px 8px", background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: 3, cursor: "pointer", color: "var(--redl)" }}
            onClick={() => handleSimulateAttack("SYN_FLOOD_DOS")}
            disabled={simulating}
          >
            SYN FLOOD
          </button>
          <button
            className="action-btn"
            style={{ fontSize: 10, padding: "4px 8px", background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: 3, cursor: "pointer", color: "var(--redl)" }}
            onClick={() => handleSimulateAttack("DNS_TUNNEL_EXFIL")}
            disabled={simulating}
          >
            DNS TUNNEL
          </button>
          <button
            className="action-btn"
            style={{ fontSize: 10, padding: "4px 8px", background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: 3, cursor: "pointer", color: "var(--redl)" }}
            onClick={() => handleSimulateAttack("REVERSE_TCP_C2")}
            disabled={simulating}
          >
            REVERSE TCP C2
          </button>
        </div>

        {/* View switcher */}
        <div style={{ display: "flex", gap: 4 }}>
          <button
            className={`sm-btn ${subTab === "connections" ? "sm-btn--active" : ""}`}
            onClick={() => setSubTab("connections")}
            style={{ fontSize: 10, padding: "4px 10px", borderRadius: 4 }}
          >
            SOCKETS ({filteredConns.length})
          </button>
          <button
            className={`sm-btn ${subTab === "attacks" ? "sm-btn--active" : ""}`}
            onClick={() => setSubTab("attacks")}
            style={{ fontSize: 10, padding: "4px 10px", borderRadius: 4 }}
          >
            ATTACK EVENTS ({attacks.length})
          </button>
          <button
            className={`sm-btn ${subTab === "dns" ? "sm-btn--active" : ""}`}
            onClick={() => setSubTab("dns")}
            style={{ fontSize: 10, padding: "4px 10px", borderRadius: 4 }}
          >
            DNS ({dnsQueries.length})
          </button>
          <button
            className={`sm-btn ${subTab === "distribution" ? "sm-btn--active" : ""}`}
            onClick={() => setSubTab("distribution")}
            style={{
              fontSize: 10,
              padding: "4px 10px",
              borderRadius: 4,
              borderColor: subTab === "distribution" ? "#8b5cf6" : undefined,
              color: subTab === "distribution" ? "#c4b5fd" : undefined,
              fontWeight: 700,
            }}
          >
            📊 PROTOCOL CHARTS (TCP/UDP/ICMP)
          </button>
          <button
            className={`sm-btn ${subTab === "config" ? "sm-btn--active" : ""}`}
            onClick={() => setSubTab("config")}
            style={{ fontSize: 10, padding: "4px 10px", borderRadius: 4 }}
          >
            IDS POLICIES
          </button>
          <button
            className={`sm-btn ${subTab === "ebpf" ? "sm-btn--active" : ""}`}
            onClick={() => {
              setSubTab("ebpf");
              loadEbpfData();
            }}
            style={{
              fontSize: 10,
              padding: "4px 10px",
              borderRadius: 4,
              borderColor: subTab === "ebpf" ? "var(--teal)" : undefined,
              color: subTab === "ebpf" ? "var(--teall)" : undefined,
              fontWeight: 700,
            }}
          >
            ⚡ eBPF FILTER LAB
          </button>
        </div>
      </div>

      {statusMsg && (
        <div
          style={{
            margin: "8px 16px",
            padding: "8px 14px",
            background: "rgba(13,148,136,0.12)",
            border: "1px solid var(--teal)",
            borderRadius: 4,
            fontSize: 11,
            color: "var(--teall)",
          }}
        >
          {statusMsg}
        </div>
      )}

      {/* Subtab 1: Connections */}
      {subTab === "connections" && (
        <div style={{ display: "flex", flexDirection: "column", flex: 1, overflow: "hidden" }}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "55px 150px 160px 110px 95px 120px 1fr 85px",
              padding: "7px 16px",
              fontSize: 9,
              color: "var(--tx2)",
              letterSpacing: ".08em",
              textTransform: "uppercase",
              borderBottom: "1px solid var(--border)",
              background: "var(--bg1)",
              flexShrink: 0,
              fontWeight: 600,
            }}
          >
            <span>PROTO</span>
            <span>LOCAL ENDPOINT</span>
            <span>REMOTE ENDPOINT</span>
            <span>PROCESS</span>
            <span>STATE</span>
            <span>TRAFFIC</span>
            <span>VERDICT / THREAT</span>
            <span style={{ textAlign: "right" }}>ACTION</span>
          </div>

          <div style={{ flex: 1, overflowY: "auto" }}>
            {filteredConns.length === 0 ? (
              <div style={{ padding: 32, textAlign: "center", color: "var(--tx2)", fontSize: 12 }}>
                NO ACTIVE SOCKET CONNECTIONS RECORDED.
              </div>
            ) : (
              filteredConns.map((c) => {
              const isBad = c.threat !== "safe";
              return (
                <div
                  key={c.id}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "55px 150px 160px 110px 95px 120px 1fr 85px",
                    padding: "8px 16px",
                    borderBottom: "1px solid var(--border)",
                    alignItems: "center",
                    fontSize: 11,
                    background: isBad ? "rgba(225,29,72,0.04)" : "transparent",
                    borderLeft: isBad ? "3px solid var(--red)" : "3px solid transparent",
                  }}
                >
                  <span style={{ fontFamily: "monospace", fontSize: 10, color: "var(--tx2)" }}>{c.proto}</span>
                  <span style={{ fontFamily: "monospace", fontSize: 10 }}>{c.local_addr}:{c.local_port}</span>
                  <span style={{ fontFamily: "monospace", fontSize: 10, color: isBad ? "var(--redl)" : "var(--tx)" }}>
                    {c.remote_addr}:{c.remote_port}
                  </span>
                  <span style={{ fontSize: 11 }}>{c.process_name}</span>
                  <span style={{ fontSize: 10, color: c.state === "ESTABLISHED" ? "var(--teall)" : "var(--tx2)" }}>{c.state}</span>
                  <span style={{ fontSize: 10, fontFamily: "monospace", color: "var(--tx2)" }}>
                    ↑{(c.bytes_tx / 1024).toFixed(1)}k ↓{(c.bytes_rx / 1024).toFixed(1)}k
                  </span>
                  <span>
                    {isBad ? (
                      <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 3, background: "rgba(225,29,72,0.15)", color: "var(--redl)", fontWeight: 700 }}>
                        {c.threat_reason || "SUSPICIOUS CONNECTION"}
                      </span>
                    ) : (
                      <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 3, background: "rgba(13,148,136,0.15)", color: "var(--teall)", fontWeight: 600 }}>
                        CLEAN
                      </span>
                    )}
                  </span>
                  <span style={{ textAlign: "right" }}>
                    {c.threat !== "c2_blocked" ? (
                      <button
                        style={{ fontSize: 9, padding: "3px 8px", borderRadius: 3, background: "rgba(225,29,72,0.12)", border: "1px solid var(--red)", color: "var(--redl)", cursor: "pointer" }}
                        onClick={() => handleBlockIp(c.remote_addr)}
                      >
                        BLOCK IP
                      </button>
                    ) : (
                      <span style={{ fontSize: 9, color: "var(--redl)", fontWeight: 700 }}>BLOCKED</span>
                    )}
                  </span>
                </div>
              );
            })
          )}
          </div>
        </div>
      )}

      {/* Subtab 2: Attack Events & Eavesdropping / Sniffing Alarms */}
      {subTab === "attacks" && (
        <div style={{ display: "flex", flexDirection: "column", flex: 1, overflow: "hidden" }}>
          {/* Active Attack Defense & Simulation Toolbar */}
          <div
            style={{
              padding: "10px 16px",
              background: "var(--bg2)",
              borderBottom: "1px solid var(--border)",
              display: "flex",
              flexWrap: "wrap",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 10,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: "var(--tx)", display: "flex", alignItems: "center", gap: 5 }}>
                <span style={{ color: "var(--red)" }}>⚡</span> SIMULATE INTERNET ATTACK:
              </span>
              <button
                disabled={simulating}
                onClick={() => handleSimulateAttack("ARP_POISON_SNIFF")}
                style={{
                  padding: "4px 10px",
                  fontSize: 10,
                  fontWeight: 600,
                  borderRadius: 4,
                  border: "1px solid rgba(245,158,11,0.4)",
                  background: "rgba(245,158,11,0.1)",
                  color: "var(--orangel)",
                  cursor: "pointer",
                }}
                title="Simulate promiscuous mode raw packet sniffing and unauthorized eavesdropping"
              >
                📡 Packet Sniffing
              </button>
              <button
                disabled={simulating}
                onClick={() => handleSimulateAttack("SYN_FLOOD_DOS")}
                style={{
                  padding: "4px 10px",
                  fontSize: 10,
                  fontWeight: 600,
                  borderRadius: 4,
                  border: "1px solid rgba(225,29,72,0.4)",
                  background: "rgba(225,29,72,0.1)",
                  color: "var(--redl)",
                  cursor: "pointer",
                }}
                title="Simulate high-volume TCP SYN flood denial of service attack"
              >
                🌊 SYN Flood DoS
              </button>
              <button
                disabled={simulating}
                onClick={() => handleSimulateAttack("PORT_SCAN_RECON")}
                style={{
                  padding: "4px 10px",
                  fontSize: 10,
                  fontWeight: 600,
                  borderRadius: 4,
                  border: "1px solid rgba(147,51,234,0.4)",
                  background: "rgba(147,51,234,0.1)",
                  color: "var(--purplel)",
                  cursor: "pointer",
                }}
                title="Simulate stealth port scanning (FIN/NULL/XMAS probe flags)"
              >
                🔍 Stealth Port Scan
              </button>
              <button
                disabled={simulating}
                onClick={() => handleSimulateAttack("REVERSE_TCP_C2")}
                style={{
                  padding: "4px 10px",
                  fontSize: 10,
                  fontWeight: 600,
                  borderRadius: 4,
                  border: "1px solid rgba(225,29,72,0.4)",
                  background: "rgba(225,29,72,0.1)",
                  color: "var(--redl)",
                  cursor: "pointer",
                }}
                title="Simulate reverse shell interactive C2 connection attempt"
              >
                🐚 Reverse Shell C2
              </button>
              <button
                disabled={simulating}
                onClick={() => handleSimulateAttack("DNS_TUNNEL_EXFIL")}
                style={{
                  padding: "4px 10px",
                  fontSize: 10,
                  fontWeight: 600,
                  borderRadius: 4,
                  border: "1px solid rgba(13,148,136,0.4)",
                  background: "rgba(13,148,136,0.1)",
                  color: "var(--teall)",
                  cursor: "pointer",
                }}
                title="Simulate high-entropy base32 DNS tunneling data exfiltration"
              >
                📤 DNS Exfiltration
              </button>
            </div>

            {/* Manual IP Null-Route Enforcer */}
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <input
                type="text"
                placeholder="Enter IP (e.g. 185.220.101.5)"
                value={manualIp}
                onChange={(e) => setManualIp(e.target.value)}
                style={{
                  background: "var(--bg3)",
                  border: "1px solid var(--border)",
                  borderRadius: 4,
                  padding: "4px 8px",
                  fontSize: 11,
                  color: "var(--tx)",
                  width: 170,
                  fontFamily: "monospace",
                }}
              />
              <button
                disabled={!manualIp.trim()}
                onClick={() => {
                  if (manualIp.trim()) {
                    handleBlockIp(manualIp.trim());
                    setManualIp("");
                  }
                }}
                style={{
                  padding: "4px 10px",
                  fontSize: 10,
                  fontWeight: 700,
                  borderRadius: 4,
                  border: "1px solid var(--red)",
                  background: "var(--red)",
                  color: "#fff",
                  cursor: manualIp.trim() ? "pointer" : "not-allowed",
                  opacity: manualIp.trim() ? 1 : 0.6,
                }}
              >
                ⛔ Drop IP
              </button>
            </div>
          </div>

          {/* Table Header */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "130px 170px 140px 130px 1fr 140px",
              padding: "7px 16px",
              fontSize: 9,
              color: "var(--tx2)",
              letterSpacing: ".08em",
              textTransform: "uppercase",
              borderBottom: "1px solid var(--border)",
              background: "var(--bg1)",
              flexShrink: 0,
              fontWeight: 600,
            }}
          >
            <span>ATTACK TYPE</span>
            <span>SOURCE & PORT</span>
            <span>TARGET DEST</span>
            <span>SEVERITY / PROTO</span>
            <span>IDS PACKET FORENSICS & SIGNATURE</span>
            <span style={{ textAlign: "right" }}>DEFENSE ACTION</span>
          </div>

          <div style={{ flex: 1, overflowY: "auto" }}>
            {attacks.length === 0 ? (
              <div style={{ padding: 32, textAlign: "center", color: "var(--tx2)", fontSize: 12 }}>
                No network attacks recorded. Click any simulation button above to trigger an attack scenario and test active firewall response.
              </div>
            ) : (
              attacks.map((a) => {
                const isBlocked = config.blocked_ip_list.includes(a.source_ip);
                return (
                  <div
                    key={a.id}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "130px 170px 140px 130px 1fr 140px",
                      padding: "10px 16px",
                      borderBottom: "1px solid var(--border)",
                      alignItems: "center",
                      fontSize: 11,
                      background: a.severity === "critical" ? "rgba(225,29,72,0.06)" : "transparent",
                      borderLeft: a.severity === "critical" ? "3px solid var(--red)" : "3px solid var(--orange)",
                    }}
                  >
                    <div>
                      <div style={{ fontSize: 10, fontWeight: 700, color: a.severity === "critical" ? "var(--redl)" : "var(--orangel)" }}>
                        {a.attack_type === "ARP_POISON_SNIFF"
                          ? "📡 Packet Sniffing"
                          : a.attack_type === "SYN_FLOOD_DOS"
                          ? "🌊 SYN Flood DoS"
                          : a.attack_type === "PORT_SCAN_RECON"
                          ? "🔍 Stealth Scan"
                          : a.attack_type === "REVERSE_TCP_C2"
                          ? "🐚 Reverse C2"
                          : a.attack_type === "DNS_TUNNEL_EXFIL"
                          ? "📤 DNS Exfiltration"
                          : a.attack_type}
                      </div>
                      <div style={{ fontSize: 8, color: "var(--tx2)", textTransform: "uppercase" }}>{a.attack_type}</div>
                    </div>

                    <div style={{ fontFamily: "monospace", fontSize: 10 }}>
                      <span style={{ color: isBlocked ? "var(--teall)" : "var(--redl)", fontWeight: 600 }}>{a.source_ip}</span>:{a.source_port}
                      {isBlocked && (
                        <div style={{ fontSize: 8, color: "var(--teall)", fontWeight: 700 }}>[NULL-ROUTED]</div>
                      )}
                    </div>

                    <div style={{ fontFamily: "monospace", fontSize: 10 }}>
                      {a.target_ip}:{a.target_port}
                    </div>

                    <div>
                      <span
                        style={{
                          fontSize: 9,
                          padding: "1px 6px",
                          borderRadius: 3,
                          background: a.severity === "critical" ? "rgba(225,29,72,0.18)" : "rgba(245,158,11,0.18)",
                          color: a.severity === "critical" ? "var(--redl)" : "var(--orangel)",
                          fontWeight: 700,
                        }}
                      >
                        {a.severity.toUpperCase()} [{a.protocol}]
                      </span>
                    </div>

                    <div>
                      <div style={{ fontSize: 11, color: "var(--tx)", fontWeight: 500 }}>{a.packet_summary}</div>
                      <div style={{ fontSize: 9, color: "var(--tx2)", fontFamily: "monospace", marginTop: 2 }}>{a.signature_hit}</div>
                    </div>

                    <div style={{ textAlign: "right", display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
                      <span
                        style={{
                          fontSize: 9,
                          padding: "2px 6px",
                          borderRadius: 4,
                          background: "rgba(13,148,136,0.15)",
                          border: "1px solid var(--teal)",
                          color: "var(--teall)",
                          fontWeight: 700,
                        }}
                      >
                        {a.defense_action}
                      </span>
                      {isBlocked ? (
                        <button
                          onClick={() => handleUnblockIp(a.source_ip)}
                          style={{
                            fontSize: 9,
                            padding: "2px 6px",
                            borderRadius: 3,
                            background: "transparent",
                            border: "1px solid var(--border)",
                            color: "var(--tx2)",
                            cursor: "pointer",
                          }}
                        >
                          Lift Block (Allow IP)
                        </button>
                      ) : (
                        <button
                          onClick={() => handleBlockIp(a.source_ip)}
                          style={{
                            fontSize: 9,
                            padding: "2px 6px",
                            borderRadius: 3,
                            background: "rgba(225,29,72,0.2)",
                            border: "1px solid var(--red)",
                            color: "var(--redl)",
                            cursor: "pointer",
                            fontWeight: 600,
                          }}
                        >
                          🛡️ Block IP (Null-Route)
                        </button>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* Subtab 3: DNS Queries */}
      {subTab === "dns" && (
        <div style={{ display: "flex", flexDirection: "column", flex: 1, overflow: "hidden" }}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "80px 220px 60px 140px 120px 1fr",
              padding: "7px 16px",
              fontSize: 9,
              color: "var(--tx2)",
              letterSpacing: ".08em",
              textTransform: "uppercase",
              borderBottom: "1px solid var(--border)",
              background: "var(--bg1)",
              flexShrink: 0,
              fontWeight: 600,
            }}
          >
            <span>TIME</span>
            <span>QUERY DOMAIN</span>
            <span>TYPE</span>
            <span>RESOLVED IP</span>
            <span>PROCESS</span>
            <span>VERDICT</span>
          </div>

          <div style={{ flex: 1, overflowY: "auto" }}>
            {dnsQueries.length === 0 ? (
              <div style={{ padding: 32, textAlign: "center", color: "var(--tx2)", fontSize: 12 }}>
                NO DNS QUERIES CAPTURED YET.
              </div>
            ) : (
              dnsQueries.map((q) => {
                const isBad = q.verdict !== "safe";
                return (
                  <div
                    key={q.id}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "80px 220px 60px 140px 120px 1fr",
                      padding: "8px 16px",
                      borderBottom: "1px solid var(--border)",
                      alignItems: "center",
                      fontSize: 11,
                      borderLeft: isBad ? "3px solid var(--red)" : "3px solid transparent",
                      background: isBad ? "rgba(225,29,72,0.05)" : "transparent",
                    }}
                  >
                    <span style={{ color: "var(--tx2)", fontSize: 10 }}>
                      {new Date(q.ts).toLocaleTimeString("en-GB", { hour12: false })}
                    </span>
                    <span style={{ color: isBad ? "var(--redl)" : "var(--tx)", fontWeight: isBad ? 700 : 400, fontFamily: "monospace", fontSize: 11 }}>
                      {q.query}
                    </span>
                    <span style={{ color: "var(--tx2)", fontSize: 10 }}>{q.qtype}</span>
                    <span style={{ color: "var(--tx)", fontFamily: "monospace", fontSize: 11 }}>{q.resolved_ip}</span>
                    <span style={{ color: "var(--tx2)", fontSize: 11 }}>{q.process_name}</span>
                    <span>
                      {isBad ? (
                        <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 3, background: "rgba(225,29,72,0.15)", color: "var(--redl)", fontWeight: 700 }}>
                          ⚠ C2 FLAGGED
                        </span>
                      ) : (
                        <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 3, background: "rgba(13,148,136,0.15)", color: "var(--teall)", fontWeight: 600 }}>
                          BENIGN
                        </span>
                      )}
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* Subtab 4: IDS Defense & Anti-Eavesdropping Policies */}
      {subTab === "config" && (
        <div style={{ flex: 1, overflowY: "auto", padding: "20px 24px", display: "flex", flexDirection: "column", gap: 16 }}>
          <h3 style={{ margin: 0, fontSize: 15, fontWeight: 700, color: "var(--tx)" }}>
            AUTOMATED NETWORK DEFENSE & ANTI-SNIFFING HARDENING POLICIES
          </h3>
          <p style={{ margin: 0, fontSize: 12, color: "var(--tx2)" }}>
            Configure active mitigation filters. Any detected eavesdropping (ARP poisoning, stealth port scans, DNS tunnels, volumetric floods) will be null-routed automatically.
          </p>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 14 }}>
            <div style={{ padding: "14px 18px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tx)" }}>Intrusion Detection System (IDS)</div>
                <div style={{ fontSize: 10, color: "var(--tx2)", marginTop: 2 }}>Inspects inbound/outbound packets using eBPF filters</div>
              </div>
              <button
                onClick={() => toggleConfigOption("ids_enabled")}
                style={{
                  padding: "5px 12px",
                  fontSize: 11,
                  fontWeight: 600,
                  borderRadius: 4,
                  border: "none",
                  cursor: "pointer",
                  background: config.ids_enabled ? "var(--teal)" : "var(--bg)",
                  color: config.ids_enabled ? "#fff" : "var(--tx2)",
                }}
              >
                {config.ids_enabled ? "ACTIVE" : "DISABLED"}
              </button>
            </div>

            <div style={{ padding: "14px 18px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tx)" }}>Auto-Drop Attacker IPs</div>
                <div style={{ fontSize: 10, color: "var(--tx2)", marginTop: 2 }}>Automatically null-routes source IP on confirmed attacks</div>
              </div>
              <button
                onClick={() => toggleConfigOption("auto_drop_attackers")}
                style={{
                  padding: "5px 12px",
                  fontSize: 11,
                  fontWeight: 600,
                  borderRadius: 4,
                  border: "none",
                  cursor: "pointer",
                  background: config.auto_drop_attackers ? "var(--teal)" : "var(--bg)",
                  color: config.auto_drop_attackers ? "#fff" : "var(--tx2)",
                }}
              >
                {config.auto_drop_attackers ? "ENABLED" : "DISABLED"}
              </button>
            </div>

            <div style={{ padding: "14px 18px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tx)" }}>Anti-Eavesdropping / ARP Sniff Guard</div>
                <div style={{ fontSize: 10, color: "var(--tx2)", marginTop: 2 }}>Detects gratuitous ARP spoofing & MITM packet taps</div>
              </div>
              <button
                onClick={() => toggleConfigOption("sniffing_detection_active")}
                style={{
                  padding: "5px 12px",
                  fontSize: 11,
                  fontWeight: 600,
                  borderRadius: 4,
                  border: "none",
                  cursor: "pointer",
                  background: config.sniffing_detection_active ? "var(--teal)" : "var(--bg)",
                  color: config.sniffing_detection_active ? "#fff" : "var(--tx2)",
                }}
              >
                {config.sniffing_detection_active ? "ENABLED" : "DISABLED"}
              </button>
            </div>

            <div style={{ padding: "14px 18px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tx)" }}>Anti-Port Scan Recon Filter</div>
                <div style={{ fontSize: 10, color: "var(--tx2)", marginTop: 2 }}>Suppresses and resets horizontal Nmap/SYN port sweeps</div>
              </div>
              <button
                onClick={() => toggleConfigOption("anti_port_scan_filter")}
                style={{
                  padding: "5px 12px",
                  fontSize: 11,
                  fontWeight: 600,
                  borderRadius: 4,
                  border: "none",
                  cursor: "pointer",
                  background: config.anti_port_scan_filter ? "var(--teal)" : "var(--bg)",
                  color: config.anti_port_scan_filter ? "#fff" : "var(--tx2)",
                }}
              >
                {config.anti_port_scan_filter ? "ENABLED" : "DISABLED"}
              </button>
            </div>

            <div style={{ padding: "14px 18px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tx)" }}>DNS Tunneling Exfiltration Guard</div>
                <div style={{ fontSize: 10, color: "var(--tx2)", marginTop: 2 }}>Flags base32/hex encrypted payload extraction via UDP/53</div>
              </div>
              <button
                onClick={() => toggleConfigOption("dns_tunneling_guard")}
                style={{
                  padding: "5px 12px",
                  fontSize: 11,
                  fontWeight: 600,
                  borderRadius: 4,
                  border: "none",
                  cursor: "pointer",
                  background: config.dns_tunneling_guard ? "var(--teal)" : "var(--bg)",
                  color: config.dns_tunneling_guard ? "#fff" : "var(--tx2)",
                }}
              >
                {config.dns_tunneling_guard ? "ENABLED" : "DISABLED"}
              </button>
            </div>
          </div>

          <div style={{ padding: "14px 18px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tx)", marginBottom: 8 }}>
              ACTIVE BLOCKED REMOTE IP LIST ({config.blocked_ip_list.length})
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {config.blocked_ip_list.map((ip, idx) => (
                <span
                  key={idx}
                  style={{
                    fontSize: 11,
                    fontFamily: "monospace",
                    padding: "3px 8px",
                    background: "rgba(225,29,72,0.12)",
                    border: "1px solid var(--red)",
                    borderRadius: 4,
                    color: "var(--redl)",
                  }}
                >
                  {ip} [NULL-ROUTED]
                </span>
              ))}
              {config.blocked_ip_list.length === 0 && (
                <span style={{ fontSize: 11, color: "var(--tx2)" }}>No IP addresses currently on blocklist</span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Subtab 5: eBPF Socket Filter Lab */}
      {subTab === "ebpf" && (
        <div style={{ flex: 1, overflowY: "auto", padding: "16px 20px", display: "flex", flexDirection: "column", gap: 14 }}>
          {/* Engine Header Card */}
          <div style={{ padding: "14px 18px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: "var(--tx0)", letterSpacing: "0.04em", display: "flex", alignItems: "center", gap: 8 }}>
                <span>⚡ IN-KERNEL eBPF SOCKET IDS FILTER (SO_ATTACH_BPF)</span>
                <span style={{ fontSize: 9, padding: "2px 6px", background: "rgba(13,148,136,0.18)", color: "var(--teall)", borderRadius: 3, border: "1px solid var(--teal)" }}>
                  JIT COMPILED ({ebpfStatus?.instructions_count || 12} INSTRUCTIONS)
                </span>
              </div>
              <div style={{ fontSize: 11, color: "var(--tx2)", marginTop: 4 }}>
                Direct L4 packet inspection hooked via kernel socket filter on interface <code style={{ color: "var(--tx0)" }}>{ebpfStatus?.interface || "eth0"}</code>
              </div>
            </div>
            <div style={{ display: "flex", gap: 12, textAlign: "right" }}>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: "var(--tx0)" }}>{ebpfStatus?.packets_inspected || 0}</div>
                <div style={{ fontSize: 9, color: "var(--tx2)" }}>INSPECTED</div>
              </div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: "var(--amberl)" }}>{ebpfStatus?.threats_detected || 0}</div>
                <div style={{ fontSize: 9, color: "var(--tx2)" }}>THREATS DETECTED</div>
              </div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: "var(--redl)" }}>{ebpfStatus?.packets_dropped || 0}</div>
                <div style={{ fontSize: 9, color: "var(--tx2)" }}>DROPPED</div>
              </div>
            </div>
          </div>

          {/* Test & Simulation Section */}
          <div style={{ padding: "14px 18px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--tx0)", letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 10 }}>
              Live eBPF Packet Verification & Simulation Bench
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button
                className="action-btn"
                onClick={() => testEbpfPacket("c2_shell")}
                disabled={simulating}
                style={{ fontSize: 10, padding: "5px 12px", background: "rgba(225,29,72,0.15)", borderColor: "var(--red)", color: "var(--redl)" }}
              >
                ⚡ TEST C2 REVERSE SHELL (PORT 4444)
              </button>
              <button
                className="action-btn"
                onClick={() => testEbpfPacket("dns_tunnel")}
                disabled={simulating}
                style={{ fontSize: 10, padding: "5px 12px", background: "rgba(245,158,11,0.15)", borderColor: "var(--amber)", color: "var(--amberl)" }}
              >
                ⚡ TEST DNS COVERT TUNNEL (PORT 53)
              </button>
              <button
                className="action-btn"
                onClick={() => testEbpfPacket("cobalt_strike")}
                disabled={simulating}
                style={{ fontSize: 10, padding: "5px 12px", background: "rgba(225,29,72,0.15)", borderColor: "var(--red)", color: "var(--redl)" }}
              >
                ⚡ TEST COBALT STRIKE BEACON (PORT 8888)
              </button>
              <button
                className="action-btn"
                onClick={() => testEbpfPacket("benign_tls")}
                disabled={simulating}
                style={{ fontSize: 10, padding: "5px 12px", background: "rgba(13,148,136,0.15)", borderColor: "var(--teal)", color: "var(--teall)" }}
              >
                ✓ TEST BENIGN TLS 1.3 (PORT 443)
              </button>
            </div>
          </div>

          {/* Last Tested Packet Detail */}
          {lastTestedPacket && (
            <div style={{ padding: "14px 18px", background: "var(--bg0)", border: `1px solid ${lastTestedPacket.verdict === "drop" ? "var(--red)" : lastTestedPacket.verdict === "alert" ? "var(--amber)" : "var(--teal)"}`, borderRadius: 6, display: "flex", flexDirection: "column", gap: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{
                    fontSize: 10,
                    fontWeight: 700,
                    padding: "2px 8px",
                    borderRadius: 3,
                    background: lastTestedPacket.verdict === "drop" ? "var(--red)" : lastTestedPacket.verdict === "alert" ? "var(--amber)" : "var(--teal)",
                    color: "#fff",
                  }}>
                    KERNEL VERDICT: {lastTestedPacket.verdict.toUpperCase()}
                  </span>
                  <span style={{ fontSize: 11, fontWeight: 700, color: "var(--tx0)" }}>
                    {lastTestedPacket.reason}
                  </span>
                </div>
                <span style={{ fontSize: 10, color: "var(--tx2)", fontFamily: "var(--mono)" }}>
                  {lastTestedPacket.proto} {lastTestedPacket.src_ip}:{lastTestedPacket.src_port} → {lastTestedPacket.dst_ip}:{lastTestedPacket.dst_port}
                </span>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10, fontSize: 10, background: "var(--bg1)", padding: "8px 12px", borderRadius: 4 }}>
                <div><span style={{ color: "var(--tx2)" }}>Length: </span><span style={{ color: "var(--tx0)", fontFamily: "var(--mono)" }}>{lastTestedPacket.packet_len} bytes</span></div>
                <div><span style={{ color: "var(--tx2)" }}>Entropy: </span><span style={{ color: lastTestedPacket.payload_entropy > 6 ? "var(--redl)" : "var(--teall)", fontWeight: 700, fontFamily: "var(--mono)" }}>{lastTestedPacket.payload_entropy} / 8.0</span></div>
                <div><span style={{ color: "var(--tx2)" }}>Matched Rule: </span><span style={{ color: "var(--vl)", fontWeight: 700, fontFamily: "var(--mono)" }}>{lastTestedPacket.matched_rule || "NONE (PASS)"}</span></div>
                <div><span style={{ color: "var(--tx2)" }}>Threat Score: </span><span style={{ color: lastTestedPacket.threat_score > 70 ? "var(--redl)" : "var(--tx0)", fontWeight: 700 }}>{lastTestedPacket.threat_score}/100</span></div>
              </div>
              <div style={{ fontSize: 10 }}>
                <span style={{ color: "var(--tx2)" }}>Payload Preview: </span>
                <code style={{ fontSize: 10, color: "var(--tx0)", background: "rgba(0,0,0,0.4)", padding: "2px 6px", borderRadius: 3 }}>
                  {lastTestedPacket.payload_preview}
                </code>
              </div>
            </div>
          )}

          {/* Active In-Kernel Rules */}
          <div style={{ padding: "14px 18px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--tx0)", letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 10 }}>
              Active eBPF Security Filter Rules ({ebpfRules.length})
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {ebpfRules.map((r: any) => (
                <div key={r.id} style={{ display: "grid", gridTemplateColumns: "100px 180px 70px 80px 80px 80px 1fr", padding: "6px 10px", background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: 4, alignItems: "center", fontSize: 10 }}>
                  <code style={{ color: "var(--vl)", fontWeight: 700 }}>{r.id}</code>
                  <span style={{ fontWeight: 600, color: "var(--tx0)" }}>{r.name}</span>
                  <span style={{ color: "var(--tx2)" }}>{r.proto}</span>
                  <span style={{ color: "var(--tx0)", fontFamily: "var(--mono)" }}>Port: {r.dst_port ?? "ANY"}</span>
                  <span style={{ color: r.action === "drop" ? "var(--redl)" : "var(--amberl)", fontWeight: 700 }}>{r.action.toUpperCase()}</span>
                  <span style={{ color: r.severity === "critical" ? "var(--redl)" : "var(--amberl)", fontWeight: 600 }}>{r.severity}</span>
                  <span style={{ color: "var(--tx2)", fontSize: 9 }}>{r.description}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Live Inspected Packets Stream */}
          <div style={{ padding: "14px 18px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--tx0)", letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 10 }}>
              Recent Kernel Filter Stream ({ebpfPackets.length} captured)
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {ebpfPackets.map((pkt: any) => (
                <div key={pkt.id} style={{ display: "grid", gridTemplateColumns: "70px 60px 140px 140px 60px 1fr 60px", padding: "5px 10px", background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: 4, alignItems: "center", fontSize: 10 }}>
                  <span style={{
                    fontSize: 8.5,
                    fontWeight: 700,
                    padding: "1px 5px",
                    borderRadius: 2,
                    background: pkt.verdict === "drop" ? "rgba(225,29,72,0.18)" : pkt.verdict === "alert" ? "rgba(245,158,11,0.18)" : "rgba(13,148,136,0.18)",
                    color: pkt.verdict === "drop" ? "var(--redl)" : pkt.verdict === "alert" ? "var(--amberl)" : "var(--teall)",
                    textAlign: "center",
                  }}>
                    {pkt.verdict.toUpperCase()}
                  </span>
                  <span style={{ color: "var(--tx2)" }}>{pkt.proto}</span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--tx1)" }}>{pkt.src_ip}:{pkt.src_port}</span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--tx0)" }}>{pkt.dst_ip}:{pkt.dst_port}</span>
                  <span style={{ color: "var(--tx2)", fontSize: 9 }}>{pkt.packet_len}B</span>
                  <span style={{ color: "var(--tx2)", fontSize: 9, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{pkt.reason}</span>
                  <span style={{ color: "var(--tx2)", fontSize: 9, textAlign: "right" }}>{new Date(pkt.ts).toLocaleTimeString()}</span>
                </div>
              ))}
              {ebpfPackets.length === 0 && (
                <div style={{ padding: 12, textAlign: "center", fontSize: 11, color: "var(--tx2)" }}>
                  No packets captured yet. Click the test buttons above to simulate packet inspection.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Subtab 6: Real-time Protocol Distribution Data Visualization (Recharts) */}
      {subTab === "distribution" && (
        <ProtocolDistributionChart
          connections={connections}
          attacks={attacks}
          ebpfPackets={ebpfPackets}
          onInjectTraffic={(proto, count) => {
            setStatusMsg(`⚡ Live Protocol Telemetry: Injected ${count} real-time ${proto} packet stream into kernel observer buffer`);
            setTimeout(() => setStatusMsg(null), 4000);
          }}
        />
      )}
    </div>
  );
}
