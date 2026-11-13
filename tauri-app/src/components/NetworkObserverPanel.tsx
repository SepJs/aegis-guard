import { useState, useEffect } from "react";
import { invoke } from "../lib/ipc/core";
import { listen } from "../lib/ipc/event";
import { useProcessStore } from "../store/processStore";
import type {
  NetworkConnection,
  DnsQuery,
  NetworkAttackEvent,
  NetworkDefenseConfig,
  NetworkMetrics,
  PacketInspectionSnapshot,
  PacketInspectorConfig,
} from "../types";

function fmtNetBytes(b: number): string {
  if (b >= 1024 * 1024 * 1024) return `${(b / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  if (b >= 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(2)} MB`;
  if (b >= 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${b} B`;
}

export default function NetworkObserverPanel() {
  const { store, dispatch } = useProcessStore();
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [dnsQueries, setDnsQueries] = useState<DnsQuery[]>([]);
  const [attacks, setAttacks] = useState<NetworkAttackEvent[]>([]);
  const [netMetrics, setNetMetrics] = useState<NetworkMetrics | null>(store.netMetrics);
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
  const [subTab, setSubTab] = useState<"connections" | "packet" | "attacks" | "dns" | "config">("connections");
  const [packetSnapshot, setPacketSnapshot] = useState<PacketInspectionSnapshot | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [manualIp, setManualIp] = useState("");

  async function loadData() {
    try {
      const [conns, dns, atks, cfg, metrics, pkt] = await Promise.all([
        invoke<NetworkConnection[]>("list_network_connections"),
        invoke<DnsQuery[]>("list_dns_queries"),
        invoke<NetworkAttackEvent[]>("list_network_attacks"),
        invoke<NetworkDefenseConfig>("get_network_defense_config"),
        invoke<NetworkMetrics>("get_network_metrics"),
        invoke<PacketInspectionSnapshot>("get_packet_inspection"),
      ]);
      if (conns) setConnections(conns);
      if (dns) setDnsQueries(dns);
      if (atks) setAttacks(atks);
      if (cfg) setConfig(cfg);
      if (pkt) setPacketSnapshot(pkt);
      if (metrics) {
        setNetMetrics(metrics);
        dispatch({ type: "SET_NET_METRICS", payload: metrics });
      }
    } catch (err) {
      console.error("Failed to load network data:", err);
    }
  }

  useEffect(() => {
    loadData();

    // Listen for live network updates from /proc/net & Go Packet Inspector engine
    const unsubNet = listen<{ connections: NetworkConnection[]; netDev?: NetworkMetrics }>("net-update", (ev) => {
      if (ev.payload?.connections) {
        setConnections([...ev.payload.connections]);
      }
      if (ev.payload?.netDev) {
        setNetMetrics(ev.payload.netDev);
      }
    });

    const unsubPkt = listen<PacketInspectionSnapshot>("packet-inspection", (ev) => {
      if (ev.payload) {
        setPacketSnapshot(ev.payload);
      }
    });

    const unsubAtk = listen<NetworkAttackEvent>("net-attack", (ev) => {
      if (ev.payload) {
        setAttacks((prev) => [ev.payload, ...prev]);
        setStatusMsg(`SOCKET/ARP ANOMALY DETECTED: ${ev.payload.attack_type} (${ev.payload.source_ip})`);
      }
    });

    return () => {
      unsubNet.then((f) => f && f());
      unsubPkt.then((f) => f && f());
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

  async function togglePacketInspectorOption(key: keyof PacketInspectorConfig) {
    if (!packetSnapshot || typeof packetSnapshot.config[key] !== "boolean") return;
    const nextCfg: PacketInspectorConfig = {
      ...packetSnapshot.config,
      [key]: !packetSnapshot.config[key],
    };
    try {
      const updated = await invoke<PacketInspectorConfig>("set_packet_inspector_config", { config: nextCfg });
      setPacketSnapshot((prev) => (prev ? { ...prev, config: updated || nextCfg } : prev));
      setStatusMsg(`Packet inspector policy updated (${key}).`);
      setTimeout(() => setStatusMsg(null), 3000);
    } catch (err) {
      console.error("Packet inspector config error:", err);
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
  const totalTx = netMetrics?.total_tx_bytes ?? connections.reduce((acc, c) => acc + c.bytes_tx, 0);
  const totalRx = netMetrics?.total_rx_bytes ?? connections.reduce((acc, c) => acc + c.bytes_rx, 0);

  return (
    <div className="panel" id="network-observer-panel" style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      {/* Panel Top Header */}
      <div className="panel-header" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 16px", borderBottom: "1px solid var(--border)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className="panel-title" style={{ fontWeight: 700, letterSpacing: "0.08em" }}>
            NETWORK IDS &amp; PACKET INSPECTOR
          </span>
          <span
            className="pstat"
            style={{
              background: packetSnapshot?.go_bridge_connected ? "rgba(13,148,136,0.18)" : "rgba(124,58,237,0.14)",
              color: packetSnapshot?.go_bridge_connected ? "var(--teall)" : "var(--vl)",
              border: `1px solid ${packetSnapshot?.go_bridge_connected ? "var(--teal)" : "var(--v)"}`,
              padding: "2px 8px",
              borderRadius: 4,
              fontSize: 10,
            }}
          >
            {packetSnapshot?.go_bridge_connected
              ? "GO PACKET DAEMON :50053"
              : "LINUX /proc/net/snmp INSPECTOR"}
          </span>
          <span className="pstat" style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, background: "var(--bg1)" }}>
            {connections.length} SOCKETS ({establishedCount} ESTABLISHED)
          </span>
          {packetSnapshot && (
            <span className="pstat" style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, background: "var(--bg1)" }}>
              {packetSnapshot.snmp_counters.segments_per_sec} SEG/S
            </span>
          )}
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

      {/* Real-time /proc/net/dev Network Interface Counters Strip */}
      <div className="scan-summary-bar" style={{ display: "flex", flexWrap: "wrap", gap: 12, padding: "8px 16px", alignItems: "center", background: "var(--bg1)", borderBottom: "1px solid var(--border)" }}>
        <div className="sum-pill" style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", background: "var(--bg0)", borderRadius: 4, border: "1px solid var(--border)" }}>
          <span className="sum-pill-val" style={{ fontSize: 12, fontWeight: 700, color: "var(--teall)" }}>
            {fmtNetBytes(totalTx)}
          </span>
          <span className="sum-pill-label" style={{ fontSize: 9, color: "var(--tx2)", textTransform: "uppercase" }}>TOTAL TX (/proc/net/dev)</span>
        </div>

        <div className="sum-pill" style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", background: "var(--bg0)", borderRadius: 4, border: "1px solid var(--border)" }}>
          <span className="sum-pill-val" style={{ fontSize: 12, fontWeight: 700, color: "var(--vl)" }}>
            {fmtNetBytes(totalRx)}
          </span>
          <span className="sum-pill-label" style={{ fontSize: 9, color: "var(--tx2)", textTransform: "uppercase" }}>TOTAL RX (/proc/net/dev)</span>
        </div>

        <div className="sum-pill" style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", background: "var(--bg0)", borderRadius: 4, border: "1px solid var(--border)" }}>
          <span className="sum-pill-val" style={{ fontSize: 12, fontWeight: 700, color: attacks.length > 0 ? "var(--redl)" : "var(--tx2)" }}>
            {attacks.length}
          </span>
          <span className="sum-pill-label" style={{ fontSize: 9, color: "var(--tx2)", textTransform: "uppercase" }}>REAL NETWORK ALERTS</span>
        </div>

        {netMetrics?.interfaces && netMetrics.interfaces.length > 0 && (
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            {netMetrics.interfaces.slice(0, 4).map((iface) => (
              <span
                key={iface.iface}
                style={{
                  fontSize: 9,
                  fontFamily: "var(--mono)",
                  padding: "3px 7px",
                  borderRadius: 3,
                  background: "var(--bg0)",
                  border: "1px solid var(--border)",
                  color: "var(--tx1)",
                }}
              >
                {iface.iface}: ↑{fmtNetBytes(iface.tx_bytes)} ↓{fmtNetBytes(iface.rx_bytes)}
              </span>
            ))}
          </div>
        )}

        {/* View switcher */}
        <div style={{ display: "flex", gap: 4, marginLeft: "auto" }}>
          <button
            className={`sm-btn ${subTab === "connections" ? "sm-btn--active" : ""}`}
            onClick={() => setSubTab("connections")}
            style={{ fontSize: 10, padding: "4px 10px", borderRadius: 4 }}
          >
            SOCKETS ({filteredConns.length})
          </button>
          <button
            className={`sm-btn ${subTab === "packet" ? "sm-btn--active" : ""}`}
            onClick={() => setSubTab("packet")}
            style={{ fontSize: 10, padding: "4px 10px", borderRadius: 4 }}
          >
            PACKET INSPECTOR ({packetSnapshot?.flow_findings.length ?? 0})
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
            className={`sm-btn ${subTab === "config" ? "sm-btn--active" : ""}`}
            onClick={() => setSubTab("config")}
            style={{ fontSize: 10, padding: "4px 10px", borderRadius: 4 }}
          >
            IDS POLICIES
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
            {filteredConns.map((c) => {
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
                  <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--tx2)" }}>{c.proto}</span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 10 }}>{c.local_addr}:{c.local_port}</span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: isBad ? "var(--redl)" : "var(--tx)" }}>
                    {c.remote_addr}:{c.remote_port}
                  </span>
                  <span style={{ fontSize: 11 }}>{c.process_name}</span>
                  <span style={{ fontSize: 10, color: c.state === "ESTABLISHED" ? "var(--teall)" : "var(--tx2)" }}>{c.state}</span>
                  <span style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--tx2)" }}>
                    TX {(c.bytes_tx / 1024).toFixed(1)}k · RX {(c.bytes_rx / 1024).toFixed(1)}k
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
            })}
          </div>
        </div>
      )}

      {/* Subtab 1b: Go Packet Inspector & /proc/net/snmp L3/L4 Engine */}
      {subTab === "packet" && (
        <div style={{ flex: 1, overflowY: "auto", padding: "14px 16px", display: "flex", flexDirection: "column", gap: 14 }}>
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 10,
              padding: "10px 14px",
              background: "var(--bg1)",
              border: "1px solid var(--border)",
              borderRadius: 6,
            }}
          >
            <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: "var(--tx)" }}>
                HIGH-PERFORMANCE L3/L4 PACKET &amp; FLOW INSPECTION ENGINE
              </span>
              <span style={{ fontSize: 10, color: "var(--tx2)" }}>
                Bridge:{" "}
                <strong style={{ color: packetSnapshot?.go_bridge_connected ? "var(--teall)" : "var(--vl)" }}>
                  {packetSnapshot?.go_bridge_connected
                    ? "Go Daemon Connected (127.0.0.1:50053)"
                    : "Linux /proc/net/snmp Live Inspector (Go TCP Bridge :50053 Ready)"}
                </strong>{" "}
                · Workers: {packetSnapshot?.stats.worker_threads ?? 2}
              </span>
            </div>
            <button className="sm-btn" onClick={loadData} style={{ fontSize: 10, padding: "4px 10px" }}>
              ↻ REFRESH SNAPSHOT
            </button>
          </div>

          {packetSnapshot && (
            <>
              {/* L3/L4 Counters Grid */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(175px, 1fr))", gap: 10 }}>
                {[
                  {
                    label: "SEGMENTS / PACKETS",
                    value: packetSnapshot.stats.packets_inspected.toLocaleString(),
                    sub: `${packetSnapshot.snmp_counters.segments_per_sec} seg/s live rate`,
                    color: "var(--teall)",
                  },
                  {
                    label: "TCP IN / OUT SEGS",
                    value: `${packetSnapshot.snmp_counters.tcp_in_segs.toLocaleString()} / ${packetSnapshot.snmp_counters.tcp_out_segs.toLocaleString()}`,
                    sub: `Retrans: ${packetSnapshot.snmp_counters.tcp_retrans_segs} (${packetSnapshot.snmp_counters.retrans_rate_pct}%)`,
                    color: "var(--tx0)",
                  },
                  {
                    label: "UDP / ICMP DATAGRAMS",
                    value: `${(packetSnapshot.snmp_counters.udp_in_datagrams + packetSnapshot.snmp_counters.udp_out_datagrams).toLocaleString()}`,
                    sub: `ICMP In/Out: ${packetSnapshot.snmp_counters.icmp_in_msgs}/${packetSnapshot.snmp_counters.icmp_out_msgs}`,
                    color: "var(--vl)",
                  },
                  {
                    label: "IP RECEIVES / OUT",
                    value: `${packetSnapshot.snmp_counters.ip_in_receives.toLocaleString()} / ${packetSnapshot.snmp_counters.ip_out_requests.toLocaleString()}`,
                    sub: `Header Errors: ${packetSnapshot.snmp_counters.ip_in_hdr_errors}`,
                    color: "var(--tx0)",
                  },
                  {
                    label: "SYN_RECV BACKLOG",
                    value: String(packetSnapshot.stats.active_syn_recv),
                    sub: `TCP Established: ${packetSnapshot.snmp_counters.tcp_curr_estab}`,
                    color: packetSnapshot.stats.active_syn_recv >= packetSnapshot.config.syn_flood_threshold ? "var(--redl)" : "var(--teall)",
                  },
                  {
                    label: "FLOWS ANALYZED",
                    value: packetSnapshot.stats.flows_analyzed.toLocaleString(),
                    sub: `Findings: ${packetSnapshot.stats.anomalies_found} · Queues: ${fmtNetBytes(packetSnapshot.stats.bytes_inspected)}`,
                    color: "var(--tx0)",
                  },
                ].map((card) => (
                  <div
                    key={card.label}
                    style={{
                      padding: "10px 12px",
                      background: "var(--bg1)",
                      border: "1px solid var(--border)",
                      borderRadius: 6,
                    }}
                  >
                    <div style={{ fontSize: 9, color: "var(--tx2)", letterSpacing: "0.06em", fontWeight: 700 }}>{card.label}</div>
                    <div style={{ fontSize: 15, fontWeight: 700, color: card.color, marginTop: 4, fontFamily: "var(--mono)" }}>{card.value}</div>
                    <div style={{ fontSize: 9, color: "var(--tx2)", marginTop: 2 }}>{card.sub}</div>
                  </div>
                ))}
              </div>

              {/* Guard Controls */}
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center", padding: "10px 14px", background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6 }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: "var(--tx2)", marginRight: 4 }}>INSPECTOR GUARDS:</span>
                {(
                  [
                    ["deep_inspection", "Deep Inspection"],
                    ["syn_flood_guard", "SYN Flood Guard"],
                    ["port_scan_guard", "Port Sweep Guard"],
                    ["dns_tunnel_guard", "DNS Tunnel Guard"],
                    ["arp_spoof_guard", "ARP Collision Guard"],
                  ] as Array<[keyof PacketInspectorConfig, string]>
                ).map(([key, label]) => {
                  const active = Boolean(packetSnapshot.config[key]);
                  return (
                    <button
                      key={key}
                      onClick={() => togglePacketInspectorOption(key)}
                      className={`sm-btn ${active ? "sm-btn--active" : ""}`}
                      style={{ fontSize: 10, padding: "4px 10px" }}
                    >
                      {active ? "✓" : "○"} {label}
                    </button>
                  );
                })}
              </div>

              {/* Flow Inspection Findings */}
              <div style={{ background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" }}>
                <div style={{ padding: "8px 14px", borderBottom: "1px solid var(--border)", fontSize: 10, fontWeight: 700, color: "var(--tx2)", letterSpacing: "0.06em" }}>
                  PACKET &amp; FLOW INSPECTION FINDINGS ({packetSnapshot.flow_findings.length})
                </div>
                {packetSnapshot.flow_findings.length === 0 ? (
                  <div style={{ padding: 20, textAlign: "center", fontSize: 11, color: "var(--tx2)" }}>
                    No anomalous L3/L4 flows, half-open SYN floods, C2 sockets, or horizontal port sweeps observed.
                  </div>
                ) : (
                  <div>
                    {packetSnapshot.flow_findings.map((f) => (
                      <div
                        key={f.id}
                        style={{
                          display: "grid",
                          gridTemplateColumns: "95px 110px 150px 150px 1fr 110px",
                          padding: "8px 14px",
                          borderBottom: "1px solid var(--border)",
                          fontSize: 10,
                          alignItems: "center",
                          gap: 8,
                        }}
                      >
                        <span style={{ fontWeight: 700, color: f.severity === "critical" ? "var(--redl)" : "var(--amberl)" }}>
                          {f.rule}
                        </span>
                        <span style={{ color: "var(--tx)" }}>{f.process} ({f.pid})</span>
                        <span style={{ fontFamily: "var(--mono)", color: "var(--tx2)" }}>{f.src_endpoint}</span>
                        <span style={{ fontFamily: "var(--mono)", color: "var(--redl)" }}>{f.dst_endpoint}</span>
                        <span style={{ color: "var(--tx1)" }}>{f.summary}</span>
                        <span style={{ textAlign: "right", fontWeight: 700, color: "var(--teall)" }}>{f.action_taken}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Live Kernel ARP Table */}
              <div style={{ background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" }}>
                <div style={{ padding: "8px 14px", borderBottom: "1px solid var(--border)", fontSize: 10, fontWeight: 700, color: "var(--tx2)", letterSpacing: "0.06em" }}>
                  LIVE /proc/net/arp NEIGHBOR TABLE ({packetSnapshot.arp_table.length})
                </div>
                {packetSnapshot.arp_table.length === 0 ? (
                  <div style={{ padding: 14, fontSize: 10, color: "var(--tx2)" }}>No ARP neighbor entries present on host interface.</div>
                ) : (
                  packetSnapshot.arp_table.map((a, idx) => (
                    <div
                      key={`${a.ip}-${idx}`}
                      style={{
                        display: "grid",
                        gridTemplateColumns: "150px 180px 100px 1fr",
                        padding: "6px 14px",
                        borderBottom: "1px solid var(--border)",
                        fontSize: 10,
                        fontFamily: "var(--mono)",
                      }}
                    >
                      <span>{a.ip}</span>
                      <span style={{ color: "var(--teall)" }}>{a.hw_addr}</span>
                      <span>{a.device}</span>
                      <span style={{ color: "var(--tx2)" }}>flags {a.flags}</span>
                    </div>
                  ))
                )}
              </div>
            </>
          )}
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
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: "var(--teall)" }}>
                LIVE /proc/net &amp; /proc/net/arp MONITORING ACTIVE
              </span>
              <span style={{ fontSize: 10, color: "var(--tx2)" }}>
                Only real socket IOC hits, suspicious ports, or duplicate ARP MAC collisions appear here.
              </span>
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
                  fontFamily: "var(--mono)",
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
                DROP IP
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
            <span>SOURCE &amp; PORT</span>
            <span>TARGET DEST</span>
            <span>SEVERITY / PROTO</span>
            <span>IDS PACKET FORENSICS &amp; SIGNATURE</span>
            <span style={{ textAlign: "right" }}>DEFENSE ACTION</span>
          </div>

          <div style={{ flex: 1, overflowY: "auto" }}>
            {attacks.length === 0 ? (
              <div style={{ padding: 32, textAlign: "center", color: "var(--tx2)", fontSize: 12 }}>
                No real network attacks or suspicious socket/ARP anomalies detected on host interfaces.
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
                          ? "ARP Spoofing / Sniff"
                          : a.attack_type === "SYN_FLOOD_DOS"
                          ? "SYN Flood DoS"
                          : a.attack_type === "PORT_SCAN_RECON"
                          ? "Stealth Port Scan"
                          : a.attack_type === "REVERSE_TCP_C2"
                          ? "Reverse TCP C2"
                          : a.attack_type === "DNS_TUNNEL_EXFIL"
                          ? "DNS Exfiltration"
                          : a.attack_type}
                      </div>
                      <div style={{ fontSize: 8, color: "var(--tx2)", textTransform: "uppercase" }}>{a.attack_type}</div>
                    </div>

                    <div style={{ fontFamily: "var(--mono)", fontSize: 10 }}>
                      <span style={{ color: isBlocked ? "var(--teall)" : "var(--redl)", fontWeight: 600 }}>{a.source_ip}</span>:{a.source_port}
                      {isBlocked && (
                        <div style={{ fontSize: 8, color: "var(--teall)", fontWeight: 700 }}>[NULL-ROUTED]</div>
                      )}
                    </div>

                    <div style={{ fontFamily: "var(--mono)", fontSize: 10 }}>
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
                      <div style={{ fontSize: 9, color: "var(--tx2)", fontFamily: "var(--mono)", marginTop: 2 }}>{a.signature_hit}</div>
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
                          Block IP (Null-Route)
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
            {dnsQueries.map((q) => {
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
                  <span style={{ color: isBad ? "var(--redl)" : "var(--tx)", fontWeight: isBad ? 700 : 400, fontFamily: "var(--mono)", fontSize: 11 }}>
                    {q.query}
                  </span>
                  <span style={{ color: "var(--tx2)", fontSize: 10 }}>{q.qtype}</span>
                  <span style={{ color: "var(--tx)", fontFamily: "var(--mono)", fontSize: 11 }}>{q.resolved_ip}</span>
                  <span style={{ color: "var(--tx2)", fontSize: 11 }}>{q.process_name}</span>
                  <span>
                    {isBad ? (
                      <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 3, background: "rgba(225,29,72,0.15)", color: "var(--redl)", fontWeight: 700 }}>
                        C2 FLAGGED
                      </span>
                    ) : (
                      <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 3, background: "rgba(13,148,136,0.15)", color: "var(--teall)", fontWeight: 600 }}>
                        BENIGN
                      </span>
                    )}
                  </span>
                </div>
              );
            })}
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
    </div>
  );
}
