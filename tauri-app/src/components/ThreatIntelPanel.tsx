import { useState, useEffect } from "react";
import { invoke } from "../lib/ipc/core";

interface IocStats { ips: number; cidrs: number; domains: number; hashes: number }
interface IocMatch { ioc: string; kind: string; threat_type: string; feed: string; confidence: number; context: string }

export default function ThreatIntelPanel() {
  const [stats, setStats] = useState<IocStats | null>(null);
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<IocMatch | null | "clean">(null);
  const [loading, setLoading] = useState(false);
  const [customIoc, setCustomIoc] = useState("");
  const [customType, setCustomType] = useState<"ip" | "domain" | "hash">("ip");
  const [customThreat, setCustomThreat] = useState("apt_malware_c2");
  const [customAddedMsg, setCustomAddedMsg] = useState<string | null>(null);

  useEffect(() => { invoke<IocStats>("get_ioc_stats").then(setStats).catch(console.error); }, []);

  async function lookup(val?: string) {
    const target = (val || query).trim();
    if (!target) return;
    if (val) setQuery(val);
    setLoading(true); setResult(null);
    try { const r = await invoke<IocMatch | null>("check_ioc_manual", { value: target, context: "manual-lookup" }); setResult(r ?? "clean"); }
    catch (e) { console.error(e); } finally { setLoading(false); }
  }

  async function addCustom() {
    if (!customIoc.trim()) return;
    try {
      await invoke("add_custom_ioc", {
        ioc: customIoc.trim(),
        kind: customType,
        threat_type: customThreat,
        confidence: 95,
      });
      setCustomAddedMsg(`Added '${customIoc.trim()}' to threat feeds!`);
      const updatedStats = await invoke<IocStats>("get_ioc_stats");
      if (updatedStats) setStats(updatedStats);
      lookup(customIoc.trim());
      setCustomIoc("");
      setTimeout(() => setCustomAddedMsg(null), 4000);
    } catch (e) {
      console.error(e);
    }
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">THREAT INTELLIGENCE</span>
        {stats && <><span className="pstat">{stats.ips + stats.cidrs} IPs/CIDRs</span><span className="pstat">{stats.domains} DOMAINS</span><span className="pstat">{stats.hashes} HASHES</span></>}
        <div className="toolbar-right"><span style={{ fontSize: 9, color: "var(--tx2)", letterSpacing: ".06em" }}>FEEDS: BUNDLED + URLHAUS (6h refresh)</span></div>
      </div>

      <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--border)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <div style={{ fontSize: 9, color: "var(--tx2)", letterSpacing: ".1em", textTransform: "uppercase" }}>Manual IOC Lookup</div>
          <div style={{ display: "flex", gap: 6 }}>
            <button className="sm-btn" onClick={() => lookup("198.199.73.244")} style={{ fontSize: 9, padding: "2px 7px" }}>
              ⚡ C2 IP (198.199...)
            </button>
            <button className="sm-btn" onClick={() => lookup("45.33.32.156")} style={{ fontSize: 9, padding: "2px 7px" }}>
              ⚡ Dropper (45.33...)
            </button>
            <button className="sm-btn" onClick={() => lookup("evil.example.com")} style={{ fontSize: 9, padding: "2px 7px" }}>
              ⚡ Phishing Domain
            </button>
            <button className="sm-btn" onClick={() => lookup("1.1.1.1")} style={{ fontSize: 9, padding: "2px 7px" }}>
              ✓ Clean DNS (1.1.1.1)
            </button>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <input className="search-input" style={{ flex: 1, width: "auto" }} placeholder="IP address, domain, MD5 or SHA256 hash…" value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => { if (e.key === "Enter") lookup(); }} />
          <button className="action-btn" onClick={() => lookup()} disabled={loading || !query.trim()}>{loading ? "CHECKING…" : "CHECK"}</button>
        </div>
        {result && (
          <div style={{ marginTop: 10, padding: "10px 12px", borderRadius: 4, border: `1px solid ${result === "clean" ? "var(--teal)" : "var(--red)"}`, background: result === "clean" ? "rgba(13,148,136,.08)" : "rgba(220,38,38,.08)" }}>
            {result === "clean" ? (
              <div style={{ fontSize: 11, color: "var(--teall)" }}>✓ No matches found in threat intelligence feeds — IOC appears clean.</div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "var(--redl)" }}>⚠ IOC MATCHED — {result.threat_type.toUpperCase()}</div>
                <div className="meta-row"><span className="meta-label">IOC</span><code className="meta-code">{result.ioc}</code></div>
                <div className="meta-row"><span className="meta-label">TYPE</span><span className="meta-val">{result.kind}</span></div>
                <div className="meta-row"><span className="meta-label">THREAT</span><span className="meta-val" style={{ color: "var(--redl)" }}>{result.threat_type}</span></div>
                <div className="meta-row"><span className="meta-label">FEED</span><span className="meta-val">{result.feed}</span></div>
                <div className="meta-row"><span className="meta-label">CONFIDENCE</span><span className="meta-val">{result.confidence}%</span></div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Add Custom IOC */}
      <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)", background: "var(--bg0)" }}>
        <div style={{ fontSize: 9, color: "var(--tx2)", letterSpacing: ".1em", marginBottom: 6, textTransform: "uppercase" }}>Add Custom Threat Indicator</div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <select
            value={customType}
            onChange={(e) => setCustomType(e.target.value as any)}
            style={{ padding: "4px 8px", fontSize: 10, background: "var(--bg)", border: "1px solid var(--border)", borderRadius: 4, color: "var(--tx)" }}
          >
            <option value="ip">IP</option>
            <option value="domain">Domain</option>
            <option value="hash">SHA256 Hash</option>
          </select>
          <select
            value={customThreat}
            onChange={(e) => setCustomThreat(e.target.value)}
            style={{ padding: "4px 8px", fontSize: 10, background: "var(--bg)", border: "1px solid var(--border)", borderRadius: 4, color: "var(--tx)" }}
          >
            <option value="apt_malware_c2">APT / C2 Server</option>
            <option value="ransomware_dropper">Ransomware Dropper</option>
            <option value="phishing_credential_harvest">Phishing Gateway</option>
            <option value="crypto_miner">Cryptojacking Pool</option>
          </select>
          <input
            className="search-input"
            style={{ flex: 1, width: "auto" }}
            placeholder="e.g. 192.168.1.99 or malware-drop.ru"
            value={customIoc}
            onChange={(e) => setCustomIoc(e.target.value)}
          />
          <button className="sm-btn" onClick={addCustom} disabled={!customIoc.trim()}>
            + ADD & TEST IOC
          </button>
        </div>
        {customAddedMsg && (
          <div style={{ marginTop: 6, fontSize: 10, color: "var(--teall)" }}>
            ✓ {customAddedMsg}
          </div>
        )}
      </div>

      <div style={{ padding: "14px 16px", flex: 1, overflow: "auto" }}>
        <div style={{ fontSize: 9, color: "var(--tx2)", letterSpacing: ".1em", marginBottom: 10, textTransform: "uppercase" }}>Active Feeds</div>
        {[{ name: "Bundled IOC Feed", entries: stats ? stats.ips + stats.domains + stats.hashes : "…", update: "Ships with binary" },
          { name: "Abuse.ch URLhaus", entries: "500+", update: "Every 6 hours" },
          { name: "Custom IOCs", entries: "—", update: "/var/lib/aegis/custom_iocs.json" }].map(feed => (
          <div key={feed.name} style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 0", borderBottom: "1px solid var(--border-dim)" }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--teall)", flexShrink: 0, boxShadow: "0 0 5px var(--teal)" }} />
            <span style={{ flex: 1, fontSize: 11, color: "var(--tx0)" }}>{feed.name}</span>
            <span style={{ fontSize: 9, color: "var(--tx2)" }}>{feed.entries} entries</span>
            <span style={{ fontSize: 9, color: "var(--tx2)", fontStyle: "italic" }}>{feed.update}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
