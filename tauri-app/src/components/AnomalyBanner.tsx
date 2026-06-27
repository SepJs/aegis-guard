import { useState, useEffect } from "react";
import { listen }              from "@tauri-apps/api/event";
import type { ThreatIncident } from "../types";
import RuleBadge               from "./RuleBadge";

export default function AnomalyBanner() {
  const [alerts, setAlerts] = useState<ThreatIncident[]>([]);

  useEffect(() => {
    const unsub = listen<ThreatIncident>("anomaly", ev => {
      const inc = ev.payload;
      setAlerts(prev => [inc, ...prev].slice(0, 5));
      setTimeout(() => setAlerts(p => p.filter(a => a.id !== inc.id)), 9000);
    });
    return () => { unsub.then(f => f()); };
  }, []);

  if (!alerts.length) return null;

  return (
    <div className="banner-stack">
      {alerts.map(inc => (
        <div key={inc.id}
             className={`alert-banner ${inc.severity === "high" ? "ab--high" : "ab--medium"}`}>
          <RuleBadge rule={inc.rule} />
          <span className="ab-msg">
            <strong>{inc.process}</strong> — {inc.reason.slice(0, 90)}
            {inc.reason.length > 90 ? "…" : ""}
          </span>
          <button className="ab-close"
            onClick={() => setAlerts(p => p.filter(a => a.id !== inc.id))}>
            ✕
          </button>
        </div>
      ))}
    </div>
  );
}
