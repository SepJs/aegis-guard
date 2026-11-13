import { useEffect } from "react";
import { invoke, isTauriRuntime } from "../lib/ipc/core";
import { isIpcStreamConnected, listen } from "../lib/ipc/event";
import { ProcEventPayload, useProcessStore } from "../store/processStore";
import type {
  AuditEntry,
  DebugEntry,
  NetworkAttackEvent,
  NetworkMetrics,
  ProcessNode,
  SystemMetrics,
  TelemetryEvent,
  ThreatIncident,
} from "../types";

export function useIpc() {
  const { dispatch } = useProcessStore();

  useEffect(() => {
    let cancelled = false;
    const unlisteners: Array<() => void> = [];

    const transport = isTauriRuntime() ? "tauri" : "sse";
    if (isTauriRuntime() || isIpcStreamConnected()) {
      dispatch({ type: "SET_IPC_STATUS", payload: { connected: true, transport } });
    }

    // 1. Hydrate live state from backend IPC (Linux /proc, journal, audit chain, IDS)
    const hydrateFromBackend = async () => {
      const results = await Promise.allSettled([
        invoke<ProcessNode[]>("list_processes"),
        invoke<number>("count_open"),
        invoke<TelemetryEvent[]>("list_telemetry", { limit: 200 }),
        invoke<ThreatIncident[]>("list_incidents", { limit: 100, offset: 0 }),
        invoke<AuditEntry[]>("list_audit_log", { limit: 100, offset: 0 }),
        invoke<NetworkAttackEvent[]>("list_network_attacks"),
        invoke<DebugEntry[]>("list_debug_log", { limit: 100, offset: 0 }),
        invoke<SystemMetrics>("get_system_metrics"),
        invoke<NetworkMetrics>("get_network_metrics"),
      ]);

      if (cancelled) return;

      const [procsRes, countRes, telRes, incRes, auditRes, atkRes, dbgRes, sysRes, netRes] = results;

      if (procsRes.status === "fulfilled" && Array.isArray(procsRes.value)) {
        dispatch({ type: "SET_PROCESSES", payload: procsRes.value });
        dispatch({ type: "SET_IPC_STATUS", payload: { connected: true, transport } });
      }
      if (countRes.status === "fulfilled" && typeof countRes.value === "number") {
        dispatch({ type: "SET_OPEN_COUNT", payload: countRes.value });
      }
      if (telRes.status === "fulfilled" && Array.isArray(telRes.value)) {
        dispatch({ type: "SET_TELEMETRY", payload: telRes.value });
      }
      if (incRes.status === "fulfilled" && Array.isArray(incRes.value)) {
        dispatch({ type: "SET_INCIDENTS", payload: incRes.value });
      }
      if (auditRes.status === "fulfilled" && Array.isArray(auditRes.value)) {
        dispatch({ type: "SET_AUDIT_LOGS", payload: auditRes.value });
      }
      if (atkRes.status === "fulfilled" && Array.isArray(atkRes.value)) {
        dispatch({ type: "SET_NET_ATTACKS", payload: atkRes.value });
      }
      if (dbgRes.status === "fulfilled" && Array.isArray(dbgRes.value)) {
        dispatch({ type: "SET_DEBUG_LOGS", payload: dbgRes.value });
      }
      if (sysRes.status === "fulfilled" && sysRes.value) {
        dispatch({ type: "SET_SYSTEM_METRICS", payload: sysRes.value });
      }
      if (netRes.status === "fulfilled" && netRes.value) {
        dispatch({ type: "SET_NET_METRICS", payload: netRes.value });
      }
    };

    hydrateFromBackend().catch((err) => console.error("Initial IPC hydration error:", err));

    // 2. Bind real-time IPC event listeners (native Tauri eBPF/socket bridge & Express SSE stream)
    const registerListeners = async () => {
      const subscriptions = await Promise.all([
        // Kernel process lifecycle events (spawn / exit / anomaly)
        listen<ProcEventPayload>("proc-event", (ev) => {
          if (cancelled || !ev.payload) return;
          dispatch({ type: "HANDLE_PROC_EVENT", payload: ev.payload });

          // Inside native Tauri runtime, ipc_bridge emits proc-event without telemetry-event
          if (isTauriRuntime()) {
            const p = ev.payload;
            const anomScore = p.anomaly?.risk_score ?? (p.anomaly?.confidence === "high" ? 75 : p.anomaly ? 45 : 0);
            const anomSev =
              p.anomaly?.severity ||
              (anomScore >= 90 ? "critical" : anomScore >= 70 ? "high" : anomScore >= 35 ? "medium" : "informational");
            const syntheticTelemetry: TelemetryEvent = {
              id: p.id || `proc-ev-${p.pid}-${p.ts}`,
              ts: p.ts || Date.now(),
              event_type:
                p.kind === "exited"
                  ? "EXEC_EXIT"
                  : p.anomaly
                  ? "EXEC_ANOMALY"
                  : p.kind === "state_changed"
                  ? "STATE_CHANGE"
                  : "EXEC_SPAWN",
              process: p.name,
              parent: `ppid:${p.ppid}`,
              pid: p.pid,
              ppid: p.ppid,
              uid: p.uid,
              cmdline: p.cmdline,
              exe_path: p.exe,
              score: p.anomaly ? anomScore : 0,
              verdict: p.anomaly ? (anomScore >= 70 ? "alert" : "monitored") : "clean",
              severity: p.anomaly ? (anomSev as any) : "informational",
              rule: p.anomaly?.rule,
              explanation: p.anomaly?.reason,
              detail: p.anomaly
                ? `${p.anomaly.rule}: ${(p.cmdline || []).join(" ")}`
                : `[${p.state_label || "Running"}] ${(p.cmdline || []).join(" ") || p.name}`,
            };
            dispatch({ type: "PUSH_TELEMETRY", payload: syntheticTelemetry });
          }
        }),

        // 1.5s live Task Manager process & host telemetry snapshot
        listen<{ tree: ProcessNode[]; metrics?: SystemMetrics }>("proc-snapshot", (ev) => {
          if (cancelled || !ev.payload) return;
          dispatch({ type: "HANDLE_PROC_SNAPSHOT", payload: ev.payload });
        }),

        // Live network interface counters from /proc/net/dev
        listen<{ connections?: any[]; netDev?: NetworkMetrics }>("net-update", (ev) => {
          if (cancelled || !ev.payload?.netDev) return;
          dispatch({ type: "SET_NET_METRICS", payload: ev.payload.netDev });
        }),

        // Real-time kernel/eBPF/syscall telemetry stream
        listen<TelemetryEvent>("telemetry-event", (ev) => {
          if (cancelled || !ev.payload) return;
          dispatch({ type: "PUSH_TELEMETRY", payload: ev.payload });
        }),

        // Real-time threat anomaly alerts persisted in journal
        listen<ThreatIncident>("anomaly", (ev) => {
          if (cancelled || !ev.payload) return;
          dispatch({ type: "PUSH_INCIDENT", payload: ev.payload });
          invoke<number>("count_open")
            .then((count) => {
              if (!cancelled && typeof count === "number") {
                dispatch({ type: "SET_OPEN_COUNT", payload: count });
              }
            })
            .catch(() => {});
        }),

        // Incident dismissed/resolved updates
        listen<{ id: string }>("incident-resolved", (ev) => {
          if (cancelled || !ev.payload?.id) return;
          dispatch({ type: "RESOLVE_INCIDENT", payload: ev.payload.id });
        }),

        // Real-time cryptographic audit chain entries
        listen<AuditEntry>("audit-entry", (ev) => {
          if (cancelled || !ev.payload) return;
          dispatch({ type: "PUSH_AUDIT_LOG", payload: ev.payload });
        }),

        // Real-time network IDS attack detections
        listen<NetworkAttackEvent>("net-attack", (ev) => {
          if (cancelled || !ev.payload) return;
          dispatch({ type: "PUSH_NET_ATTACK", payload: ev.payload });
        }),

        // Real-time auto-tuning false-positive suppression entries
        listen<DebugEntry>("debug-entry", (ev) => {
          if (cancelled || !ev.payload) return;
          dispatch({ type: "PUSH_DEBUG_LOG", payload: ev.payload });
        }),

        // Stream transport health notifications
        listen<{ connected: boolean; transport?: "tauri" | "sse" }>("ipc-status", (ev) => {
          if (cancelled || !ev.payload) return;
          dispatch({ type: "SET_IPC_STATUS", payload: ev.payload });
        }),
      ]);

      if (cancelled) {
        subscriptions.forEach((fn) => fn && fn());
      } else {
        unlisteners.push(...subscriptions);
      }
    };

    registerListeners().catch((err) => console.error("Failed to attach IPC listeners:", err));

    // 3. Low-frequency reconciliation snapshot for full process tree & open incident count
    const reconcileInterval = setInterval(() => {
      invoke<ProcessNode[]>("list_processes")
        .then((procs) => {
          if (!cancelled && Array.isArray(procs)) {
            dispatch({ type: "SET_PROCESSES", payload: procs });
          }
        })
        .catch(() => {});

      invoke<number>("count_open")
        .then((count) => {
          if (!cancelled && typeof count === "number") {
            dispatch({ type: "SET_OPEN_COUNT", payload: count });
          }
        })
        .catch(() => {});
    }, 10000);

    return () => {
      cancelled = true;
      clearInterval(reconcileInterval);
      unlisteners.forEach((fn) => {
        try {
          fn();
        } catch {}
      });
    };
  }, [dispatch]);
}
