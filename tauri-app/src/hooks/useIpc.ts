import { useEffect } from "react";
import { listen } from "../lib/ipc/event";
import { invoke } from "../lib/ipc/core";
import type { ProcEvent, ThreatIncident } from "../types";
import { useProcessStore } from "../store/processStore";

export function useIpc() {
  const { dispatch } = useProcessStore();

  useEffect(() => {
    let isMounted = true;
    let knownPids = new Set<number>();

    // Initial and periodic sync of real Windows OS processes
    async function syncRealProcesses() {
      if (!isMounted) return;
      try {
        const procs = await invoke<ProcEvent[]>("list_processes");
        if (procs && Array.isArray(procs) && procs.length > 0) {
          const currentPids = new Set<number>();
          for (const p of procs) {
            currentPids.add(p.pid);
            dispatch({
              type: "UPSERT",
              event: {
                id: p.id || `proc-${p.pid}`,
                kind: p.kind || "snapshot",
                pid: p.pid,
                ppid: p.ppid ?? 0,
                name: p.name || `pid-${p.pid}`,
                exe: p.exe ?? null,
                cmdline: p.cmdline && p.cmdline.length ? p.cmdline : [p.name || `pid-${p.pid}`],
                cwd: p.cwd ?? null,
                uid: p.uid ?? 1000,
                gid: p.gid ?? 1000,
                start_time: p.start_time ?? Date.now(),
                ts: p.ts || Date.now(),
                is_quarantined: p.is_quarantined,
                anomaly: p.anomaly ?? null,
              },
            });
          }

          // Clean up exited processes
          for (const oldPid of knownPids) {
            if (!currentPids.has(oldPid)) {
              dispatch({ type: "REMOVE", pid: oldPid });
            }
          }
          knownPids = currentPids;
        }
      } catch {
        // non-blocking
      }

      try {
        const openThreats = await invoke<number>("count_open");
        if (typeof openThreats === "number") {
          dispatch({ type: "SET_OPEN_COUNT", count: openThreats });
        }
      } catch {}
    }

    // Run immediate sync then poll every 2.5s
    syncRealProcesses();
    const interval = setInterval(syncRealProcesses, 2500);

    const unlistenProc = listen<ProcEvent>("proc-event", (ev) => {
      if (ev.payload.kind === "exited") dispatch({ type: "REMOVE", pid: ev.payload.pid });
      else dispatch({ type: "UPSERT", event: ev.payload });
    });

    const unlistenAnomaly = listen<ThreatIncident>("anomaly", () => {
      invoke<number>("count_open").then((n) => dispatch({ type: "SET_OPEN_COUNT", count: n }));
    });

    return () => {
      isMounted = false;
      clearInterval(interval);
      unlistenProc.then((f) => f && f());
      unlistenAnomaly.then((f) => f && f());
    };
  }, [dispatch]);
}
