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
            dispatch({ type: "UPSERT", event: p });
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
