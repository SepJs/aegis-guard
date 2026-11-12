import { useEffect } from "react";
import { invoke } from "../lib/ipc/core";
import { listen } from "../lib/ipc/event";
import { useProcessStore } from "../store/processStore";
import type { ProcessNode, ThreatIncident } from "../types";

export function useIpc() {
  const { dispatch } = useProcessStore();

  useEffect(() => {
    // 1. Initial fetch of active processes
    invoke<ProcessNode[]>("list_processes")
      .then((procs) => {
        if (Array.isArray(procs)) {
          dispatch({ type: "SET_PROCESSES", payload: procs });
        }
      })
      .catch((err) => console.error("Failed to load initial processes:", err));

    // 2. Initial fetch of open threat count
    invoke<number>("count_open")
      .then((count) => {
        if (typeof count === "number") {
          dispatch({ type: "SET_OPEN_COUNT", payload: count });
        }
      })
      .catch((err) => console.error("Failed to count open incidents:", err));

    // 3. Listen for real-time anomaly alerts emitted by Aegis-Guard engine
    const unlistenAnomaly = listen<ThreatIncident>("anomaly", (ev) => {
      if (ev.payload) {
        invoke<number>("count_open").then((count) => {
          if (typeof count === "number") {
            dispatch({ type: "SET_OPEN_COUNT", payload: count });
          }
        });
      }
    });

    // 4. Listen for incident resolution
    const unlistenResolved = listen<{ id: string }>("incident-resolved", (ev) => {
      if (ev.payload?.id) {
        dispatch({ type: "RESOLVE_INCIDENT", payload: ev.payload.id });
      }
    });

    // 5. Periodic sync
    const interval = setInterval(() => {
      invoke<ProcessNode[]>("list_processes")
        .then((procs) => {
          if (Array.isArray(procs)) {
            dispatch({ type: "SET_PROCESSES", payload: procs });
          }
        })
        .catch(() => {});
      invoke<number>("count_open")
        .then((count) => {
          if (typeof count === "number") {
            dispatch({ type: "SET_OPEN_COUNT", payload: count });
          }
        })
        .catch(() => {});
    }, 8000);

    return () => {
      clearInterval(interval);
      unlistenAnomaly.then((fn) => fn && fn());
      unlistenResolved.then((fn) => fn && fn());
    };
  }, [dispatch]);
}
