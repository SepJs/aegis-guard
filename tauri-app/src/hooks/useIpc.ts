// hooks/useIpc.ts — subscribe to Tauri events from process-engine

import { useEffect } from "react";
import { listen }    from "@tauri-apps/api/event";
import { invoke }    from "@tauri-apps/api/core";
import type { ProcEvent, ThreatIncident } from "../types";
import { useProcessStore }                from "../store/processStore";

export function useIpc() {
  const { dispatch } = useProcessStore();

  useEffect(() => {
    // Subscribe to live process events
    const unlistenProc = listen<ProcEvent>("proc-event", (ev) => {
      if (ev.payload.kind === "exited") {
        dispatch({ type: "REMOVE", pid: ev.payload.pid });
      } else {
        dispatch({ type: "UPSERT", event: ev.payload });
      }
    });

    // Subscribe to new anomaly alerts
    const unlistenAnomaly = listen<ThreatIncident>("anomaly", () => {
      // Refresh badge count from DB
      invoke<number>("count_open").then((n) =>
        dispatch({ type: "SET_OPEN_COUNT", count: n })
      );
    });

    // Initial badge count on mount
    invoke<number>("count_open").then((n) =>
      dispatch({ type: "SET_OPEN_COUNT", count: n })
    );

    return () => {
      unlistenProc.then((f) => f());
      unlistenAnomaly.then((f) => f());
    };
  }, [dispatch]);
}
