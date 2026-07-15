import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { useProcessStore } from "../store/processStore";
export function useIpc() {
    const { dispatch } = useProcessStore();
    useEffect(() => {
        const unlistenProc = listen("proc-event", (ev) => {
            if (ev.payload.kind === "exited")
                dispatch({ type: "REMOVE", pid: ev.payload.pid });
            else
                dispatch({ type: "UPSERT", event: ev.payload });
        });
        const unlistenAnomaly = listen("anomaly", () => {
            invoke("count_open").then((n) => dispatch({ type: "SET_OPEN_COUNT", count: n }));
        });
        invoke("count_open").then((n) => dispatch({ type: "SET_OPEN_COUNT", count: n }));
        return () => { unlistenProc.then((f) => f()); unlistenAnomaly.then((f) => f()); };
    }, [dispatch]);
}
