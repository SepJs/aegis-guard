import { createContext, useContext } from "react";
import type { ProcessNode, ProcEvent } from "../types";

export interface ProcessStore { nodes: Map<number, ProcessNode>; anomalies: number[]; openCount: number }

export type StoreAction =
  | { type: "UPSERT"; event: ProcEvent }
  | { type: "REMOVE"; pid: number }
  | { type: "SET_OPEN_COUNT"; count: number };

export function processReducer(state: ProcessStore, action: StoreAction): ProcessStore {
  switch (action.type) {
    case "UPSERT": {
      const ev = action.event;
      const existing = state.nodes.get(ev.pid);
      const node: ProcessNode = { ...ev, children: existing?.children ?? [], flagged: ev.anomaly !== null, seenAt: existing?.seenAt ?? Date.now() };
      const next = new Map(state.nodes);
      next.set(ev.pid, node);
      if (ev.ppid && next.has(ev.ppid)) {
        const parent = { ...next.get(ev.ppid)! };
        if (!parent.children.find((c) => c.pid === ev.pid)) { parent.children = [...parent.children, node]; next.set(ev.ppid, parent); }
      }
      const anomalies = ev.anomaly ? [...new Set([...state.anomalies, ev.pid])] : state.anomalies;
      return { ...state, nodes: next, anomalies };
    }
    case "REMOVE": {
      const next = new Map(state.nodes);
      next.delete(action.pid);
      next.forEach((node, pid) => {
        if (node.children.some((c) => c.pid === action.pid)) next.set(pid, { ...node, children: node.children.filter((c) => c.pid !== action.pid) });
      });
      return { ...state, nodes: next, anomalies: state.anomalies.filter((p) => p !== action.pid) };
    }
    case "SET_OPEN_COUNT": return { ...state, openCount: action.count };
    default: return state;
  }
}

export const initialStore: ProcessStore = { nodes: new Map(), anomalies: [], openCount: 0 };

export const ProcessStoreContext = createContext<{ store: ProcessStore; dispatch: React.Dispatch<StoreAction> } | null>(null);

export function useProcessStore() {
  const ctx = useContext(ProcessStoreContext);
  if (!ctx) throw new Error("useProcessStore outside provider");
  return ctx;
}
