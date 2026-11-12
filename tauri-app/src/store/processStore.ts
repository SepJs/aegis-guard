import React, { createContext, useContext } from "react";
import type { ProcessNode } from "../types";

export interface ProcessStoreState {
  nodes: Map<number, ProcessNode>;
  anomalies: ProcessNode[];
  openCount: number;
}

export type ProcessStoreAction =
  | { type: "SET_PROCESSES"; payload: ProcessNode[] }
  | { type: "UPDATE_PROCESS"; payload: ProcessNode }
  | { type: "REMOVE_PROCESS"; payload: number }
  | { type: "SET_OPEN_COUNT"; payload: number }
  | { type: "RESOLVE_INCIDENT"; payload: string };

export const initialStore: ProcessStoreState = {
  nodes: new Map(),
  anomalies: [],
  openCount: 0,
};

function flattenNodes(roots: ProcessNode[], map = new Map<number, ProcessNode>()): Map<number, ProcessNode> {
  for (const node of roots) {
    map.set(node.pid, node);
    if (node.children && node.children.length > 0) {
      flattenNodes(node.children, map);
    }
  }
  return map;
}

export function processReducer(state: ProcessStoreState, action: ProcessStoreAction): ProcessStoreState {
  switch (action.type) {
    case "SET_PROCESSES": {
      const flatMap = flattenNodes(action.payload);
      const anomalies = Array.from(flatMap.values()).filter((n) => n.flagged);
      return {
        ...state,
        nodes: flatMap,
        anomalies,
        openCount: state.openCount || anomalies.length,
      };
    }

    case "UPDATE_PROCESS": {
      const nextMap = new Map(state.nodes);
      nextMap.set(action.payload.pid, action.payload);
      const anomalies = Array.from(nextMap.values()).filter((n) => n.flagged);
      return {
        ...state,
        nodes: nextMap,
        anomalies,
      };
    }

    case "REMOVE_PROCESS": {
      const nextMap = new Map(state.nodes);
      nextMap.delete(action.payload);
      const anomalies = Array.from(nextMap.values()).filter((n) => n.flagged);
      return {
        ...state,
        nodes: nextMap,
        anomalies,
      };
    }

    case "SET_OPEN_COUNT": {
      return {
        ...state,
        openCount: action.payload,
      };
    }

    case "RESOLVE_INCIDENT": {
      return {
        ...state,
        openCount: Math.max(0, state.openCount - 1),
      };
    }

    default:
      return state;
  }
}

export interface ProcessStoreContextValue {
  store: ProcessStoreState;
  dispatch: React.Dispatch<ProcessStoreAction>;
}

export const ProcessStoreContext = createContext<ProcessStoreContextValue>({
  store: initialStore,
  dispatch: () => undefined,
});

export function useProcessStore(): ProcessStoreContextValue {
  return useContext(ProcessStoreContext);
}
