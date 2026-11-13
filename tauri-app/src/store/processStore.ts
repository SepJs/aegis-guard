import React, { createContext, useContext } from "react";
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

export interface ProcEventPayload {
  id: string;
  kind: "spawned" | "exited" | "anomaly" | string;
  pid: number;
  ppid: number;
  uid: number;
  gid?: number;
  name: string;
  state?: string;
  state_label?: string;
  cpu_pct?: number;
  mem_rss_kb?: number;
  mem_pct?: number;
  threads?: number;
  fd_count?: number;
  io_read_bytes?: number;
  io_write_bytes?: number;
  cmdline: string[];
  exe?: string | null;
  cwd?: string | null;
  start_time?: number;
  ts: number | string;
  flagged?: boolean;
  children?: ProcessNode[];
  anomaly?: ProcessNode["anomaly"];
}

export interface ProcessStoreState {
  nodes: Map<number, ProcessNode>;
  anomalies: ProcessNode[];
  systemMetrics: SystemMetrics | null;
  netMetrics: NetworkMetrics | null;
  openCount: number;
  telemetry: TelemetryEvent[];
  incidents: ThreatIncident[];
  auditLogs: AuditEntry[];
  netAttacks: NetworkAttackEvent[];
  debugLogs: DebugEntry[];
  ipcConnected: boolean;
  ipcTransport: "tauri" | "sse" | "connecting";
  lastEventTs: number | null;
}

export type ProcessStoreAction =
  | { type: "SET_PROCESSES"; payload: ProcessNode[] }
  | { type: "HANDLE_PROC_SNAPSHOT"; payload: { tree: ProcessNode[]; metrics?: SystemMetrics } }
  | { type: "SET_SYSTEM_METRICS"; payload: SystemMetrics }
  | { type: "SET_NET_METRICS"; payload: NetworkMetrics }
  | { type: "HANDLE_PROC_EVENT"; payload: ProcEventPayload }
  | { type: "UPDATE_PROCESS"; payload: ProcessNode }
  | { type: "REMOVE_PROCESS"; payload: number }
  | { type: "SET_OPEN_COUNT"; payload: number }
  | { type: "SET_TELEMETRY"; payload: TelemetryEvent[] }
  | { type: "PUSH_TELEMETRY"; payload: TelemetryEvent }
  | { type: "SET_INCIDENTS"; payload: ThreatIncident[] }
  | { type: "PUSH_INCIDENT"; payload: ThreatIncident }
  | { type: "RESOLVE_INCIDENT"; payload: string }
  | { type: "SET_AUDIT_LOGS"; payload: AuditEntry[] }
  | { type: "PUSH_AUDIT_LOG"; payload: AuditEntry }
  | { type: "SET_NET_ATTACKS"; payload: NetworkAttackEvent[] }
  | { type: "PUSH_NET_ATTACK"; payload: NetworkAttackEvent }
  | { type: "SET_DEBUG_LOGS"; payload: DebugEntry[] }
  | { type: "PUSH_DEBUG_LOG"; payload: DebugEntry }
  | {
      type: "SET_IPC_STATUS";
      payload: { connected: boolean; transport?: "tauri" | "sse" | "connecting" };
    };

export const initialStore: ProcessStoreState = {
  nodes: new Map(),
  anomalies: [],
  systemMetrics: null,
  netMetrics: null,
  openCount: 0,
  telemetry: [],
  incidents: [],
  auditLogs: [],
  netAttacks: [],
  debugLogs: [],
  ipcConnected: false,
  ipcTransport: "connecting",
  lastEventTs: null,
};

function flattenNodes(
  roots: ProcessNode[],
  map = new Map<number, ProcessNode>()
): Map<number, ProcessNode> {
  for (const node of roots) {
    map.set(node.pid, node);
    if (node.children && node.children.length > 0) {
      flattenNodes(node.children, map);
    }
  }
  return map;
}

function prependUniqueById<T extends { id: string }>(
  list: T[],
  item: T,
  maxItems = 500
): T[] {
  const filtered = list.filter((existing) => existing.id !== item.id);
  return [item, ...filtered].slice(0, maxItems);
}

export function processReducer(
  state: ProcessStoreState,
  action: ProcessStoreAction
): ProcessStoreState {
  switch (action.type) {
    case "SET_PROCESSES": {
      const flatMap = flattenNodes(action.payload);
      const anomalies = Array.from(flatMap.values()).filter((n) => n.flagged);
      return {
        ...state,
        nodes: flatMap,
        anomalies,
      };
    }

    case "HANDLE_PROC_SNAPSHOT": {
      const flatMap = flattenNodes(action.payload.tree || []);
      const anomalies = Array.from(flatMap.values()).filter((n) => n.flagged);
      return {
        ...state,
        nodes: flatMap,
        anomalies,
        systemMetrics: action.payload.metrics ?? state.systemMetrics,
        lastEventTs: Date.now(),
      };
    }

    case "SET_SYSTEM_METRICS": {
      return {
        ...state,
        systemMetrics: action.payload,
      };
    }

    case "SET_NET_METRICS": {
      return {
        ...state,
        netMetrics: action.payload,
      };
    }

    case "HANDLE_PROC_EVENT": {
      const ev = action.payload;
      const nextMap = new Map(state.nodes);

      if (ev.kind === "exited") {
        const existing = nextMap.get(ev.pid);
        nextMap.delete(ev.pid);
        if (existing && nextMap.has(existing.ppid)) {
          const parent = nextMap.get(existing.ppid)!;
          nextMap.set(existing.ppid, {
            ...parent,
            children: parent.children.filter((c) => c.pid !== ev.pid),
          });
        }
      } else {
        const prevNode = nextMap.get(ev.pid);
        const flagged = Boolean(ev.flagged ?? ev.anomaly);
        const node: ProcessNode = {
          id: ev.id || `proc-${ev.pid}`,
          pid: ev.pid,
          ppid: ev.ppid,
          uid: ev.uid,
          gid: ev.gid,
          name: ev.name,
          state: ev.state ?? prevNode?.state,
          state_label: ev.state_label ?? prevNode?.state_label,
          cpu_pct: ev.cpu_pct ?? prevNode?.cpu_pct,
          mem_rss_kb: ev.mem_rss_kb ?? prevNode?.mem_rss_kb,
          mem_pct: ev.mem_pct ?? prevNode?.mem_pct,
          threads: ev.threads ?? prevNode?.threads,
          fd_count: ev.fd_count ?? prevNode?.fd_count,
          io_read_bytes: ev.io_read_bytes ?? prevNode?.io_read_bytes,
          io_write_bytes: ev.io_write_bytes ?? prevNode?.io_write_bytes,
          cmdline: ev.cmdline || [],
          exe: ev.exe ?? null,
          cwd: ev.cwd ?? null,
          start_time: ev.start_time,
          ts: ev.ts,
          flagged,
          anomaly: ev.anomaly ?? null,
          children: prevNode?.children || ev.children || [],
        };
        nextMap.set(ev.pid, node);

        if (node.ppid !== node.pid && nextMap.has(node.ppid)) {
          const parent = nextMap.get(node.ppid)!;
          const withoutDup = parent.children.filter((c) => c.pid !== node.pid);
          nextMap.set(node.ppid, {
            ...parent,
            children: [...withoutDup, node],
          });
        }
      }

      const anomalies = Array.from(nextMap.values()).filter((n) => n.flagged);
      return {
        ...state,
        nodes: nextMap,
        anomalies,
        lastEventTs: Date.now(),
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
        lastEventTs: Date.now(),
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
        lastEventTs: Date.now(),
      };
    }

    case "SET_OPEN_COUNT": {
      return {
        ...state,
        openCount: action.payload,
      };
    }

    case "SET_TELEMETRY": {
      return {
        ...state,
        telemetry: action.payload.slice(0, 500),
      };
    }

    case "PUSH_TELEMETRY": {
      return {
        ...state,
        telemetry: prependUniqueById(state.telemetry, action.payload, 500),
        lastEventTs: Date.now(),
      };
    }

    case "SET_INCIDENTS": {
      const open = action.payload.filter((i) => !i.resolved).length;
      return {
        ...state,
        incidents: action.payload,
        openCount: open,
      };
    }

    case "PUSH_INCIDENT": {
      const nextIncidents = prependUniqueById(state.incidents, action.payload, 500);
      const open = nextIncidents.filter((i) => !i.resolved).length;
      return {
        ...state,
        incidents: nextIncidents,
        openCount: open,
        lastEventTs: Date.now(),
      };
    }

    case "RESOLVE_INCIDENT": {
      const nextIncidents = state.incidents.map((inc) =>
        inc.id === action.payload ? { ...inc, resolved: true } : inc
      );
      const hasMatch = state.incidents.some((inc) => inc.id === action.payload);
      return {
        ...state,
        incidents: nextIncidents,
        openCount: hasMatch
          ? nextIncidents.filter((i) => !i.resolved).length
          : Math.max(0, state.openCount - 1),
        lastEventTs: Date.now(),
      };
    }

    case "SET_AUDIT_LOGS": {
      return {
        ...state,
        auditLogs: action.payload.slice(0, 500),
      };
    }

    case "PUSH_AUDIT_LOG": {
      return {
        ...state,
        auditLogs: prependUniqueById(state.auditLogs, action.payload, 500),
        lastEventTs: Date.now(),
      };
    }

    case "SET_NET_ATTACKS": {
      return {
        ...state,
        netAttacks: action.payload.slice(0, 200),
      };
    }

    case "PUSH_NET_ATTACK": {
      return {
        ...state,
        netAttacks: prependUniqueById(state.netAttacks, action.payload, 200),
        lastEventTs: Date.now(),
      };
    }

    case "SET_DEBUG_LOGS": {
      return {
        ...state,
        debugLogs: action.payload.slice(0, 300),
      };
    }

    case "PUSH_DEBUG_LOG": {
      return {
        ...state,
        debugLogs: prependUniqueById(state.debugLogs, action.payload, 300),
        lastEventTs: Date.now(),
      };
    }

    case "SET_IPC_STATUS": {
      return {
        ...state,
        ipcConnected: action.payload.connected,
        ipcTransport: action.payload.transport || state.ipcTransport,
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
