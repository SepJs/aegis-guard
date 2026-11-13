type UnlistenFn = () => void;
type EventHandler<T = any> = (event: { event: string; payload: T }) => void;

const eventListeners = new Map<string, Set<EventHandler>>();

const SSE_CHANNELS = [
  "proc-event",
  "proc-snapshot",
  "telemetry-event",
  "anomaly",
  "net-attack",
  "net-update",
  "packet-inspection",
  "incident-resolved",
  "sandbox-update",
  "audit-entry",
  "debug-entry",
  "update-available",
] as const;

let sseConnected = false;

export function isIpcStreamConnected(): boolean {
  return sseConnected;
}

export function isNativeTauriRuntime(): boolean {
  return (
    typeof window !== "undefined" &&
    Boolean((window as any).__TAURI_INTERNALS__) &&
    Boolean((window as any).__TAURI__?.event?.listen)
  );
}

// Connect to real-time SSE event stream from the backend engine
if (typeof window !== "undefined" && !isNativeTauriRuntime() && typeof EventSource !== "undefined") {
  try {
    const es = new EventSource("/api/events");

    es.onopen = () => {
      sseConnected = true;
      emitLocal("ipc-status", { connected: true, transport: "sse" });
    };

    es.onerror = () => {
      sseConnected = false;
      emitLocal("ipc-status", { connected: false, transport: "sse" });
    };

    es.onmessage = (e) => {
      try {
        const parsed = JSON.parse(e.data);
        if (parsed.event && parsed.payload !== undefined) {
          emitLocal(parsed.event, parsed.payload);
        }
      } catch {}
    };

    for (const channel of SSE_CHANNELS) {
      es.addEventListener(channel, (e: MessageEvent) => {
        try {
          const parsed = JSON.parse(e.data);
          emitLocal(channel, parsed.payload !== undefined ? parsed.payload : parsed);
        } catch {}
      });
    }
  } catch (e) {
    console.warn("Could not connect to SSE /api/events:", e);
  }
}

function emitLocal(event: string, payload: any) {
  const set = eventListeners.get(event);
  if (set) {
    const evObj = { event, payload };
    set.forEach((fn) => {
      try {
        fn(evObj);
      } catch (err) {
        console.error(`Error in event listener for ${event}:`, err);
      }
    });
  }
}

export async function listen<T = any>(
  event: string,
  handler: (event: { event: string; payload: T }) => void
): Promise<UnlistenFn> {
  // If running inside native Tauri runtime, bind directly to Tauri IPC event bus
  if (isNativeTauriRuntime()) {
    try {
      return await (window as any).__TAURI__.event.listen(event, handler);
    } catch (e) {
      console.warn(`Tauri native listen(${event}) failed:`, e);
    }
  }

  // Browser EventSource SSE relay bus
  if (!eventListeners.has(event)) {
    eventListeners.set(event, new Set());
  }
  const set = eventListeners.get(event)!;
  const wrapped: EventHandler = (e) => handler(e as any);
  set.add(wrapped);

  return () => {
    set.delete(wrapped);
    if (set.size === 0) {
      eventListeners.delete(event);
    }
  };
}

export async function emit<T = any>(event: string, payload: T): Promise<void> {
  if (
    typeof window !== "undefined" &&
    (window as any).__TAURI_INTERNALS__ &&
    (window as any).__TAURI__?.event?.emit
  ) {
    try {
      await (window as any).__TAURI__.event.emit(event, payload);
      return;
    } catch {
      // Fall through to local dispatch
    }
  }

  emitLocal(event, payload);
}
