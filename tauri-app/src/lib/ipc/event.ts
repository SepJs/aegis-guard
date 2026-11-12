type UnlistenFn = () => void;
type EventHandler<T = any> = (event: { event: string; payload: T }) => void;

const eventListeners = new Map<string, Set<EventHandler>>();

// Connect to real SSE stream from backend server
if (typeof window !== "undefined" && typeof EventSource !== "undefined") {
  try {
    const es = new EventSource("/api/events");
    es.onmessage = (e) => {
      try {
        const parsed = JSON.parse(e.data);
        if (parsed.event && parsed.payload) {
          emitLocal(parsed.event, parsed.payload);
        }
      } catch {}
    };
    es.addEventListener("anomaly", (e: any) => {
      try {
        const parsed = JSON.parse(e.data);
        emitLocal("anomaly", parsed.payload || parsed);
      } catch {}
    });
    es.addEventListener("net-attack", (e: any) => {
      try {
        const parsed = JSON.parse(e.data);
        emitLocal("net-attack", parsed.payload || parsed);
      } catch {}
    });
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
  // If running inside native Tauri runtime with window.__TAURI_INTERNALS__
  if (
    typeof window !== "undefined" &&
    (window as any).__TAURI_INTERNALS__ &&
    (window as any).__TAURI__?.event?.listen
  ) {
    try {
      return await (window as any).__TAURI__.event.listen(event, handler);
    } catch (e) {
      console.warn("Tauri native listen failed, using browser event bus:", e);
    }
  }

  // Web in-browser event bus
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
      // Fall through to in-memory dispatch
    }
  }

  emitLocal(event, payload);
}
