import { aegisSecurityEngine } from "../engine/securityEngine";

export interface Event<T> {
  event: string;
  id: number;
  payload: T;
}

export type EventCallback<T> = (event: Event<T>) => void;
export type UnlistenFn = () => void;

let eventCounter = 1;

export async function listen<T = any>(
  event: string,
  handler: EventCallback<T>
): Promise<UnlistenFn> {
  // If running inside actual Tauri runtime
  if (typeof window !== "undefined") {
    const internals = (window as any).__TAURI_INTERNALS__;
    if (internals && typeof internals.listen === "function") {
      try {
        return await internals.listen(event, handler);
      } catch (err) {
        console.warn(`[Tauri Native listen failed, falling back to Aegis Engine]`, err);
      }
    }
  }

  const listenerWrapper = (payload: T) => {
    handler({
      event,
      id: eventCounter++,
      payload,
    });
  };

  aegisSecurityEngine.addListener(event, listenerWrapper);

  return () => {
    aegisSecurityEngine.removeListener(event, listenerWrapper);
  };
}

export async function emit(event: string, payload?: any): Promise<void> {
  aegisSecurityEngine.emit(event, payload);
}
