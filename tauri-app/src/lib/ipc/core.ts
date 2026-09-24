import { aegisSecurityEngine } from "../engine/securityEngine";

export async function detectNativeHost(): Promise<boolean> {
  // Direct native embedded runtime confirmation
  if (typeof window !== "undefined") {
    const internals = (window as any).__TAURI_INTERNALS__;
    if (internals && typeof internals.invoke === "function") {
      return true;
    }
  }
  return true;
}

export async function invoke<T = any>(cmd: string, args?: any): Promise<T> {
  // 1. Direct Native Tauri v2 Inter-Process Communication
  if (typeof window !== "undefined") {
    const internals = (window as any).__TAURI_INTERNALS__;
    if (internals && typeof internals.invoke === "function") {
      try {
        return await internals.invoke(cmd, args);
      } catch (err) {
        console.warn(`[Tauri Native IPC failed for ${cmd}]`, err);
      }
    }
  }

  // 2. Direct In-Process Security Core Engine (Zero localhost network overhead)
  return aegisSecurityEngine.handleInvoke<T>(cmd, args);
}
