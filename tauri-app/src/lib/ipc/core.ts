import { aegisSecurityEngine } from "../engine/securityEngine";

export async function invoke<T = any>(cmd: string, args?: any): Promise<T> {
  // Check if running inside actual Tauri desktop runtime
  if (typeof window !== "undefined") {
    const internals = (window as any).__TAURI_INTERNALS__;
    if (internals && typeof internals.invoke === "function") {
      try {
        return await internals.invoke(cmd, args);
      } catch (err) {
        console.warn(`[Tauri Native invoke failed, falling back to Aegis Engine]`, err);
      }
    }
  }

  // Fallback to internal Aegis Security Engine
  return aegisSecurityEngine.handleInvoke<T>(cmd, args);
}
