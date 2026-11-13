/**
 * Aegis-Guard IPC Core
 * Routes all commands directly to native Tauri IPC runtime or the live Linux kernel Express backend (/api/ipc).
 */

export function isTauriRuntime(): boolean {
  return (
    typeof window !== "undefined" &&
    Boolean((window as any).__TAURI_INTERNALS__) &&
    Boolean((window as any).__TAURI__?.core?.invoke)
  );
}

export async function invoke<T = any>(cmd: string, args: Record<string, any> = {}): Promise<T> {
  // 1. Check if running inside native Tauri desktop runtime
  if (isTauriRuntime()) {
    return (await (window as any).__TAURI__.core.invoke(cmd, args)) as T;
  }

  // 2. Query live Linux kernel backend (/api/ipc)
  const resp = await fetch("/api/ipc", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cmd, args }),
  });

  if (!resp.ok) {
    let errMsg = `IPC command '${cmd}' failed with HTTP ${resp.status}`;
    try {
      const errBody = await resp.json();
      if (errBody?.error) errMsg = errBody.error;
    } catch {}
    throw new Error(errMsg);
  }

  return (await resp.json()) as T;
}
