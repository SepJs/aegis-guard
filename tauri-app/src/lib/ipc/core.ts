import { aegisSecurityEngine } from "../engine/securityEngine";

let nativeHostChecked = false;
let nativeHostAvailable = false;
let nativeHostBaseUrl = "http://127.0.0.1:50053";

export async function detectNativeHost(): Promise<boolean> {
  if (typeof window === "undefined") return false;
  
  const candidateUrls = [
    window.location.origin,
    "http://127.0.0.1:50053",
    "http://localhost:50053",
  ];

  for (const url of candidateUrls) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 1200);
      const res = await fetch(`${url}/api/status`, {
        method: "GET",
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (res.ok) {
        const data = await res.json();
        if (data && (data.platform === "windows" || data.real_mode)) {
          nativeHostBaseUrl = url;
          nativeHostAvailable = true;
          nativeHostChecked = true;
          console.info(`[Aegis Bridge] Connected to Native Windows OS Host: ${url}`);
          return true;
        }
      }
    } catch {
      // try next candidate
    }
  }

  nativeHostChecked = true;
  nativeHostAvailable = false;
  return false;
}

export async function invoke<T = any>(cmd: string, args?: any): Promise<T> {
  // 1. If running inside Tauri v2 native runtime
  if (typeof window !== "undefined") {
    const internals = (window as any).__TAURI_INTERNALS__;
    if (internals && typeof internals.invoke === "function") {
      try {
        return await internals.invoke(cmd, args);
      } catch (err) {
        console.warn(`[Tauri Native invoke failed for ${cmd}]`, err);
      }
    }
  }

  // 2. Check if native Windows host daemon is running
  if (typeof window !== "undefined") {
    if (!nativeHostChecked) {
      await detectNativeHost();
    }

    if (nativeHostAvailable) {
      try {
        const res = await fetch(`${nativeHostBaseUrl}/api/ipc`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cmd, args }),
        });
        if (res.ok) {
          const json = await res.json();
          if (json && json.__handled) {
            return json.result as T;
          }
        }
      } catch (err) {
        console.warn(`[Native Bridge invoke failed for ${cmd}, falling back]`, err);
      }
    }
  }

  // 3. Fallback to internal Aegis Engine
  return aegisSecurityEngine.handleInvoke<T>(cmd, args);
}
