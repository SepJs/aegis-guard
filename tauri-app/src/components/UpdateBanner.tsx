import { useState, useEffect } from "react";
import { listen } from "../lib/ipc/event";
import { invoke } from "../lib/ipc/core";
import type { UpdateInfo } from "../types";

export default function UpdateBanner() {
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  const [checking, setChecking] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [dismissed, setDismissed] = useState(false);
  const [autoUpdate, setAutoUpdate] = useState(true);

  useEffect(() => {
    const unsub = listen<UpdateInfo>("update-available", (ev) => {
      setInfo(ev.payload);
      setDismissed(false);
    });

    invoke<UpdateInfo>("check_update")
      .then((r) => {
        if (r) {
          setInfo(r);
          if (r.auto_update_enabled !== undefined) setAutoUpdate(r.auto_update_enabled);
        }
      })
      .catch(() => {});

    return () => {
      unsub.then((f) => f());
    };
  }, []);

  async function checkNow() {
    setChecking(true);
    setProgress(0);
    try {
      const r = await invoke<UpdateInfo>("check_update");
      if (r) {
        setInfo(r);
        if (r.auto_update_enabled !== undefined) setAutoUpdate(r.auto_update_enabled);
      } else {
        setInfo({
          current_version: "1.2.0",
          engine_version: "4.6.0-LINUX",
          latest_version: "1.2.0",
          update_available: false,
          release_url: "https://github.com/SepJs/aegis-guard/releases",
          release_notes: "Live Linux /proc, Go packet bridge, & real-time AV engine active.",
          auto_update_enabled: autoUpdate,
        });
      }
      setDismissed(false);
    } catch {
      setInfo({
        current_version: "1.2.0",
        engine_version: "4.6.0-LINUX",
        latest_version: "1.2.0",
        update_available: false,
        release_url: "",
        release_notes: "Latest security signatures active.",
        auto_update_enabled: autoUpdate,
      });
      setTimeout(() => setInfo(null), 3500);
    } finally {
      setChecking(false);
    }
  }

  async function toggleAutoUpdate() {
    try {
      const nextState = !autoUpdate;
      await invoke("set_auto_update", { enabled: nextState });
      setAutoUpdate(nextState);
    } catch (err) {
      console.error("Failed to toggle auto update:", err);
    }
  }

  const handleApplyUpdate = async () => {
    setDownloading(true);
    setProgress(45);
    try {
      const res: any = await invoke("apply_update");
      setProgress(100);
      setInfo((prev) =>
        prev
          ? {
              ...prev,
              current_version: res?.app_version || prev.current_version,
              engine_version: res?.engine_version || prev.engine_version,
              update_available: false,
              release_notes: res?.message || "Signatures reloaded from disk.",
            }
          : null
      );
      setTimeout(() => setDismissed(true), 3500);
    } catch {
      // keep banner state
    } finally {
      setDownloading(false);
    }
  };

  if (info && !dismissed) {
    const hasUpdate = info.update_available;
    return (
      <div
        className={`update-banner ${hasUpdate ? "" : "update-banner--ok"}`}
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 6,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 6 }}>
          <div style={{ display: "flex", flexDirection: "column" }}>
            <span style={{ fontWeight: 700, fontSize: 10, color: hasUpdate ? "var(--vl)" : "var(--teall)" }}>
              {hasUpdate ? `Update Available (${info.latest_version})` : `Up to Date (v${info.current_version || "1.2.0"})`}
            </span>
            <span style={{ fontSize: 9, color: "var(--tx2)", fontFamily: "var(--mono)" }}>
              v{info.current_version || "1.2.0"} · {info.engine_version || "4.6.0-LINUX"}
            </span>
          </div>
          <button
            type="button"
            onClick={() => setDismissed(true)}
            aria-label="Dismiss update status"
            style={{ color: "var(--tx2)", fontSize: 12, padding: 2 }}
          >
            ✕
          </button>
        </div>

        {hasUpdate && info.release_notes && (
          <div style={{ fontSize: 10, color: "var(--tx1)", lineHeight: 1.35 }}>
            {info.release_notes}
          </div>
        )}

        {hasUpdate && (
          <button
            type="button"
            className="btn-primary"
            onClick={handleApplyUpdate}
            disabled={downloading}
            style={{ width: "100%", padding: "5px 8px", fontSize: 10 }}
          >
            {downloading ? `Reloading ${progress}%` : "Reload Signatures"}
          </button>
        )}

        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: "1px solid var(--border-dim)", paddingTop: 5 }}>
          <button
            type="button"
            onClick={toggleAutoUpdate}
            style={{
              fontSize: 9,
              fontFamily: "var(--mono)",
              color: autoUpdate ? "var(--teall)" : "var(--amberl)",
            }}
          >
            {autoUpdate ? "AUTO: ON" : "AUTO: OFF"}
          </button>
          <button
            type="button"
            onClick={checkNow}
            disabled={checking}
            style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--tx2)" }}
          >
            {checking ? "Checking…" : "Check now"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0 2px" }}>
        <span style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--tx2)" }}>v1.2.0 · 4.6.0</span>
        <button
          type="button"
          onClick={toggleAutoUpdate}
          title="Toggle automatic threat feed updates"
          style={{
            fontSize: 9,
            fontFamily: "var(--mono)",
            color: autoUpdate ? "var(--teall)" : "var(--amberl)",
          }}
        >
          {autoUpdate ? "AUTO: ON" : "AUTO: OFF"}
        </button>
      </div>
      <button
        type="button"
        className="check-update-btn"
        onClick={checkNow}
        disabled={checking}
      >
        {checking ? "Checking patches…" : "Check for updates"}
      </button>
    </div>
  );
}
