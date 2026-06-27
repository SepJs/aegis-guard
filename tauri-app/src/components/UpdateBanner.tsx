import { useState, useEffect } from "react";
import { listen }  from "@tauri-apps/api/event";
import { invoke }  from "@tauri-apps/api/core";
import type { UpdateInfo } from "../types";

export default function UpdateBanner() {
  const [info,      setInfo]      = useState<UpdateInfo | null>(null);
  const [checking,  setChecking]  = useState(false);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    const unsub = listen<UpdateInfo>("update-available", ev => {
      setInfo(ev.payload);
      setDismissed(false);
    });
    return () => { unsub.then(f => f()); };
  }, []);

  async function checkNow() {
    setChecking(true);
    try {
      const r = await invoke<UpdateInfo>("check_update");
      setInfo(r);
      if (!r.update_available) setTimeout(() => setInfo(null), 3000);
    } catch { /* network error — silent */ }
    finally { setChecking(false); }
  }

  if (info && !dismissed) {
    const cls = info.update_available ? "" : "update-banner--ok";
    return (
      <div className={`update-banner ${cls}`}>
        <span className="update-msg">
          {info.update_available
            ? `↑ UPDATE AVAILABLE — v${info.latest_version}`
            : `✓ AEGIS-GUARD IS UP TO DATE (v${info.current_version})`}
        </span>
        {info.update_available && (
          <a className="update-link" href={info.release_url}
             target="_blank" rel="noreferrer">RELEASE NOTES</a>
        )}
        <button onClick={() => setDismissed(true)}
          style={{ marginLeft:"auto", background:"none", border:"none",
                   color:"var(--vl)", cursor:"pointer", fontFamily:"var(--mono)", fontSize:10 }}>
          ✕
        </button>
      </div>
    );
  }

  return (
    <button className="check-update-btn" onClick={checkNow} disabled={checking}>
      {checking ? "CHECKING…" : "CHECK FOR UPDATES"}
    </button>
  );
}
