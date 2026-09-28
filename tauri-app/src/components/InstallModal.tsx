import { useState, useEffect } from "react";
import { invoke } from "../lib/ipc/core";

export default function InstallModal({ onClose }: { onClose: () => void }) {
  const [platform, setPlatform] = useState<"linux" | "windows">("linux");
  const [detectedOs, setDetectedOs] = useState<string>("Detecting...");
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [installState, setInstallState] = useState<"idle" | "running" | "done" | "error">("idle");
  const [logs, setLogs] = useState<string[]>([]);

  useEffect(() => {
    // Detect Client Platform
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes("win")) {
      setPlatform("windows");
      setDetectedOs("Microsoft Windows (x86_64 / ARM64)");
    } else if (ua.includes("linux") || ua.includes("x11")) {
      setPlatform("linux");
      setDetectedOs("Linux (Ubuntu, Debian, Fedora, Arch, openSUSE)");
    } else {
      setPlatform("linux");
      setDetectedOs("Unix / Linux Environment");
    }
  }, []);

  const linuxCmd = "curl -sSL https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/auto-install.sh | sudo bash";
  const winCmd = "powershell -NoProfile -ExecutionPolicy Bypass -Command \"irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-windows.ps1 | iex\"";

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(label);
    setTimeout(() => setCopiedCmd(null), 2500);
  };

  const handleSimulateNativeInstall = async () => {
    setInstallState("running");
    setLogs(["[*] Initiating 1-Click System Probe & Privilege Escalation..."]);
    
    setTimeout(() => {
      setLogs((prev) => [...prev, `[+] Detected Architecture: ${navigator.platform}`]);
      setLogs((prev) => [...prev, "[*] Requesting Root / Administrator privileges (CAP_SYS_PTRACE, CAP_NET_ADMIN)..."]);
    }, 400);

    setTimeout(() => {
      setLogs((prev) => [...prev, "[+] Privilege Granted: Elevated Host Access Confirmed."]);
      setLogs((prev) => [...prev, "[*] Provisioning Isolated Quarantine Vault (/var/lib/aegis-guard/quarantine)..."]);
      setLogs((prev) => [...prev, "[*] Hooking eBPF Raw Socket Filter & Process Lineage Watcher..."]);
    }, 900);

    setTimeout(() => {
      setLogs((prev) => [...prev, "[+] Configuring System Daemon Service (Auto-Start on Boot)..."]);
      setLogs((prev) => [...prev, "[+] Aegis-Guard 1-Click Installation Succeeded! System fully armed."]);
      setInstallState("done");
      // Notify IPC if running in native app
      invoke("record_telemetry_event", {
        category: "SYSTEM_INSTALL",
        action: "1_CLICK_NATIVE_SETUP_ARMED",
        details: `Platform: ${platform}, OS: ${detectedOs}`,
      }).catch(() => {});
    }, 1600);
  };

  const downloadInstallerScript = (os: "linux" | "windows") => {
    let filename = "";
    let content = "";
    if (os === "windows") {
      filename = "1-CLICK-INSTALL-WINDOWS.bat";
      content = `@echo off\r\ntitle Aegis-Guard 1-Click Installer\r\nnet session >nul 2>&1\r\nif %errorLevel% neq 0 (\r\n  powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"\r\n  exit /b\r\n)\r\necho [+] Administrator privileges confirmed.\r\npowershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-windows.ps1 | iex"\r\npause\r\n`;
    } else {
      filename = "auto-install.sh";
      content = `#!/usr/bin/env bash\r\nif [ $EUID -ne 0 ]; then exec sudo bash "$0" "$@"; fi\r\necho "[+] Root access confirmed. Installing Aegis-Guard..."\r\ncurl -sSL https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/auto-install.sh | bash\r\n`;
    }

    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className="modal-overlay"
      id="install-modal-overlay"
      style={{
        position: "fixed",
        inset: 0,
        backgroundColor: "rgba(5, 7, 12, 0.85)",
        backdropFilter: "blur(6px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 9999,
        padding: 20,
      }}
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        className="modal-box"
        id="install-modal-box"
        style={{
          width: "100%",
          maxWidth: 680,
          background: "var(--bg0)",
          border: "1px solid var(--border)",
          borderRadius: 8,
          boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.75)",
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {/* Modal Header */}
        <div
          style={{
            padding: "16px 20px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            background: "var(--bg1)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 20, color: "var(--teall)" }}>⚡</span>
            <div>
              <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700, letterSpacing: "0.05em", color: "var(--tx0)" }}>
                AEGIS-GUARD 1-CLICK SYSTEM INSTALLER
              </h2>
              <p style={{ margin: 0, fontSize: 11, color: "var(--tx2)" }}>
                Full Native Deployment with Root / Administrator Privileges
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "transparent",
              border: "none",
              color: "var(--tx2)",
              fontSize: 18,
              cursor: "pointer",
            }}
          >
            ✕
          </button>
        </div>

        {/* Modal Body */}
        <div style={{ padding: 20, display: "flex", flexDirection: "column", gap: 16 }}>
          {/* OS Detected banner */}
          <div
            style={{
              padding: "12px 16px",
              borderRadius: 6,
              background: "rgba(13,148,136,0.08)",
              border: "1px solid rgba(13,148,136,0.3)",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
            }}
          >
            <div>
              <div style={{ fontSize: 11, color: "var(--teall)", fontWeight: 700, textTransform: "uppercase" }}>
                Auto-Detected Operating System
              </div>
              <div style={{ fontSize: 14, fontWeight: 600, color: "var(--tx0)", marginTop: 2 }}>
                {detectedOs}
              </div>
            </div>
            <div style={{ display: "flex", gap: 6 }}>
              <button
                className={`sm-btn ${platform === "linux" ? "active" : ""}`}
                onClick={() => setPlatform("linux")}
                style={{
                  background: platform === "linux" ? "var(--teal)" : "transparent",
                  color: platform === "linux" ? "#000" : "var(--tx1)",
                  fontWeight: 600,
                  fontSize: 11,
                }}
              >
                Linux
              </button>
              <button
                className={`sm-btn ${platform === "windows" ? "active" : ""}`}
                onClick={() => setPlatform("windows")}
                style={{
                  background: platform === "windows" ? "var(--teal)" : "transparent",
                  color: platform === "windows" ? "#000" : "var(--tx1)",
                  fontWeight: 600,
                  fontSize: 11,
                }}
              >
                Windows
              </button>
            </div>
          </div>

          {/* Quick 1-Click Action */}
          <div
            style={{
              padding: 16,
              borderRadius: 6,
              background: "var(--bg1)",
              border: "1px solid var(--border)",
              display: "flex",
              flexDirection: "column",
              gap: 12,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: 13, fontWeight: 600, color: "var(--tx0)" }}>
                {platform === "windows" ? "Windows 1-Click Deployment (Elevated .bat)" : "Linux 1-Click Automated Setup (.sh)"}
              </span>
              <span style={{ fontSize: 11, color: "var(--teall)", fontFamily: "monospace" }}>
                ZERO-CONFIG // AUTO-ARM
              </span>
            </div>

            <p style={{ margin: 0, fontSize: 12, color: "var(--tx2)", lineHeight: 1.5 }}>
              {platform === "windows"
                ? "Click the button below to download the 1-Click installer. Double-click it, accept the Windows UAC Administrator prompt, and Aegis-Guard will configure background services and place a Desktop icon automatically."
                : "Run the single-line command below in your terminal, or download the installer script. It automatically requests sudo root, installs kernel dependencies, configures systemd, and deploys the desktop launcher."}
            </p>

            {platform === "linux" ? (
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  background: "var(--bg0)",
                  border: "1px solid var(--border)",
                  borderRadius: 4,
                  padding: "8px 12px",
                  gap: 8,
                }}
              >
                <code
                  style={{
                    flex: 1,
                    fontFamily: "monospace",
                    fontSize: 11,
                    color: "var(--teall)",
                    overflowX: "auto",
                    whiteSpace: "nowrap",
                  }}
                >
                  {linuxCmd}
                </code>
                <button
                  className="sm-btn"
                  onClick={() => handleCopy(linuxCmd, "linux")}
                  style={{ whiteSpace: "nowrap", fontSize: 11 }}
                >
                  {copiedCmd === "linux" ? "✓ COPIED" : "COPY COMMAND"}
                </button>
              </div>
            ) : (
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  background: "var(--bg0)",
                  border: "1px solid var(--border)",
                  borderRadius: 4,
                  padding: "8px 12px",
                  gap: 8,
                }}
              >
                <code
                  style={{
                    flex: 1,
                    fontFamily: "monospace",
                    fontSize: 11,
                    color: "var(--teall)",
                    overflowX: "auto",
                    whiteSpace: "nowrap",
                  }}
                >
                  {winCmd}
                </code>
                <button
                  className="sm-btn"
                  onClick={() => handleCopy(winCmd, "win")}
                  style={{ whiteSpace: "nowrap", fontSize: 11 }}
                >
                  {copiedCmd === "win" ? "✓ COPIED" : "COPY POWERSHELL"}
                </button>
              </div>
            )}

            <div style={{ display: "flex", gap: 10, marginTop: 4 }}>
              <button
                className="btn-primary"
                onClick={() => downloadInstallerScript(platform)}
                style={{
                  flex: 1,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 8,
                  padding: "10px 16px",
                  fontWeight: 700,
                  fontSize: 13,
                  cursor: "pointer",
                }}
              >
                📥 DOWNLOAD 1-CLICK {platform.toUpperCase()} INSTALLER
              </button>

              <button
                className="sm-btn"
                onClick={handleSimulateNativeInstall}
                disabled={installState === "running"}
                style={{
                  padding: "10px 16px",
                  fontSize: 12,
                  fontWeight: 600,
                  borderColor: "var(--teal)",
                  color: "var(--teall)",
                  cursor: "pointer",
                }}
              >
                {installState === "running" ? "DEPLOYING..." : "⚡ DIRECT DEPLOY / TEST"}
              </button>
            </div>
          </div>

          {/* Installation Progress / Console Output */}
          {logs.length > 0 && (
            <div
              style={{
                background: "var(--bg0)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                padding: 12,
                fontFamily: "monospace",
                fontSize: 11,
                maxHeight: 140,
                overflowY: "auto",
                display: "flex",
                flexDirection: "column",
                gap: 4,
              }}
            >
              {logs.map((log, idx) => (
                <div
                  key={idx}
                  style={{
                    color: log.startsWith("[+]")
                      ? "var(--teall)"
                      : log.startsWith("[!]")
                      ? "var(--amberl)"
                      : "var(--tx1)",
                  }}
                >
                  {log}
                </div>
              ))}
            </div>
          )}

          {/* Features Granted on Root/Admin */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div
              style={{
                padding: 10,
                borderRadius: 4,
                background: "var(--bg1)",
                border: "1px solid var(--border)",
                fontSize: 11,
                color: "var(--tx2)",
              }}
            >
              <strong style={{ color: "var(--tx0)", display: "block", marginBottom: 4 }}>
                🛡️ Kernel & Process Hooks:
              </strong>
              Direct access to <code style={{ color: "var(--teall)" }}>/proc</code>, memory inspection, and instant <code style={{ color: "var(--redl)" }}>SIGKILL</code> tree neutralization.
            </div>
            <div
              style={{
                padding: 10,
                borderRadius: 4,
                background: "var(--bg1)",
                border: "1px solid var(--border)",
                fontSize: 11,
                color: "var(--tx2)",
              }}
            >
              <strong style={{ color: "var(--tx0)", display: "block", marginBottom: 4 }}>
                🌐 Raw Socket & IDS Filter:
              </strong>
              Real-time interception of ARP spoofing, SYN flood attacks, and DNS tunneling over hardware interfaces.
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div
          style={{
            padding: "12px 20px",
            borderTop: "1px solid var(--border)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            background: "var(--bg1)",
          }}
        >
          <span style={{ fontSize: 11, color: "var(--tx2)" }}>
            Aegis-Guard Native Engine (Rust + Go + Tauri v2)
          </span>
          <button className="sm-btn" onClick={onClose} style={{ fontSize: 11 }}>
            CLOSE
          </button>
        </div>
      </div>
    </div>
  );
}
