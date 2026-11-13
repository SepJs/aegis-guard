import { useState, useEffect } from "react";

type TargetPlatform = "linux" | "macos" | "windows";

export default function InstallModal({ onClose }: { onClose: () => void }) {
  const [platform, setPlatform] = useState<TargetPlatform>("linux");
  const [detectedOs, setDetectedOs] = useState<string>("Detecting environment…");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes("win")) {
      setPlatform("windows");
      setDetectedOs("Microsoft Windows (x64 / ARM64)");
    } else if (ua.includes("mac")) {
      setPlatform("macos");
      setDetectedOs("Apple macOS (Apple Silicon & Intel)");
    } else {
      setPlatform("linux");
      setDetectedOs("Linux (Ubuntu, Debian, Fedora, Arch, Alpine)");
    }
  }, []);

  const commands: Record<TargetPlatform, { remote: string; local: string; file: string }> = {
    linux: {
      remote: "curl -sSL https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-linux.sh | sudo bash -s -- --yes",
      local: "bash installers/install-linux.sh --console   # or: bash aegis.sh --console",
      file: "install-linux.sh",
    },
    macos: {
      remote: "curl -sSL https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-macos.sh | bash -s -- --yes",
      local: "bash installers/install-macos.sh --console   # or: bash aegis.sh --console",
      file: "install-macos.sh",
    },
    windows: {
      remote: 'powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-windows.ps1 | iex"',
      local: ".\\installers\\install-windows.ps1 -ConsoleOnly",
      file: "install-windows.bat",
    },
  };

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(label);
    setTimeout(() => setCopiedKey(null), 2200);
  };

  const downloadInstallerScript = (os: TargetPlatform) => {
    let filename = commands[os].file;
    let content = "";
    if (os === "windows") {
      content = [
        "@echo off",
        "title Aegis-Guard Windows Installer (v1.2.0)",
        "net session >nul 2>&1",
        "if %errorLevel% neq 0 (",
        "  powershell -NoProfile -Command \"Start-Process '%~f0' -Verb RunAs\"",
        "  exit /b",
        ")",
        'powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-windows.ps1 | iex"',
        "pause",
        "",
      ].join("\r\n");
    } else if (os === "macos") {
      content = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        'curl -sSL https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-macos.sh | bash -s -- --yes',
        "",
      ].join("\n");
    } else {
      content = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        'if [ "$EUID" -ne 0 ]; then exec sudo bash "$0" "$@"; fi',
        'curl -sSL https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-linux.sh | bash -s -- --yes',
        "",
      ].join("\n");
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

  const current = commands[platform];

  return (
    <div
      className="modal-backdrop"
      id="install-modal-overlay"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        id="install-modal-box"
        style={{
          width: "min(680px, 94vw)",
          background: "var(--bg1)",
          border: "1px solid var(--border2)",
          borderRadius: 8,
          boxShadow: "0 24px 64px rgba(0, 0, 0, 0.7)",
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <div className="modal-header">
          <div>
            <h2 style={{ margin: 0, fontSize: 15, fontWeight: 700, color: "var(--tx0)" }}>
              Cross-Platform Console &amp; Desktop Installer
            </h2>
            <p style={{ margin: "2px 0 0", fontSize: 12, color: "var(--tx2)" }}>
              Automated setup for Linux, macOS, and Windows (v1.2.0)
            </p>
          </div>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close installer modal">
            ✕
          </button>
        </div>

        <div style={{ padding: 20, display: "flex", flexDirection: "column", gap: 16 }}>
          <div
            style={{
              padding: "12px 14px",
              borderRadius: 6,
              background: "var(--bg0)",
              border: "1px solid var(--border)",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              flexWrap: "wrap",
              gap: 10,
            }}
          >
            <div>
              <div style={{ fontSize: 10, color: "var(--teall)", fontWeight: 700, textTransform: "uppercase" }}>
                Detected Platform
              </div>
              <div style={{ fontSize: 13, fontWeight: 600, color: "var(--tx0)", marginTop: 2 }}>
                {detectedOs}
              </div>
            </div>
            <div style={{ display: "flex", gap: 6 }}>
              {(["linux", "macos", "windows"] as TargetPlatform[]).map((p) => (
                <button
                  key={p}
                  type="button"
                  className={`sm-btn ${platform === p ? "sm-btn--active" : ""}`}
                  onClick={() => setPlatform(p)}
                >
                  {p === "macos" ? "macOS" : p.charAt(0).toUpperCase() + p.slice(1)}
                </button>
              ))}
            </div>
          </div>

          <div
            style={{
              padding: 16,
              borderRadius: 6,
              background: "var(--bg0)",
              border: "1px solid var(--border)",
              display: "flex",
              flexDirection: "column",
              gap: 12,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: 13, fontWeight: 600, color: "var(--tx0)" }}>
                Remote Console Install ({platform === "macos" ? "macOS" : platform.toUpperCase()})
              </span>
              <span className="mono" style={{ fontSize: 10, color: "var(--teall)" }}>
                {current.file}
              </span>
            </div>

            <div
              style={{
                display: "flex",
                alignItems: "center",
                background: "var(--bg1)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                padding: "8px 12px",
                gap: 8,
              }}
            >
              <code style={{ flex: 1, fontSize: 11, color: "var(--teall)", overflowX: "auto", whiteSpace: "nowrap" }}>
                {current.remote}
              </code>
              <button type="button" className="sm-btn" onClick={() => handleCopy(current.remote, "remote")}>
                {copiedKey === "remote" ? "Copied" : "Copy"}
              </button>
            </div>

            <div style={{ fontSize: 11, fontWeight: 600, color: "var(--tx2)", marginTop: 2 }}>
              Or run headless console mode from a cloned repository:
            </div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                background: "var(--bg1)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                padding: "8px 12px",
                gap: 8,
              }}
            >
              <code style={{ flex: 1, fontSize: 11, color: "var(--vl)", overflowX: "auto", whiteSpace: "nowrap" }}>
                {current.local}
              </code>
              <button type="button" className="sm-btn" onClick={() => handleCopy(current.local, "local")}>
                {copiedKey === "local" ? "Copied" : "Copy"}
              </button>
            </div>

            <button
              type="button"
              className="btn-primary"
              onClick={() => downloadInstallerScript(platform)}
              style={{ width: "100%", padding: "9px 14px", marginTop: 4 }}
            >
              Download {current.file}
            </button>
          </div>
        </div>

        <div
          style={{
            padding: "12px 20px",
            borderTop: "1px solid var(--border)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            background: "var(--bg0)",
          }}
        >
          <span style={{ fontSize: 11, color: "var(--tx2)" }}>
            Supports headless server console (port 3000) and native desktop packaging
          </span>
          <button type="button" className="sm-btn" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
