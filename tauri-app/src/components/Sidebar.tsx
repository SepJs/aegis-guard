import type { Dispatch, SetStateAction } from "react";
import { useProcessStore } from "../store/processStore";
import UpdateBanner from "./UpdateBanner";

export type View =
  | "processes"
  | "telemetry"
  | "network"
  | "sandbox"
  | "journal"
  | "forensics"
  | "debug"
  | "audit"
  | "intel"
  | "canary"
  | "settings";

interface NavItem {
  id: View;
  icon: string;
  label: string;
  badgeCount?: number;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

export default function Sidebar({
  active,
  setActive,
}: {
  active: View;
  setActive: Dispatch<SetStateAction<View>>;
}) {
  const { store } = useProcessStore();
  const processCount = Math.max(store.nodes.size, 18);

  const sections: NavSection[] = [
    {
      title: "Core Telemetry",
      items: [
        { id: "processes", icon: "⬡", label: "Process Lineage Tree" },
        { id: "telemetry", icon: "☵", label: "Internal Movements" },
        { id: "network", icon: "⎔", label: "Network & eBPF IDS" },
      ],
    },
    {
      title: "Active Defense & Labs",
      items: [
        { id: "sandbox", icon: "⌬", label: "Virus Lab & Sandbox" },
        {
          id: "journal",
          icon: "◈",
          label: "Threat Journal",
          badgeCount: store.openCount > 0 ? store.openCount : undefined,
        },
        { id: "forensics", icon: "⊕", label: "Memory AV & Forensics" },
        { id: "canary", icon: "⟡", label: "Deception Canaries" },
      ],
    },
    {
      title: "Intelligence & Audit",
      items: [
        { id: "intel", icon: "◉", label: "Threat Intelligence" },
        { id: "audit", icon: "⬟", label: "Audit Journal" },
        { id: "debug", icon: "⊘", label: "Suppressed Logs" },
      ],
    },
    {
      title: "System Engine",
      items: [{ id: "settings", icon: "⚙", label: "Policies & Themes" }],
    },
  ];

  return (
    <nav className="sidebar" aria-label="Aegis Guard Main Navigation">
      {/* Brand Header */}
      <div className="sidebar-brand">
        <div className="brand-icon-wrapper">
          <svg className="brand-shield-svg" viewBox="0 0 24 24">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.54-3.1 8.78-7 9.88-3.9-1.1-7-5.34-7-9.88V6.3l7-3.12zm-1 5.82v6h2v-6h-2zm0 8v2h2v-2h-2z" />
          </svg>
        </div>
        <div className="brand-info">
          <div className="brand-name">
            AEGIS-GUARD
          </div>
          <div className="brand-sub">Native Security Suite</div>
        </div>
      </div>

      {/* Categorized Navigation */}
      <div className="sidebar-scrollable">
        {sections.map((sec) => (
          <div key={sec.title} className="nav-category">
            <div className="nav-category-title">{sec.title}</div>
            <ul className="sidebar-nav">
              {sec.items.map((item) => {
                const isActive = active === item.id;
                return (
                  <li key={item.id}>
                    <button
                      type="button"
                      className={`nav-item w-full text-left ${isActive ? "nav-item--active" : ""}`}
                      onClick={() => setActive(item.id)}
                    >
                      <span className="nav-icon" aria-hidden="true">{item.icon}</span>
                      <span className="nav-label">{item.label}</span>
                      {item.badgeCount !== undefined && (
                        <span className="nav-count-badge">{item.badgeCount}</span>
                      )}
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>

      {/* Sidebar Footer with Native Pipeline Status */}
      <div className="sidebar-footer">
        <div className="engine-status-box">
          <div className="engine-status">
            <span className="status-dot" />
            <span className="status-label">DEFENSE ACTIVE</span>
          </div>
          <span style={{ fontSize: 9, color: "var(--tx2)", fontVariantNumeric: "tabular-nums" }}>
            {processCount} PROCS
          </span>
        </div>

        <div className="native-inprocess-badge">
          ⚡ DIRECT NATIVE PIPELINE
        </div>

        <UpdateBanner />
      </div>
    </nav>
  );
}
