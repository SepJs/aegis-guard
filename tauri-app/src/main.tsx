import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";

// Restore stored appearance theme or default to cyber-purple
const savedTheme = localStorage.getItem("aegis_theme") || "cyber-purple";
document.body.className = `theme-${savedTheme}`;

ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
