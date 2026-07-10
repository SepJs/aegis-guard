mod models;
mod rules;
mod rules_path;
mod scanner;

use anyhow::Result;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use ipc::{writer::IpcWriter, DEFAULT_SOCKET_PATH};
use models::Confidence;
use rules::RuleEngine;
use rules_path::PathRuleEngine;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env("AEGIS_LOG").unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .init();

    let socket_path = std::env::var("AEGIS_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

    info!("Aegis-Guard Process Engine — by Vladimir Unknown");
    info!("rules: PAR-001..008 + PATH-001..004 + ARG-001..003 + ENV-001..002");
    info!(socket = %socket_path, "IPC target");

    let rules = RuleEngine::new();
    let path_rules = PathRuleEngine::new();
    let mut recv = scanner::start(rules, path_rules);
    let mut ipc = IpcWriter::new(&socket_path);

    while let Some(event) = recv.recv().await {
        if let Some(ref a) = event.anomaly {
            let emoji = match a.confidence {
                Confidence::High => "🔴", Confidence::Medium => "🟡", Confidence::Low => "⚪",
            };
            warn!(rule = %a.rule, confidence = %a.confidence, pid = event.pid, name = %event.name, "{}  ANOMALY — {}", emoji, a.reason);
        }
        if let Err(e) = ipc.send(&event).await {
            warn!("IPC send failed: {e}");
        }
    }
    Ok(())
}
