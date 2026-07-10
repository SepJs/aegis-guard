use anyhow::{Context, Result};
use chrono::Utc;
use tracing::info;

use crate::models::{IocKind, ThreatEntry};
use crate::ioc::IocStore;

const BUNDLED_FEED: &str = include_str!("bundled_feed.json");

pub fn load_bundled(store: &IocStore) -> Result<usize> {
    let entries: Vec<ThreatEntry> = serde_json::from_str(BUNDLED_FEED).context("parse bundled feed")?;
    let count = store.ingest(entries)?;
    info!("bundled IOC feed loaded: {} entries", count);
    Ok(count)
}

pub async fn fetch_urlhaus(store: &IocStore) -> Result<usize> {
    info!("fetching Abuse.ch URLhaus feed...");
    let client = reqwest::Client::builder().user_agent("aegis-guard/0.1 (CTI updater)").timeout(std::time::Duration::from_secs(30)).build()?;
    let resp: serde_json::Value = client.get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/500/").send().await?.json().await?;
    let mut entries = Vec::new();
    if let Some(urls) = resp["urls"].as_array() {
        for url in urls {
            let host = url["host"].as_str().unwrap_or("").to_string();
            if host.is_empty() { continue; }
            let kind = if host.parse::<std::net::IpAddr>().is_ok() { IocKind::Ip } else { IocKind::Domain };
            entries.push(ThreatEntry { ioc: host, kind, feed: "urlhaus".into(), threat_type: url["threat"].as_str().unwrap_or("malware_download").into(), confidence: 85, added_ts: Utc::now().timestamp_millis() });
        }
    }
    let count = store.ingest(entries)?;
    info!("URLhaus: ingested {} IOCs", count);
    Ok(count)
}

pub fn load_custom(store: &IocStore) -> Result<usize> {
    let path = "/var/lib/aegis/custom_iocs.json";
    if !std::path::Path::new(path).exists() { return Ok(0); }
    let raw = std::fs::read_to_string(path)?;
    let entries: Vec<ThreatEntry> = serde_json::from_str(&raw)?;
    let count = store.ingest(entries)?;
    info!("custom IOC feed loaded: {} entries", count);
    Ok(count)
}
