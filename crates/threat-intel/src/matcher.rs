use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use anyhow::Result;
use tracing::{info, warn};

use crate::feed;
use crate::ioc::{IocStats, IocStore};
use crate::models::{IocKind, IocMatch};

pub struct ThreatMatcher { store: Arc<IocStore> }

impl ThreatMatcher {
    pub fn new() -> Result<Self> {
        let store = Arc::new(IocStore::new());
        feed::load_bundled(&store)?;
        feed::load_custom(&store).ok();
        Ok(Self { store })
    }

    pub fn start_auto_update(&self) {
        let store = self.store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
                info!("refreshing CTI feeds...");
                match feed::fetch_urlhaus(&store).await {
                    Ok(n) => info!("URLhaus refresh: {} IOCs", n),
                    Err(e) => warn!("URLhaus refresh failed: {}", e),
                }
                feed::load_custom(&store).ok();
            }
        });
    }

    pub fn check_ip(&self, ip: &str, context: &str) -> Option<IocMatch> {
        let addr: IpAddr = ip.parse().ok()?;
        let entry = self.store.check_ip(&addr)?;
        Some(IocMatch { ioc: ip.to_string(), kind: IocKind::Ip, threat_type: entry.threat_type, feed: entry.feed, confidence: entry.confidence, context: context.to_string() })
    }

    pub fn check_domain(&self, domain: &str, context: &str) -> Option<IocMatch> {
        let entry = self.store.check_domain(domain)?;
        Some(IocMatch { ioc: domain.to_string(), kind: IocKind::Domain, threat_type: entry.threat_type, feed: entry.feed, confidence: entry.confidence, context: context.to_string() })
    }

    pub fn check_hash(&self, hash: &str, context: &str) -> Option<IocMatch> {
        let entry = self.store.check_hash(hash)?;
        Some(IocMatch { ioc: hash.to_string(), kind: IocKind::Sha256, threat_type: entry.threat_type, feed: entry.feed, confidence: entry.confidence, context: context.to_string() })
    }

    pub fn check_file(&self, path: &str) -> Option<IocMatch> {
        let data = std::fs::read(path).ok()?;
        let hash = blake3::hash(&data).to_hex().to_string();
        self.check_hash(&hash, &format!("file:{}", path))
    }

    pub fn stats(&self) -> IocStats { self.store.stats() }
}
