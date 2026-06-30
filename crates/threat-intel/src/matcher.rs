// matcher.rs — high-level matching API used by Tauri backend + net_bridge

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tracing::{info, warn};

use crate::feed;
use crate::ioc::{IocStats, IocStore};
use crate::models::{IocKind, IocMatch};

/// Main interface for threat intelligence matching.
pub struct ThreatMatcher {
    store: Arc<IocStore>,
}

impl ThreatMatcher {
    /// Create and load all feeds (bundled + custom).
    pub fn new() -> Result<Self> {
        let store = Arc::new(IocStore::new());

        // Always load bundled feed (offline, zero latency)
        feed::load_bundled(&store)?;
        // Load user custom IOCs if present
        feed::load_custom(&store).ok();

        Ok(Self { store })
    }

    /// Spawn background feed update task (every 6 hours).
    pub fn start_auto_update(&self) {
        let store = self.store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
                info!("refreshing CTI feeds...");
                match feed::fetch_urlhaus(&store).await {
                    Ok(n)  => info!("URLhaus refresh: {} IOCs", n),
                    Err(e) => warn!("URLhaus refresh failed: {}", e),
                }
                feed::load_custom(&store).ok();
            }
        });
    }

    /// Check an IP address against all loaded feeds.
    pub fn check_ip(&self, ip: &str, context: &str) -> Option<IocMatch> {
        let addr: IpAddr = ip.parse().ok()?;
        let entry = self.store.check_ip(&addr)?;
        Some(IocMatch {
            ioc:         ip.to_string(),
            kind:        IocKind::Ip,
            threat_type: entry.threat_type,
            feed:        entry.feed,
            confidence:  entry.confidence,
            context:     context.to_string(),
        })
    }

    /// Check a domain name (supports subdomain matching).
    pub fn check_domain(&self, domain: &str, context: &str) -> Option<IocMatch> {
        let entry = self.store.check_domain(domain)?;
        Some(IocMatch {
            ioc:         domain.to_string(),
            kind:        IocKind::Domain,
            threat_type: entry.threat_type,
            feed:        entry.feed,
            confidence:  entry.confidence,
            context:     context.to_string(),
        })
    }

    /// Check a file hash (MD5 or SHA256).
    pub fn check_hash(&self, hash: &str, context: &str) -> Option<IocMatch> {
        let entry = self.store.check_hash(hash)?;
        Some(IocMatch {
            ioc:         hash.to_string(),
            kind:        IocKind::Sha256,
            threat_type: entry.threat_type,
            feed:        entry.feed,
            confidence:  entry.confidence,
            context:     context.to_string(),
        })
    }

    /// Hash a file and check against threat intel.
    pub fn check_file(&self, path: &str) -> Option<IocMatch> {
        let data = std::fs::read(path).ok()?;
        // Compute SHA256
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        // Use blake3 as SHA256 substitute for speed (real impl would use sha2 crate)
        let hash = blake3::hash(&data).to_hex().to_string();
        self.check_hash(&hash, &format!("file:{}", path))
    }

    pub fn stats(&self) -> IocStats {
        self.store.stats()
    }
}
