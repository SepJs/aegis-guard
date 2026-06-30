// ioc.rs — IOC store: in-memory HashSet/HashMap for O(1) matching

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::RwLock;

use anyhow::Result;
use ipnet::IpNet;

use crate::models::ThreatEntry;

/// In-memory IOC store.
pub struct IocStore {
    ips:     RwLock<HashMap<IpAddr, ThreatEntry>>,
    cidrs:   RwLock<Vec<(IpNet, ThreatEntry)>>,
    domains: RwLock<HashMap<String, ThreatEntry>>,
    sha256:  RwLock<HashMap<String, ThreatEntry>>,
    md5:     RwLock<HashMap<String, ThreatEntry>>,
    urls:    RwLock<HashSet<String>>,
}

impl IocStore {
    pub fn new() -> Self {
        Self {
            ips:     RwLock::new(HashMap::new()),
            cidrs:   RwLock::new(Vec::new()),
            domains: RwLock::new(HashMap::new()),
            sha256:  RwLock::new(HashMap::new()),
            md5:     RwLock::new(HashMap::new()),
            urls:    RwLock::new(HashSet::new()),
        }
    }

    /// Ingest a batch of threat entries.
    pub fn ingest(&self, entries: Vec<ThreatEntry>) -> Result<usize> {
        let mut count = 0usize;
        for e in entries {
            match e.kind {
                crate::models::IocKind::Ip => {
                    if let Ok(ip) = e.ioc.parse::<IpAddr>() {
                        self.ips.write().unwrap().insert(ip, e);
                        count += 1;
                    } else if let Ok(net) = e.ioc.parse::<IpNet>() {
                        self.cidrs.write().unwrap().push((net, e));
                        count += 1;
                    }
                }
                crate::models::IocKind::Domain => {
                    let key = e.ioc.to_lowercase();
                    self.domains.write().unwrap().insert(key, e);
                    count += 1;
                }
                crate::models::IocKind::Sha256 => {
                    let key = e.ioc.to_lowercase();
                    self.sha256.write().unwrap().insert(key, e);
                    count += 1;
                }
                crate::models::IocKind::Md5 => {
                    let key = e.ioc.to_lowercase();
                    self.md5.write().unwrap().insert(key, e);
                    count += 1;
                }
                crate::models::IocKind::Url => {
                    self.urls.write().unwrap().insert(e.ioc.clone());
                    count += 1;
                }
                _ => {}
            }
        }
        Ok(count)
    }

    pub fn check_ip(&self, ip: &IpAddr) -> Option<ThreatEntry> {
        // Exact match first
        if let Some(e) = self.ips.read().unwrap().get(ip) {
            return Some(e.clone());
        }
        // CIDR range match
        for (net, entry) in self.cidrs.read().unwrap().iter() {
            if net.contains(ip) {
                return Some(entry.clone());
            }
        }
        None
    }

    pub fn check_domain(&self, domain: &str) -> Option<ThreatEntry> {
        let key = domain.to_lowercase();
        // Exact match
        if let Some(e) = self.domains.read().unwrap().get(&key) {
            return Some(e.clone());
        }
        // Subdomain match: check if domain ends with any known bad domain
        let domains = self.domains.read().unwrap();
        for (bad, entry) in domains.iter() {
            if key.ends_with(&format!(".{}", bad)) || key == bad.as_str() {
                return Some(entry.clone());
            }
        }
        None
    }

    pub fn check_hash(&self, hash: &str) -> Option<ThreatEntry> {
        let h = hash.to_lowercase();
        self.sha256.read().unwrap().get(&h)
            .or_else(|| self.md5.read().unwrap().get(&h))
            .cloned()
    }

    pub fn stats(&self) -> IocStats {
        IocStats {
            ips:     self.ips.read().unwrap().len(),
            cidrs:   self.cidrs.read().unwrap().len(),
            domains: self.domains.read().unwrap().len(),
            hashes:  self.sha256.read().unwrap().len() + self.md5.read().unwrap().len(),
        }
    }
}

impl Default for IocStore { fn default() -> Self { Self::new() } }

#[derive(Debug, Clone, serde::Serialize)]
pub struct IocStats {
    pub ips:     usize,
    pub cidrs:   usize,
    pub domains: usize,
    pub hashes:  usize,
}
