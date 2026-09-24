use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{info, warn};
use uuid::Uuid;

use crate::models::{DeceptionEvent, TrapKind};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotService {
    pub id: String,
    pub name: String,
    pub port: u16,
    pub service_type: String,
    pub active: bool,
    pub hits: u64,
    pub last_hit_ts: Option<i64>,
}

pub struct HoneypotManager {
    services: Arc<RwLock<HashMap<String, HoneypotService>>>,
}

impl HoneypotManager {
    pub fn new() -> Self {
        Self {
            services: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn list_services(&self) -> Vec<HoneypotService> {
        self.services.read().unwrap().values().cloned().collect()
    }

    pub async fn spawn_listener(
        &self,
        name: &str,
        port: u16,
        service_type: &str,
    ) -> Result<HoneypotService> {
        let id = Uuid::new_v4().to_string();
        let service = HoneypotService {
            id: id.clone(),
            name: name.to_string(),
            port,
            service_type: service_type.to_string(),
            active: true,
            hits: 0,
            last_hit_ts: None,
        };

        self.services.write().unwrap().insert(id.clone(), service.clone());

        let services_clone = self.services.clone();
        let id_clone = id.clone();
        let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;

        tokio::spawn(async move {
            match TcpListener::bind(bind_addr).await {
                Ok(listener) => {
                    info!(port = port, name = name, "Honeypot listener active");
                    loop {
                        match listener.accept().await {
                            Ok((stream, remote_addr)) => {
                                let now = Utc::now().timestamp_millis();
                                warn!(
                                    remote = %remote_addr,
                                    port = port,
                                    name = name,
                                    "🚨 HONEYPOT TRIGGERED: Unauthorized connection to decoy service"
                                );

                                if let Ok(mut map) = services_clone.write() {
                                    if let Some(srv) = map.get_mut(&id_clone) {
                                        srv.hits += 1;
                                        srv.last_hit_ts = Some(now);
                                    }
                                }

                                // Emulate fake service banner then close
                                drop(stream);
                            }
                            Err(e) => {
                                warn!("Honeypot accept error: {e}");
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(port = port, "Could not bind honeypot port: {e}");
                    if let Ok(mut map) = services_clone.write() {
                        if let Some(srv) = map.get_mut(&id_clone) {
                            srv.active = false;
                        }
                    }
                }
            }
        });

        Ok(service)
    }

    pub fn record_connection(&self, id: &str, remote_ip: &str) -> Option<DeceptionEvent> {
        let now = Utc::now().timestamp_millis();
        let mut map = self.services.write().unwrap();
        if let Some(srv) = map.get_mut(id) {
            srv.hits += 1;
            srv.last_hit_ts = Some(now);
            Some(DeceptionEvent {
                id: Uuid::new_v4().to_string(),
                kind: TrapKind::HoneypotConnected,
                target: format!("{}:{}", remote_ip, srv.port),
                trigger_pid: None,
                trigger_proc: Some(srv.name.clone()),
                confidence: "high".to_string(),
                reason: format!("Decoy honeypot service '{}' received connection from {}", srv.name, remote_ip),
                ts: now,
            })
        } else {
            None
        }
    }
}

impl Default for HoneypotManager {
    fn default() -> Self {
        Self::new()
    }
}
