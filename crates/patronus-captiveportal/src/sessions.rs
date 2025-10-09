//! Client session management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSession {
    pub session_id: String,
    pub mac_address: String,
    pub ip_address: IpAddr,
    pub username: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub bytes_downloaded: u64,
    pub bytes_uploaded: u64,
    pub authenticated: bool,
}

pub struct SessionManager {
    sessions: HashMap<String, ClientSession>,
    mac_to_session: HashMap<String, String>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            mac_to_session: HashMap::new(),
        }
    }

    pub async fn create_session(&mut self, mac: String, ip: IpAddr) -> ClientSession {
        let session_id = Uuid::new_v4().to_string();
        let session = ClientSession {
            session_id: session_id.clone(),
            mac_address: mac.clone(),
            ip_address: ip,
            username: None,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            bytes_downloaded: 0,
            bytes_uploaded: 0,
            authenticated: true,
        };

        self.sessions.insert(session_id.clone(), session.clone());
        self.mac_to_session.insert(mac, session_id);

        session
    }

    pub async fn get_by_mac(&self, mac: &str) -> Option<&ClientSession> {
        self.mac_to_session.get(mac)
            .and_then(|id| self.sessions.get(id))
    }

    pub async fn terminate_by_mac(&mut self, mac: &str) {
        if let Some(session_id) = self.mac_to_session.remove(mac) {
            self.sessions.remove(&session_id);
        }
    }

    pub async fn cleanup_expired(&mut self, timeout_minutes: u32) {
        let now = Utc::now();
        self.sessions.retain(|_, session| {
            let age = now.signed_duration_since(session.last_activity);
            age.num_minutes() < timeout_minutes as i64
        });
    }
}
