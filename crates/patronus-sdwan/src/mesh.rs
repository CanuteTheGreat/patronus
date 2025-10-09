//! Mesh management - automatic site discovery and peering

use crate::{database::Database, peering::PeeringManager, types::*, Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

const MULTICAST_ADDR: &str = "239.255.42.1:51821";
const ANNOUNCEMENT_INTERVAL: Duration = Duration::from_secs(30);
const SITE_TIMEOUT: Duration = Duration::from_secs(120);

/// Mesh manager handles site discovery and automatic VPN peering
pub struct MeshManager {
    site_id: SiteId,
    site_name: String,
    db: Arc<Database>,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    running: Arc<RwLock<bool>>,
    known_sites: Arc<RwLock<HashMap<SiteId, SiteInfo>>>,
    announcement_tx: mpsc::Sender<SiteAnnouncement>,
    announcement_rx: Arc<RwLock<mpsc::Receiver<SiteAnnouncement>>>,
    tasks: Arc<RwLock<Vec<JoinHandle<()>>>>,
    peering_manager: Arc<PeeringManager>,
}

/// Internal site information
#[derive(Clone)]
struct SiteInfo {
    site: Site,
    last_announcement: SystemTime,
}

impl MeshManager {
    /// Create a new mesh manager
    pub fn new(site_id: SiteId, site_name: String, db: Arc<Database>) -> Self {
        // Generate signing keypair for site authentication
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let (announcement_tx, announcement_rx) = mpsc::channel(100);

        // Create peering manager
        let peering_manager = Arc::new(PeeringManager::new(
            db.clone(),
            site_id,
            "wg-sdwan".to_string(),
            51820,
        ));

        Self {
            site_id,
            site_name,
            db,
            signing_key,
            verifying_key,
            running: Arc::new(RwLock::new(false)),
            known_sites: Arc::new(RwLock::new(HashMap::new())),
            announcement_tx,
            announcement_rx: Arc::new(RwLock::new(announcement_rx)),
            tasks: Arc::new(RwLock::new(Vec::new())),
            peering_manager,
        }
    }

    /// Start the mesh manager
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }

        info!(
            site_id = %self.site_id,
            site_name = %self.site_name,
            "Starting mesh manager"
        );

        *running = true;

        // Initialize WireGuard interface
        info!("Initializing WireGuard interface for SD-WAN");
        if let Err(e) = self.peering_manager.initialize_interface().await {
            warn!("Failed to initialize WireGuard interface: {}", e);
            // Continue anyway - may work without root or with existing interface
        }

        // Start announcement broadcaster
        let broadcaster_task = self.start_broadcaster().await?;

        // Start announcement listener
        let listener_task = self.start_listener().await?;

        // Start auto-peering worker
        let peering_task = self.start_auto_peering().await?;

        // Start site timeout checker
        let timeout_task = self.start_timeout_checker().await?;

        // Store task handles
        let mut tasks = self.tasks.write().await;
        tasks.push(broadcaster_task);
        tasks.push(listener_task);
        tasks.push(peering_task);
        tasks.push(timeout_task);

        Ok(())
    }

    /// Stop the mesh manager
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }

        info!("Stopping mesh manager");
        *running = false;

        // Abort all tasks
        let mut tasks = self.tasks.write().await;
        for task in tasks.drain(..) {
            task.abort();
        }

        Ok(())
    }

    /// Start the announcement broadcaster
    async fn start_broadcaster(&self) -> Result<JoinHandle<()>> {
        let site_id = self.site_id;
        let site_name = self.site_name.clone();
        let signing_key = self.signing_key.clone();
        let running = self.running.clone();

        let task = tokio::spawn(async move {
            info!("Starting announcement broadcaster");

            // Create UDP socket for multicast
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to create broadcast socket: {}", e);
                    return;
                }
            };

            // Enable broadcast
            if let Err(e) = socket.set_broadcast(true) {
                error!("Failed to enable broadcast: {}", e);
                return;
            }

            let mut interval = tokio::time::interval(ANNOUNCEMENT_INTERVAL);

            while *running.read().await {
                interval.tick().await;

                // Create announcement
                let announcement = SiteAnnouncement {
                    site_id,
                    site_name: site_name.clone(),
                    public_key: signing_key.verifying_key().to_bytes().to_vec(),
                    endpoints: vec![
                        // TODO: Discover actual endpoints
                        Endpoint {
                            address: "0.0.0.0:51820".parse().unwrap(),
                            interface_type: "auto".to_string(),
                            cost_per_gb: 0.0,
                            reachable: true,
                        }
                    ],
                    capabilities: SiteCapabilities::default(),
                    timestamp: SystemTime::now(),
                    signature: Vec::new(), // Will be filled below
                };

                // Serialize announcement for signing
                let announcement_bytes = match bincode::serialize(&(
                    &announcement.site_id,
                    &announcement.site_name,
                    &announcement.public_key,
                    &announcement.endpoints,
                    &announcement.capabilities,
                    &announcement.timestamp,
                )) {
                    Ok(b) => b,
                    Err(e) => {
                        error!("Failed to serialize announcement: {}", e);
                        continue;
                    }
                };

                // Sign announcement
                let signature = signing_key.sign(&announcement_bytes);

                let mut signed_announcement = announcement;
                signed_announcement.signature = signature.to_bytes().to_vec();

                // Serialize full announcement
                let message = match bincode::serialize(&signed_announcement) {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Failed to serialize signed announcement: {}", e);
                        continue;
                    }
                };

                // Broadcast to multicast group
                if let Err(e) = socket.send_to(&message, MULTICAST_ADDR).await {
                    warn!("Failed to send announcement: {}", e);
                }

                debug!("Announced site {} to mesh", site_id);
            }

            info!("Announcement broadcaster stopped");
        });

        Ok(task)
    }

    /// Start the announcement listener
    async fn start_listener(&self) -> Result<JoinHandle<()>> {
        let running = self.running.clone();
        let announcement_tx = self.announcement_tx.clone();
        let own_site_id = self.site_id;

        let task = tokio::spawn(async move {
            info!("Starting announcement listener");

            // Bind to multicast address
            let socket = match UdpSocket::bind(MULTICAST_ADDR).await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to bind listener socket: {}", e);
                    return;
                }
            };

            // Join multicast group
            let multicast_addr = MULTICAST_ADDR.parse::<SocketAddr>().unwrap().ip();
            if let Err(e) = socket.join_multicast_v4(
                multicast_addr.to_string().parse().unwrap(),
                "0.0.0.0".parse().unwrap(),
            ) {
                error!("Failed to join multicast group: {}", e);
                return;
            }

            let mut buf = vec![0u8; 65536];

            while *running.read().await {
                match socket.recv_from(&mut buf).await {
                    Ok((len, _addr)) => {
                        // Deserialize announcement
                        let announcement: SiteAnnouncement = match bincode::deserialize(&buf[..len]) {
                            Ok(a) => a,
                            Err(e) => {
                                warn!("Failed to deserialize announcement: {}", e);
                                continue;
                            }
                        };

                        // Ignore our own announcements
                        if announcement.site_id == own_site_id {
                            continue;
                        }

                        // Send to processing channel
                        if let Err(e) = announcement_tx.send(announcement).await {
                            error!("Failed to queue announcement: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to receive announcement: {}", e);
                    }
                }
            }

            info!("Announcement listener stopped");
        });

        Ok(task)
    }

    /// Start auto-peering worker
    async fn start_auto_peering(&self) -> Result<JoinHandle<()>> {
        let running = self.running.clone();
        let announcement_rx = self.announcement_rx.clone();
        let db = self.db.clone();
        let known_sites = self.known_sites.clone();
        let peering_manager = self.peering_manager.clone();

        let task = tokio::spawn(async move {
            info!("Starting auto-peering worker");

            let mut rx = announcement_rx.write().await;

            while *running.read().await {
                match rx.recv().await {
                    Some(announcement) => {
                        // Verify signature
                        if let Err(e) = Self::verify_announcement(&announcement) {
                            warn!(
                                "Invalid announcement signature from site {}: {}",
                                announcement.site_id, e
                            );
                            continue;
                        }

                        info!(
                            site_id = %announcement.site_id,
                            site_name = %announcement.site_name,
                            "Received verified site announcement"
                        );

                        // Create or update site
                        let site = Site {
                            id: announcement.site_id,
                            name: announcement.site_name.clone(),
                            public_key: announcement.public_key.clone(),
                            endpoints: announcement.endpoints.clone(),
                            created_at: announcement.timestamp,
                            last_seen: SystemTime::now(),
                            status: SiteStatus::Active,
                        };

                        // Store in database
                        if let Err(e) = db.upsert_site(&site).await {
                            error!("Failed to store site: {}", e);
                            continue;
                        }

                        // Update known sites
                        let mut sites = known_sites.write().await;
                        let is_new_site = !sites.contains_key(&site.id);
                        sites.insert(
                            site.id,
                            SiteInfo {
                                site: site.clone(),
                                last_announcement: SystemTime::now(),
                            },
                        );
                        drop(sites); // Release lock before async operation

                        debug!("Site {} registered in mesh", announcement.site_id);

                        // Establish VPN tunnel if this is a new site
                        if is_new_site {
                            info!("Establishing WireGuard tunnel to site {}", site.id);
                            if let Err(e) = peering_manager.add_peer(&site).await {
                                error!("Failed to establish VPN tunnel: {}", e);
                            } else {
                                info!("Successfully peered with site {}", site.id);
                            }
                        }
                    }
                    None => break,
                }
            }

            info!("Auto-peering worker stopped");
        });

        Ok(task)
    }

    /// Start site timeout checker
    async fn start_timeout_checker(&self) -> Result<JoinHandle<()>> {
        let running = self.running.clone();
        let known_sites = self.known_sites.clone();
        let db = self.db.clone();

        let task = tokio::spawn(async move {
            info!("Starting site timeout checker");

            let mut interval = tokio::time::interval(Duration::from_secs(30));

            while *running.read().await {
                interval.tick().await;

                let now = SystemTime::now();
                let mut sites = known_sites.write().await;
                let mut timed_out = Vec::new();

                // Check for timed-out sites
                for (site_id, info) in sites.iter() {
                    if let Ok(elapsed) = now.duration_since(info.last_announcement) {
                        if elapsed > SITE_TIMEOUT {
                            timed_out.push(*site_id);
                        }
                    }
                }

                // Mark timed-out sites as inactive
                for site_id in timed_out {
                    warn!("Site {} timed out, marking as inactive", site_id);

                    if let Some(mut info) = sites.remove(&site_id) {
                        info.site.status = SiteStatus::Inactive;
                        info.site.last_seen = now;

                        if let Err(e) = db.upsert_site(&info.site).await {
                            error!("Failed to update site status: {}", e);
                        }
                    }
                }
            }

            info!("Site timeout checker stopped");
        });

        Ok(task)
    }

    /// Verify announcement signature
    fn verify_announcement(announcement: &SiteAnnouncement) -> Result<()> {
        // Extract public key
        let public_key_bytes: [u8; 32] = announcement.public_key[..32]
            .try_into()
            .map_err(|_| Error::AuthenticationFailed("Invalid public key length".to_string()))?;

        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| Error::AuthenticationFailed(format!("Invalid public key: {}", e)))?;

        // Serialize announcement data (without signature)
        let announcement_bytes = bincode::serialize(&(
            &announcement.site_id,
            &announcement.site_name,
            &announcement.public_key,
            &announcement.endpoints,
            &announcement.capabilities,
            &announcement.timestamp,
        ))
        .map_err(|e| Error::Serialization(serde_json::Error::custom(e.to_string())))?;

        // Extract signature
        let signature_bytes: [u8; 64] = announcement.signature[..64]
            .try_into()
            .map_err(|_| Error::AuthenticationFailed("Invalid signature length".to_string()))?;

        let signature = Signature::from_bytes(&signature_bytes);

        // Verify signature
        verifying_key
            .verify(&announcement_bytes, &signature)
            .map_err(|e| Error::AuthenticationFailed(format!("Signature verification failed: {}", e)))?;

        Ok(())
    }

    /// Get list of known sites
    pub async fn list_known_sites(&self) -> Vec<Site> {
        let sites = self.known_sites.read().await;
        sites.values().map(|info| info.site.clone()).collect()
    }

    /// Check if site is known
    pub async fn is_site_known(&self, site_id: &SiteId) -> bool {
        self.known_sites.read().await.contains_key(site_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mesh_manager_creation() {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let manager = MeshManager::new(
            SiteId::generate(),
            "test-site".to_string(),
            db,
        );

        assert!(manager.start().await.is_ok());
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(manager.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_announcement_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let site_id = SiteId::generate();

        let announcement = SiteAnnouncement {
            site_id,
            site_name: "test".to_string(),
            public_key: signing_key.verifying_key().to_bytes().to_vec(),
            endpoints: Vec::new(),
            capabilities: SiteCapabilities::default(),
            timestamp: SystemTime::now(),
            signature: Vec::new(),
        };

        // Serialize and sign
        let announcement_bytes = bincode::serialize(&(
            &announcement.site_id,
            &announcement.site_name,
            &announcement.public_key,
            &announcement.endpoints,
            &announcement.capabilities,
            &announcement.timestamp,
        ))
        .unwrap();

        let signature = signing_key.sign(&announcement_bytes);

        let mut signed_announcement = announcement;
        signed_announcement.signature = signature.to_bytes().to_vec();

        // Verify
        assert!(MeshManager::verify_announcement(&signed_announcement).is_ok());
    }

    #[tokio::test]
    async fn test_site_list() {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let manager = MeshManager::new(
            SiteId::generate(),
            "test-site".to_string(),
            db,
        );

        let sites = manager.list_known_sites().await;
        assert_eq!(sites.len(), 0);
    }
}
