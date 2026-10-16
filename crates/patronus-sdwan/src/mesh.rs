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
const WIREGUARD_PORT: u16 = 51820;
/// Oldest signed announcement timestamp we accept. Announcements are signed
/// but carry no nonce, so without a freshness bound any captured packet can be
/// replayed forever to resurrect a site (and re-trigger auto-peering).
const MAX_ANNOUNCEMENT_AGE: Duration = Duration::from_secs(300);
/// How far in the future a timestamp may be (tolerated clock skew).
const MAX_ANNOUNCEMENT_CLOCK_SKEW: Duration = Duration::from_secs(300);

/// Discover network endpoints from system interfaces
async fn discover_endpoints() -> Vec<Endpoint> {
    let mut endpoints = Vec::new();

    // Try to get interfaces from patronus-network
    match patronus_network::list_interfaces().await {
        Ok(interfaces) => {
            for iface in interfaces {
                // Skip loopback and disabled interfaces
                if iface.name.starts_with("lo") || !iface.enabled {
                    continue;
                }

                // Skip virtual interfaces (docker, veth, etc.)
                if iface.name.starts_with("docker")
                    || iface.name.starts_with("veth")
                    || iface.name.starts_with("br-")
                {
                    continue;
                }

                for ip in &iface.ip_addresses {
                    // Skip loopback and link-local addresses
                    if ip.is_loopback() {
                        continue;
                    }

                    // Skip link-local IPv4 (169.254.x.x) and IPv6 (fe80::)
                    match ip {
                        std::net::IpAddr::V4(v4) => {
                            if v4.is_link_local() {
                                continue;
                            }
                        }
                        std::net::IpAddr::V6(v6) => {
                            // Skip link-local IPv6 (fe80::/10)
                            let octets = v6.octets();
                            if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                                continue;
                            }
                        }
                    }

                    let addr = SocketAddr::new(*ip, WIREGUARD_PORT);
                    let (interface_type, cost_per_gb) = classify_interface(&iface.name);

                    endpoints.push(Endpoint {
                        address: addr,
                        interface_type,
                        cost_per_gb,
                        reachable: true,
                    });
                }
            }
        }
        Err(e) => {
            warn!("Failed to discover interfaces: {}", e);
        }
    }

    // If no endpoints were discovered, add a default fallback
    if endpoints.is_empty() {
        endpoints.push(Endpoint {
            address: "0.0.0.0:51820".parse().unwrap(),
            interface_type: "unknown".to_string(),
            cost_per_gb: 0.0,
            reachable: true,
        });
    }

    endpoints
}

/// Classify interface type and estimate cost per GB
fn classify_interface(name: &str) -> (String, f64) {
    // Ethernet interfaces
    if name.starts_with("eth") || name.starts_with("en") || name.starts_with("eno") {
        return ("ethernet".to_string(), 0.0); // Free
    }

    // WiFi interfaces
    if name.starts_with("wlan") || name.starts_with("wl") || name.starts_with("wifi") {
        return ("wifi".to_string(), 0.0); // Usually free
    }

    // Cellular/LTE interfaces
    if name.starts_with("wwan")
        || name.starts_with("lte")
        || name.starts_with("usb")
        || name.starts_with("ppp")
    {
        return ("cellular".to_string(), 0.05); // Metered - ~$5/100GB
    }

    // Starlink/Satellite
    if name.starts_with("starlink") || name.starts_with("sat") {
        return ("satellite".to_string(), 0.01); // Lower cost than cellular
    }

    // WireGuard/VPN tunnels
    if name.starts_with("wg") || name.starts_with("tun") || name.starts_with("tap") {
        return ("tunnel".to_string(), 0.0);
    }

    // Bridge interfaces
    if name.starts_with("br") || name.starts_with("virbr") {
        return ("bridge".to_string(), 0.0);
    }

    // Unknown - assume wired
    ("unknown".to_string(), 0.0)
}

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
    /// Signed timestamp of the last accepted announcement (replay ordering).
    announced_at: SystemTime,
}

/// Result of admitting a fresh, verified, key-pinned announcement.
struct AdmittedAnnouncement {
    site: Site,
    /// No WireGuard peer exists for this site yet (first sighting since
    /// start/timeout, or the site was re-keyed after an operator unpin).
    needs_peering: bool,
    /// An in-memory entry existed with a different key (operator deleted the
    /// pinned DB row to re-key the site); the old WireGuard peer must go.
    rekeyed: bool,
}

impl MeshManager {
    /// Create a new mesh manager.
    ///
    /// The site's identity (site ID + ed25519 announcement signing key) is
    /// loaded from the database, or generated and persisted on first start,
    /// so it is stable across restarts. Peers pin the first key they see for
    /// a site ID (trust-on-first-use), so a key that changed on every restart
    /// would lock this site out of the mesh.
    ///
    /// `site_id`: `None` uses the persisted site ID (or a new random one on
    /// first start). `Some(id)` seeds a fresh database with that ID; if the
    /// database already holds a different identity this is an error rather
    /// than a silent identity change.
    pub async fn new(
        site_id: Option<SiteId>,
        site_name: String,
        db: Arc<Database>,
    ) -> Result<Self> {
        let (site_id, signing_key) = Self::load_or_create_identity(&db, site_id).await?;
        let verifying_key = signing_key.verifying_key();

        let (announcement_tx, announcement_rx) = mpsc::channel(100);

        // Create peering manager
        let peering_manager = Arc::new(PeeringManager::new(
            db.clone(),
            site_id,
            "wg-sdwan".to_string(),
            51820,
        ));

        Ok(Self {
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
        })
    }

    /// Load the persisted local identity, or generate and persist one.
    async fn load_or_create_identity(
        db: &Database,
        requested_site_id: Option<SiteId>,
    ) -> Result<(SiteId, SigningKey)> {
        let (site_id, seed) = match db.get_local_identity().await? {
            Some(identity) => identity,
            None => {
                use rand::RngCore;
                let mut seed = [0u8; 32];
                OsRng.fill_bytes(&mut seed);
                let site_id = requested_site_id.unwrap_or_else(SiteId::generate);
                // init_local_identity returns whatever is actually stored, so
                // a concurrent first start can't leave us with a key that
                // isn't the persisted one.
                let stored = db.init_local_identity(&site_id, &seed).await?;
                info!(site_id = %stored.0, "Generated and persisted new mesh site identity");
                stored
            }
        };

        if let Some(requested) = requested_site_id.filter(|r| *r != site_id) {
            return Err(Error::InvalidConfig(format!(
                "Configured site ID {} does not match the persisted mesh identity {}; \
                 peers have pinned the persisted identity's key, so refusing to \
                 silently change it (leave site_id unset to use the persisted one)",
                requested, site_id
            )));
        }

        Ok((site_id, SigningKey::from_bytes(&seed)))
    }

    /// This site's (persisted) ID.
    pub fn site_id(&self) -> SiteId {
        self.site_id
    }

    /// This site's (persisted) announcement verifying key.
    pub fn public_key(&self) -> VerifyingKey {
        self.verifying_key
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

                // Discover endpoints from system interfaces
                let discovered_endpoints = discover_endpoints().await;

                // Create announcement
                let announcement = SiteAnnouncement {
                    site_id,
                    site_name: site_name.clone(),
                    public_key: signing_key.verifying_key().to_bytes().to_vec(),
                    endpoints: discovered_endpoints,
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
                        let announcement: SiteAnnouncement = match bincode::deserialize(&buf[..len])
                        {
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
                        let admitted = match Self::admit_announcement(
                            &db,
                            &known_sites,
                            &announcement,
                            SystemTime::now(),
                        )
                        .await
                        {
                            Ok(admitted) => admitted,
                            Err(Error::Database(e)) => {
                                error!(
                                    "Failed to store site {} from announcement: {}",
                                    announcement.site_id, e
                                );
                                continue;
                            }
                            Err(e) => {
                                warn!(
                                    site_id = %announcement.site_id,
                                    site_name = %announcement.site_name,
                                    "Rejected announcement: {}",
                                    e
                                );
                                continue;
                            }
                        };
                        let site = admitted.site;

                        debug!("Site {} registered in mesh", site.id);

                        if admitted.rekeyed {
                            info!(
                                "Site {} was re-keyed after its pin was cleared; replacing WireGuard peer",
                                site.id
                            );
                            if let Err(e) = peering_manager.remove_peer(&site.id).await {
                                warn!("Failed to remove old WireGuard peer for {}: {}", site.id, e);
                            }
                        }

                        // Establish VPN tunnel if this site has no peer yet
                        if admitted.needs_peering {
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

                    if let Some(info) = sites.remove(&site_id) {
                        if let Err(e) = db
                            .mark_site_inactive(&site_id, &info.site.public_key, now)
                            .await
                        {
                            error!("Failed to update site status: {}", e);
                        }
                    }
                }
            }

            info!("Site timeout checker stopped");
        });

        Ok(task)
    }

    /// Admit one received announcement: freshness/replay check, signature
    /// check, then trust-on-first-use key pinning, and finally record it in
    /// the database and `known_sites`.
    ///
    /// Key pinning: the first public key stored for a site ID is pinned in
    /// `sdwan_sites`. A validly signed announcement for that site ID under a
    /// *different* key is rejected here -- the DB row, `known_sites` and the
    /// WireGuard peering are all left untouched. Without this, anyone on the
    /// multicast segment could sign an announcement with their own key for an
    /// existing site ID and hijack it (signatures only prove possession of
    /// *some* key, not the site's key). To re-key a site legitimately, delete
    /// its row (`Database::delete_site`) so the next announcement re-pins.
    async fn admit_announcement(
        db: &Database,
        known_sites: &RwLock<HashMap<SiteId, SiteInfo>>,
        announcement: &SiteAnnouncement,
        now: SystemTime,
    ) -> Result<AdmittedAnnouncement> {
        // Reject stale / future-dated / replayed announcements before
        // spending time on signature verification.
        let last_accepted = known_sites
            .read()
            .await
            .get(&announcement.site_id)
            .map(|info| info.announced_at);
        Self::check_announcement_freshness(announcement.timestamp, now, last_accepted)?;

        Self::verify_announcement(announcement)?;

        let site = Site {
            id: announcement.site_id,
            name: announcement.site_name.clone(),
            public_key: announcement.public_key.clone(),
            endpoints: announcement.endpoints.clone(),
            created_at: announcement.timestamp,
            last_seen: now,
            status: SiteStatus::Active,
        };

        // Pin check and write are one atomic statement.
        if !db.upsert_site_pinned(&site).await? {
            return Err(Error::AuthenticationFailed(format!(
                "public key for site {} does not match the key pinned on first use; \
                 ignoring announcement (delete the site record to re-key it)",
                site.id
            )));
        }

        info!(
            site_id = %site.id,
            site_name = %site.name,
            "Accepted verified site announcement"
        );

        let previous = known_sites.write().await.insert(
            site.id,
            SiteInfo {
                site: site.clone(),
                last_announcement: now,
                announced_at: announcement.timestamp,
            },
        );
        let rekeyed = previous
            .as_ref()
            .is_some_and(|p| p.site.public_key != site.public_key);
        let needs_peering = previous.is_none() || rekeyed;

        Ok(AdmittedAnnouncement {
            site,
            needs_peering,
            rekeyed,
        })
    }

    /// Check that an announcement's (signed) timestamp is fresh and strictly
    /// newer than the last one accepted from the same site.
    ///
    /// The window bounds replay of captured packets; the monotonic check stops
    /// replay of a still-in-window packet against a site we already track.
    /// A site whose clock steps backwards is rejected only until it times out
    /// of `known_sites` (`SITE_TIMEOUT`), after which it is accepted again.
    fn check_announcement_freshness(
        timestamp: SystemTime,
        now: SystemTime,
        last_accepted: Option<SystemTime>,
    ) -> Result<()> {
        match now.duration_since(timestamp) {
            Ok(age) if age > MAX_ANNOUNCEMENT_AGE => {
                return Err(Error::AuthenticationFailed(format!(
                    "Stale announcement: {}s old (max {}s)",
                    age.as_secs(),
                    MAX_ANNOUNCEMENT_AGE.as_secs()
                )));
            }
            Ok(_) => {}
            Err(e) if e.duration() > MAX_ANNOUNCEMENT_CLOCK_SKEW => {
                return Err(Error::AuthenticationFailed(format!(
                    "Announcement timestamp {}s in the future (max skew {}s)",
                    e.duration().as_secs(),
                    MAX_ANNOUNCEMENT_CLOCK_SKEW.as_secs()
                )));
            }
            Err(_) => {}
        }

        if let Some(last) = last_accepted {
            if timestamp <= last {
                return Err(Error::AuthenticationFailed(
                    "Replayed or out-of-order announcement (timestamp not newer than last accepted)"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Verify announcement signature
    fn verify_announcement(announcement: &SiteAnnouncement) -> Result<()> {
        // Extract public key. Announcements arrive over unauthenticated
        // multicast, so the length must be checked *before* touching the
        // bytes: slicing `[..32]` first panicked on any shorter key, and since
        // this runs inside the spawned auto-peering task, one malformed packet
        // from anyone on the segment permanently killed mesh auto-peering.
        // Require the exact length too -- a longer key would otherwise verify
        // against its first 32 bytes and then be stored/peered as-is.
        let public_key_bytes: [u8; 32] =
            announcement.public_key.as_slice().try_into().map_err(|_| {
                Error::AuthenticationFailed(format!(
                    "Invalid public key length: {} (expected 32)",
                    announcement.public_key.len()
                ))
            })?;

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
        .map_err(|e| Error::Network(format!("Serialization failed: {}", e)))?;

        // Extract signature
        let signature_bytes: [u8; 64] =
            announcement.signature.as_slice().try_into().map_err(|_| {
                Error::AuthenticationFailed(format!(
                    "Invalid signature length: {} (expected 64)",
                    announcement.signature.len()
                ))
            })?;

        let signature = Signature::from_bytes(&signature_bytes);

        // Verify signature
        verifying_key
            .verify(&announcement_bytes, &signature)
            .map_err(|e| {
                Error::AuthenticationFailed(format!("Signature verification failed: {}", e))
            })?;

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
        let manager = MeshManager::new(None, "test-site".to_string(), db)
            .await
            .unwrap();

        assert!(manager.start().await.is_ok());
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(manager.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_announcement_verification() {
        let mut secret_bytes = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
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

    fn signed_test_announcement() -> SiteAnnouncement {
        let mut secret_bytes = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let mut announcement = SiteAnnouncement {
            site_id: SiteId::generate(),
            site_name: "test".to_string(),
            public_key: signing_key.verifying_key().to_bytes().to_vec(),
            endpoints: Vec::new(),
            capabilities: SiteCapabilities::default(),
            timestamp: SystemTime::now(),
            signature: Vec::new(),
        };
        let announcement_bytes = bincode::serialize(&(
            &announcement.site_id,
            &announcement.site_name,
            &announcement.public_key,
            &announcement.endpoints,
            &announcement.capabilities,
            &announcement.timestamp,
        ))
        .unwrap();
        announcement.signature = signing_key.sign(&announcement_bytes).to_bytes().to_vec();
        announcement
    }

    /// Announcements come from unauthenticated multicast: malformed key or
    /// signature lengths must be rejected with an error, never panic (a panic
    /// here kills the auto-peering task for good).
    #[test]
    fn test_announcement_with_bad_lengths_is_rejected_not_panicking() {
        let good = signed_test_announcement();
        assert!(MeshManager::verify_announcement(&good).is_ok());

        for len in [0usize, 1, 31, 33, 64] {
            let mut a = good.clone();
            a.public_key.resize(len, 0);
            assert!(
                MeshManager::verify_announcement(&a).is_err(),
                "public key of length {len} must be rejected"
            );
        }
        for len in [0usize, 1, 63, 65] {
            let mut a = good.clone();
            a.signature.resize(len, 0);
            assert!(
                MeshManager::verify_announcement(&a).is_err(),
                "signature of length {len} must be rejected"
            );
        }
    }

    /// Signed announcements carry no nonce: old, far-future, or repeated
    /// timestamps must be rejected so captured packets can't be replayed.
    #[test]
    fn test_announcement_freshness_rejects_stale_future_and_replay() {
        let now = SystemTime::now();
        let check = MeshManager::check_announcement_freshness;

        // Fresh, first sighting.
        assert!(check(now, now, None).is_ok());
        assert!(check(now - Duration::from_secs(10), now, None).is_ok());
        // Modest clock skew either way is tolerated.
        assert!(check(now + Duration::from_secs(30), now, None).is_ok());
        assert!(check(now - MAX_ANNOUNCEMENT_AGE, now, None).is_ok());

        // Too old / too far in the future.
        let stale = now - MAX_ANNOUNCEMENT_AGE - Duration::from_secs(1);
        assert!(check(stale, now, None).is_err());
        let future = now + MAX_ANNOUNCEMENT_CLOCK_SKEW + Duration::from_secs(1);
        assert!(check(future, now, None).is_err());

        // Replay (same timestamp) and out-of-order (older) for a known site.
        let last = now - Duration::from_secs(30);
        assert!(check(last, now, Some(last)).is_err());
        assert!(check(last - Duration::from_secs(1), now, Some(last)).is_err());
        // Strictly newer is accepted.
        assert!(check(last + Duration::from_secs(30), now, Some(last)).is_ok());
    }

    #[tokio::test]
    async fn test_site_list() {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let manager = MeshManager::new(None, "test-site".to_string(), db)
            .await
            .unwrap();

        let sites = manager.list_known_sites().await;
        assert_eq!(sites.len(), 0);
    }

    fn test_signing_key() -> SigningKey {
        use rand::RngCore;
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        SigningKey::from_bytes(&secret_bytes)
    }

    fn announcement_signed_by(
        key: &SigningKey,
        site_id: SiteId,
        timestamp: SystemTime,
    ) -> SiteAnnouncement {
        let mut announcement = SiteAnnouncement {
            site_id,
            site_name: "remote".to_string(),
            public_key: key.verifying_key().to_bytes().to_vec(),
            endpoints: Vec::new(),
            capabilities: SiteCapabilities::default(),
            timestamp,
            signature: Vec::new(),
        };
        let announcement_bytes = bincode::serialize(&(
            &announcement.site_id,
            &announcement.site_name,
            &announcement.public_key,
            &announcement.endpoints,
            &announcement.capabilities,
            &announcement.timestamp,
        ))
        .unwrap();
        announcement.signature = key.sign(&announcement_bytes).to_bytes().to_vec();
        announcement
    }

    /// The local signing key and site ID must survive a restart: peers pin
    /// the first key they see, so a fresh key per start would lock us out.
    #[tokio::test]
    async fn test_local_identity_persists_across_restart() {
        let path = std::env::temp_dir().join(format!(
            "patronus-mesh-identity-{}.db",
            uuid::Uuid::new_v4()
        ));
        let path_str = path.to_str().unwrap().to_string();

        let (site_id, public_key) = {
            let db = Arc::new(Database::new(&path_str).await.unwrap());
            let manager = MeshManager::new(None, "a".to_string(), db.clone())
                .await
                .unwrap();
            let identity = (manager.site_id(), manager.public_key());
            drop(manager);
            db.pool().close().await;
            identity
        };

        // The DB now holds a private key: it must be owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o077,
                0,
                "database must not be group/world accessible"
            );
        }

        // "Restart": reopen the same file.
        let db = Arc::new(Database::new(&path_str).await.unwrap());
        let reloaded = MeshManager::new(None, "a".to_string(), db.clone())
            .await
            .unwrap();
        assert_eq!(reloaded.site_id(), site_id);
        assert_eq!(reloaded.public_key(), public_key);
        assert_eq!(
            reloaded.signing_key.to_bytes(),
            MeshManager::new(Some(site_id), "a".to_string(), db.clone())
                .await
                .unwrap()
                .signing_key
                .to_bytes(),
            "an explicitly configured matching site ID reuses the persisted key"
        );

        // A configured site ID that contradicts the persisted identity is
        // refused rather than silently changing identity.
        assert!(
            MeshManager::new(Some(SiteId::generate()), "a".to_string(), db.clone())
                .await
                .is_err()
        );

        db.pool().close().await;
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", path_str, suffix));
        }
    }

    /// A configured site ID seeds a fresh database's identity.
    #[tokio::test]
    async fn test_configured_site_id_seeds_new_identity() {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let wanted = SiteId::generate();
        let manager = MeshManager::new(Some(wanted), "a".to_string(), db.clone())
            .await
            .unwrap();
        assert_eq!(manager.site_id(), wanted);
        let (stored_id, stored_key) = db.get_local_identity().await.unwrap().unwrap();
        assert_eq!(stored_id, wanted);
        assert_eq!(stored_key, manager.signing_key.to_bytes());
    }

    /// Trust-on-first-use: the first key seen for a site ID is pinned; the
    /// same key keeps being accepted; a different (validly self-signed) key
    /// for that site ID is rejected without touching the DB or known_sites.
    #[tokio::test]
    async fn test_tofu_pins_first_key_and_rejects_different_key() {
        let db = Database::new(":memory:").await.unwrap();
        let known_sites = RwLock::new(HashMap::new());
        let site_id = SiteId::generate();
        let real_key = test_signing_key();
        let attacker_key = test_signing_key();
        let now = SystemTime::now();

        // First sighting: accepted, pinned, peering requested.
        let first = announcement_signed_by(&real_key, site_id, now - Duration::from_secs(30));
        let admitted = MeshManager::admit_announcement(&db, &known_sites, &first, now)
            .await
            .expect("first key must be accepted");
        assert!(admitted.needs_peering);
        assert!(!admitted.rekeyed);
        let pinned = real_key.verifying_key().to_bytes().to_vec();
        assert_eq!(
            db.get_site(&site_id).await.unwrap().unwrap().public_key,
            pinned
        );

        // Same key again: accepted, no re-peering.
        let again = announcement_signed_by(&real_key, site_id, now - Duration::from_secs(20));
        let admitted = MeshManager::admit_announcement(&db, &known_sites, &again, now)
            .await
            .expect("same key must be accepted again");
        assert!(!admitted.needs_peering);

        // Forged announcement for the same site ID under a different key:
        // validly signed (by the attacker's key), fresh, but rejected.
        let forged = announcement_signed_by(&attacker_key, site_id, now - Duration::from_secs(10));
        assert!(MeshManager::verify_announcement(&forged).is_ok());
        let err = match MeshManager::admit_announcement(&db, &known_sites, &forged, now).await {
            Ok(_) => panic!("different key for a pinned site ID must be rejected"),
            Err(e) => e,
        };
        assert!(matches!(err, Error::AuthenticationFailed(_)));
        assert_eq!(
            db.get_site(&site_id).await.unwrap().unwrap().public_key,
            pinned,
            "rejected announcement must not overwrite the pinned key"
        );
        assert_eq!(
            known_sites
                .read()
                .await
                .get(&site_id)
                .unwrap()
                .site
                .public_key,
            pinned
        );

        // The pin lives in the DB, so it also holds after the site has left
        // known_sites (timeout or restart).
        known_sites.write().await.clear();
        let forged_later =
            announcement_signed_by(&attacker_key, site_id, now - Duration::from_secs(5));
        assert!(
            MeshManager::admit_announcement(&db, &known_sites, &forged_later, now)
                .await
                .is_err()
        );
        assert!(known_sites.read().await.is_empty());

        // ...while the real key is still accepted (and re-peered).
        let real_later = announcement_signed_by(&real_key, site_id, now);
        let admitted = MeshManager::admit_announcement(&db, &known_sites, &real_later, now)
            .await
            .expect("pinned key must still be accepted");
        assert!(admitted.needs_peering);
    }

    /// Timing a site out must not re-insert a row an operator deleted (to
    /// re-key it) or touch a row pinned to another key.
    #[tokio::test]
    async fn test_mark_site_inactive_never_repins() {
        let db = Database::new(":memory:").await.unwrap();
        let known_sites = RwLock::new(HashMap::new());
        let site_id = SiteId::generate();
        let key = test_signing_key();
        let now = SystemTime::now();

        let a = announcement_signed_by(&key, site_id, now);
        MeshManager::admit_announcement(&db, &known_sites, &a, now)
            .await
            .unwrap();
        let pinned = key.verifying_key().to_bytes().to_vec();

        db.mark_site_inactive(&site_id, &pinned, now).await.unwrap();
        assert_eq!(
            db.get_site(&site_id).await.unwrap().unwrap().status,
            SiteStatus::Inactive
        );

        db.delete_site(&site_id).await.unwrap();
        db.mark_site_inactive(&site_id, &pinned, now).await.unwrap();
        assert!(db.get_site(&site_id).await.unwrap().is_none());
    }
}
