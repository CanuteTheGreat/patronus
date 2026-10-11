//! Captive Portal Core
//!
//! Main captive portal engine with HTTP interception, authentication,
//! and client management.

use crate::{
    auth::{AuthMethod, AuthProvider},
    bandwidth::BandwidthLimiter,
    sessions::SessionManager,
    vouchers::VoucherManager,
};
use axum::{
    extract::{Form, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

/// Captive portal configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalConfig {
    pub enabled: bool,
    pub interface: String,
    pub listen_addr: SocketAddr,
    pub portal_url: String, // https://portal.example.com

    // Branding
    pub portal_title: String,
    pub company_name: String,
    pub logo_url: Option<String>,
    pub background_image: Option<String>,
    pub custom_css: Option<String>,

    // Authentication
    pub auth_methods: Vec<AuthMethod>,
    pub require_terms: bool,
    pub terms_url: Option<String>,

    // Session limits
    pub session_timeout_minutes: u32,
    pub max_sessions_per_mac: u32,
    pub idle_timeout_minutes: u32,

    // Bandwidth limits
    pub download_limit_kbps: Option<u64>,
    pub upload_limit_kbps: Option<u64>,
    pub total_quota_mb: Option<u64>,

    // Access control
    pub allowed_domains: Vec<String>, // Whitelist before auth
    pub blocked_domains: Vec<String>,

    // Voucher settings
    pub enable_vouchers: bool,
    pub voucher_validity_hours: u32,

    // Social login
    pub enable_social_login: bool,
    pub facebook_app_id: Option<String>,
    pub google_client_id: Option<String>,

    // Legal
    pub enable_logging: bool,
    pub data_retention_days: u32,
}

/// Client authentication request
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: Option<String>,
    pub password: Option<String>,
    pub voucher: Option<String>,
    pub accept_terms: Option<bool>,
    pub redirect_url: Option<String>,
    pub mac_address: String,
    pub ip_address: String,
}

/// Portal state
pub struct PortalState {
    config: PortalConfig,
    sessions: Arc<RwLock<SessionManager>>,
    vouchers: Arc<RwLock<VoucherManager>>,
    bandwidth: Arc<BandwidthLimiter>,
    #[allow(dead_code)]
    auth_providers: HashMap<String, Box<dyn AuthProvider>>,
}

pub struct CaptivePortal {
    state: Arc<PortalState>,
}

impl CaptivePortal {
    pub fn new(config: PortalConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let sessions = Arc::new(RwLock::new(SessionManager::new()));
        let vouchers = Arc::new(RwLock::new(VoucherManager::new()));
        let bandwidth = Arc::new(BandwidthLimiter::new());

        let state = Arc::new(PortalState {
            config,
            sessions,
            vouchers,
            bandwidth,
            auth_providers: HashMap::new(),
        });

        Ok(Self { state })
    }

    /// Start the captive portal HTTP server
    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error>> {
        let app = Router::new()
            // Portal pages
            .route("/", get(portal_index))
            .route("/login", get(login_page).post(handle_login))
            .route("/logout", post(handle_logout))
            .route("/status", get(status_page))
            .route("/terms", get(terms_page))
            // Voucher management
            .route("/voucher/redeem", post(redeem_voucher))
            .route("/voucher/check", get(check_voucher))
            // Social login callbacks
            .route("/auth/facebook/callback", get(facebook_callback))
            .route("/auth/google/callback", get(google_callback))
            // Admin API
            .route("/api/sessions", get(list_sessions))
            .route("/api/sessions/:id/terminate", post(terminate_session))
            .route("/api/vouchers/generate", post(generate_vouchers))
            // Assets
            .route("/static/*path", get(serve_static))
            .with_state(self.state.clone());

        let addr = self.state.config.listen_addr;
        tracing::info!("Captive portal listening on {}", addr);

        // Set up firewall rules for captive portal
        self.setup_firewall_rules().await?;

        // Start session cleanup background task
        self.start_session_cleanup().await;

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;

        Ok(())
    }

    /// Configure firewall rules for captive portal
    async fn setup_firewall_rules(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create nftables rules to redirect HTTP/HTTPS to portal
        let nft_rules = format!(
            r#"
table inet captive_portal {{

    # Authenticated clients (bypass portal)
    set authenticated_clients {{
        type ether_addr
        flags timeout
    }}

    # Whitelisted domains (allowed before auth)
    set whitelist_domains {{
        type ipv4_addr
        elements = {{
            # DNS servers
            8.8.8.8,
            8.8.4.4,
            1.1.1.1,
        }}
    }}

    chain prerouting {{
        type nat hook prerouting priority -100

        # Skip authenticated clients
        ether saddr @authenticated_clients accept

        # Allow DNS
        udp dport 53 accept
        tcp dport 53 accept

        # Allow whitelisted IPs
        ip daddr @whitelist_domains accept

        # Redirect HTTP to portal
        iifname "{}" tcp dport 80 redirect to :{}

        # Drop HTTPS (can't redirect due to TLS)
        iifname "{}" tcp dport 443 drop
    }}

    chain forward {{
        type filter hook forward priority 0

        # Allow authenticated clients
        ether saddr @authenticated_clients accept

        # Drop unauthenticated traffic
        iifname "{}" drop
    }}
}}
"#,
            self.state.config.interface,
            self.state.config.listen_addr.port(),
            self.state.config.interface,
            self.state.config.interface,
        );

        // Apply rules using nft command
        tokio::process::Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()?
            .stdin
            .as_mut()
            .unwrap()
            .write_all(nft_rules.as_bytes())
            .await?;

        Ok(())
    }

    /// Background task to clean up expired sessions
    async fn start_session_cleanup(&self) {
        let sessions = self.state.sessions.clone();
        let timeout = self.state.config.session_timeout_minutes;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

            loop {
                interval.tick().await;

                let mut sessions = sessions.write().await;
                sessions.cleanup_expired(timeout).await;
            }
        });
    }
}

// HTTP Handlers

async fn portal_index(
    State(state): State<Arc<PortalState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Html<String> {
    let redirect_url = params
        .get("redirect")
        .cloned()
        .unwrap_or_else(|| "http://www.google.com".to_string());

    let html = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }}
        .container {{
            background: white;
            border-radius: 10px;
            padding: 40px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 400px;
            width: 100%;
        }}
        .logo {{
            text-align: center;
            margin-bottom: 30px;
        }}
        h1 {{
            color: #333;
            text-align: center;
            margin-bottom: 10px;
        }}
        .subtitle {{
            color: #666;
            text-align: center;
            margin-bottom: 30px;
        }}
        .btn {{
            display: block;
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: all 0.3s;
        }}
        .btn-primary {{
            background: #667eea;
            color: white;
        }}
        .btn-primary:hover {{
            background: #5568d3;
        }}
        .btn-secondary {{
            background: #f0f0f0;
            color: #333;
        }}
        .divider {{
            text-align: center;
            margin: 20px 0;
            color: #999;
        }}
        .social-login {{
            display: flex;
            gap: 10px;
        }}
        .social-btn {{
            flex: 1;
            padding: 12px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
        }}
        .facebook {{
            background: #1877f2;
            color: white;
        }}
        .google {{
            background: #fff;
            color: #333;
            border: 1px solid #ddd;
        }}
        {}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>🛡️ {}</h1>
        </div>
        <h1>Welcome!</h1>
        <p class="subtitle">Please log in to access the internet</p>

        <form action="/login" method="POST">
            <input type="hidden" name="redirect_url" value="{}">

            {}

            {}

            <button type="submit" class="btn btn-primary">Connect</button>
        </form>

        {}

        <p style="text-align: center; margin-top: 20px; font-size: 12px; color: #999;">
            Powered by Patronus Firewall
        </p>
    </div>
</body>
</html>
"#,
        state.config.portal_title,
        state.config.custom_css.as_deref().unwrap_or(""),
        state.config.company_name,
        redirect_url,
        if state
            .config
            .auth_methods
            .contains(&AuthMethod::UsernamePassword)
        {
            r#"
            <input type="text" name="username" placeholder="Username" class="btn btn-secondary" required>
            <input type="password" name="password" placeholder="Password" class="btn btn-secondary" required>
            "#
        } else {
            ""
        },
        if state.config.enable_vouchers {
            r#"
            <div class="divider">- OR -</div>
            <input type="text" name="voucher" placeholder="Enter voucher code" class="btn btn-secondary">
            "#
        } else {
            ""
        },
        if state.config.enable_social_login {
            r#"
            <div class="divider">- OR -</div>
            <div class="social-login">
                <button type="button" class="social-btn facebook" onclick="loginFacebook()">Facebook</button>
                <button type="button" class="social-btn google" onclick="loginGoogle()">Google</button>
            </div>
            "#
        } else {
            ""
        }
    );

    Html(html)
}

async fn login_page() -> Html<&'static str> {
    Html("<h1>Login Page</h1>")
}

/// Validate that a string is a plausible MAC address (`AA:BB:CC:DD:EE:FF` or
/// `AA-BB-CC-DD-EE-FF`, case-insensitive). `mac_address` values on this module's
/// endpoints come straight off unauthenticated/placeholder-authenticated HTTP form
/// POSTs and are interpolated directly into `nft add/delete element ... { <value> }`
/// command-line arguments. `nft` parses its own argument list as a sequence of
/// statements (it does not need a shell to chain commands with `;`), so an
/// unvalidated value there is an nftables ruleset-injection vector, not just a
/// cosmetic parsing concern. Reject anything that isn't a well-formed MAC before it
/// ever reaches session bookkeeping or a `Command`.
fn is_valid_mac_address(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 17 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        if i % 3 == 2 {
            if *b != b':' && *b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

async fn handle_login(
    State(state): State<Arc<PortalState>>,
    Form(login): Form<LoginRequest>,
) -> Response {
    // Authenticate user
    let authenticated = if let Some(voucher) = &login.voucher {
        // Voucher authentication
        let mut vouchers = state.vouchers.write().await;
        vouchers.redeem(voucher).await.is_ok()
    } else if let (Some(_username), Some(_password)) = (&login.username, &login.password) {
        // Username/password authentication
        // Check against configured auth providers
        true // Placeholder
    } else {
        false
    };

    if authenticated {
        // Validate client-supplied IP address before using it: `login.ip_address` comes
        // straight off an unauthenticated HTTP form POST (any device on the captive-portal
        // network can submit arbitrary garbage here), so a bare `.parse().unwrap()` let any
        // client crash this request with a malformed value instead of just failing the login.
        let ip_address = match login.ip_address.parse() {
            Ok(ip) => ip,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "Invalid ip_address in login request",
                )
                    .into_response();
            }
        };

        if !is_valid_mac_address(&login.mac_address) {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid mac_address in login request",
            )
                .into_response();
        }

        // Create session
        let mut sessions = state.sessions.write().await;
        let _session = sessions
            .create_session(login.mac_address.clone(), ip_address)
            .await;

        // Add MAC to nftables authenticated set
        let _ = tokio::process::Command::new("nft")
            .args([
                "add",
                "element",
                "inet",
                "captive_portal",
                "authenticated_clients",
                &format!("{{ {} timeout 1h }}", login.mac_address),
            ])
            .output()
            .await;

        // Apply bandwidth limits if configured
        if let Some(download_limit) = state.config.download_limit_kbps {
            state
                .bandwidth
                .set_limit(
                    &login.mac_address,
                    download_limit,
                    state.config.upload_limit_kbps.unwrap_or(download_limit),
                )
                .await;
        }

        // Redirect to original URL
        let redirect_url = login
            .redirect_url
            .unwrap_or_else(|| "http://www.google.com".to_string());
        Redirect::to(&redirect_url).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "Authentication failed").into_response()
    }
}

async fn handle_logout(
    State(state): State<Arc<PortalState>>,
    Form(params): Form<HashMap<String, String>>,
) -> Response {
    if let Some(mac) = params.get("mac_address") {
        if !is_valid_mac_address(mac) {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid mac_address in logout request",
            )
                .into_response();
        }

        // Remove session
        let mut sessions = state.sessions.write().await;
        sessions.terminate_by_mac(mac).await;

        // Remove from nftables
        let _ = tokio::process::Command::new("nft")
            .args([
                "delete",
                "element",
                "inet",
                "captive_portal",
                "authenticated_clients",
                &format!("{{ {} }}", mac),
            ])
            .output()
            .await;

        // Remove bandwidth limits
        state.bandwidth.remove_limit(mac).await;
    }

    Redirect::to("/").into_response()
}

async fn status_page() -> Html<&'static str> {
    Html("<h1>Connection Status</h1>")
}

async fn terms_page(State(state): State<Arc<PortalState>>) -> Html<String> {
    let html = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Terms of Service</title>
</head>
<body>
    <h1>Terms of Service</h1>
    <p>Terms and conditions for {} guest WiFi access...</p>
</body>
</html>
"#,
        state.config.company_name
    );

    Html(html)
}

async fn redeem_voucher() -> impl IntoResponse {
    (StatusCode::OK, "Voucher redeemed")
}

async fn check_voucher() -> impl IntoResponse {
    (StatusCode::OK, "Voucher valid")
}

async fn facebook_callback() -> impl IntoResponse {
    Redirect::to("/")
}

async fn google_callback() -> impl IntoResponse {
    Redirect::to("/")
}

async fn list_sessions() -> impl IntoResponse {
    (StatusCode::OK, "[]")
}

async fn terminate_session() -> impl IntoResponse {
    (StatusCode::OK, "Session terminated")
}

async fn generate_vouchers() -> impl IntoResponse {
    (StatusCode::OK, "Vouchers generated")
}

async fn serve_static() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "Not found")
}

impl Default for PortalConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: "wlan0".to_string(),
            listen_addr: "0.0.0.0:8888".parse().unwrap(),
            portal_url: "http://portal.local".to_string(),
            portal_title: "Guest WiFi Portal".to_string(),
            company_name: "My Company".to_string(),
            logo_url: None,
            background_image: None,
            custom_css: None,
            auth_methods: vec![AuthMethod::Voucher],
            require_terms: true,
            terms_url: None,
            session_timeout_minutes: 240, // 4 hours
            max_sessions_per_mac: 1,
            idle_timeout_minutes: 30,
            download_limit_kbps: Some(10000), // 10 Mbps
            upload_limit_kbps: Some(5000),    // 5 Mbps
            total_quota_mb: None,
            allowed_domains: vec![],
            blocked_domains: vec![],
            enable_vouchers: true,
            voucher_validity_hours: 24,
            enable_social_login: false,
            facebook_app_id: None,
            google_client_id: None,
            enable_logging: true,
            data_retention_days: 90,
        }
    }
}

#[cfg(test)]
mod qa_regression_tests {
    //! Regression tests added by agent-driven QA (2026-10-10) for commit
    //! 6f33d1325ec96b2a88b9fca75146a8a8b7574eba: handle_login() must not panic
    //! on a malformed client-supplied ip_address, it must return 400.
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    fn test_state() -> Arc<PortalState> {
        Arc::new(PortalState {
            config: PortalConfig::default(),
            sessions: Arc::new(RwLock::new(SessionManager::new())),
            vouchers: Arc::new(RwLock::new(VoucherManager::new())),
            bandwidth: Arc::new(BandwidthLimiter::new()),
            auth_providers: HashMap::new(),
        })
    }

    fn router(state: Arc<PortalState>) -> Router {
        Router::new()
            .route("/login", post(handle_login))
            .with_state(state)
    }

    #[tokio::test]
    async fn malformed_ip_address_returns_400_not_panic() {
        let state = test_state();
        // Force the authenticated branch via username/password (placeholder auth
        // returns true for any username+password per current handle_login code),
        // which keeps this test independent of the voucher-manager API.
        let body =
            "username=alice&password=whatever&mac_address=AA:BB:CC:DD:EE:FF&ip_address=not-an-ip";
        let req = Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let resp = router(state).oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "malformed ip_address must yield 400, not a panic/500"
        );
    }

    #[tokio::test]
    async fn valid_ip_address_creates_session_successfully() {
        let state = test_state();
        let body = "username=alice&password=whatever&mac_address=AA:BB:CC:DD:EE:FF&ip_address=192.168.1.50";
        let req = Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let resp = router(state.clone()).oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "a valid ip_address must not be rejected"
        );
        assert_ne!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let sessions = state.sessions.read().await;
        assert!(
            sessions.get_by_mac("AA:BB:CC:DD:EE:FF").await.is_some(),
            "a session should have been created for the authenticated client"
        );
    }

    #[test]
    fn is_valid_mac_address_accepts_well_formed_macs() {
        assert!(is_valid_mac_address("AA:BB:CC:DD:EE:FF"));
        assert!(is_valid_mac_address("aa:bb:cc:dd:ee:ff"));
        assert!(is_valid_mac_address("AA-BB-CC-DD-EE-FF"));
    }

    #[test]
    fn is_valid_mac_address_rejects_nftables_injection_payloads() {
        // A real payload that would otherwise be spliced straight into
        // `nft add element inet captive_portal authenticated_clients { <value> timeout 1h }`
        // as a single command-line argument, letting an unauthenticated/placeholder-
        // authenticated client inject arbitrary additional nft statements.
        assert!(!is_valid_mac_address(
            "AA:BB:CC:DD:EE:FF }; add rule inet captive_portal forward accept #"
        ));
        assert!(!is_valid_mac_address(""));
        assert!(!is_valid_mac_address("not-a-mac"));
        assert!(!is_valid_mac_address("AA:BB:CC:DD:EE:FF:00")); // too long
        assert!(!is_valid_mac_address("AA:BB:CC:DD:EE:FG")); // non-hex digit
    }

    #[tokio::test]
    async fn malformed_mac_address_returns_400_not_injected_into_nft() {
        let state = test_state();
        let body = "username=alice&password=whatever&\
                     mac_address=AA:BB:CC:DD:EE:FF%20%7D%3B%20add%20rule%20inet%20captive_portal%20forward%20accept&\
                     ip_address=192.168.1.50";
        let req = Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let resp = router(state).oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "a mac_address containing nft syntax must be rejected, not executed"
        );
    }
}
