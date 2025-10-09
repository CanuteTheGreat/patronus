//! Web routes module
//!
//! Organizes all HTTP routes into logical modules:
//! - pages: HTML page handlers (renders Askama templates)
//! - api: REST API endpoints (returns JSON)

pub mod pages;
pub mod api;

use axum::{
    Router,
    routing::{get, post, put, delete},
};
use tower_http::services::ServeDir;

use crate::state::AppState;

/// Build the complete application router
pub fn build_router(state: AppState) -> Router {
    Router::new()
        // Page routes (HTML)
        .route("/", get(pages::dashboard))
        .route("/firewall", get(pages::firewall))
        .route("/vpn", get(pages::vpn))
        .route("/network", get(pages::network))
        .route("/monitoring", get(pages::monitoring))
        .route("/system", get(pages::system))

        // API routes (JSON)
        .nest("/api", api_routes())

        // Static files
        .nest_service("/static", ServeDir::new("static"))

        // Attach application state
        .with_state(state)
}

/// Build API routes
fn api_routes() -> Router<AppState> {
    Router::new()
        // Status endpoint
        .route("/status", get(api::status::system_status))

        // Firewall API
        .route("/firewall/rules", get(api::firewall::list_rules).post(api::firewall::add_rule))
        .route("/firewall/rules/:id", get(api::firewall::get_rule).put(api::firewall::update_rule).delete(api::firewall::delete_rule))
        .route("/firewall/rules/apply", post(api::firewall::apply_rules))
        .route("/firewall/nat", get(api::firewall::list_nat_rules).post(api::firewall::add_nat_rule))
        .route("/firewall/nat/:id", delete(api::firewall::delete_nat_rule))

        // VPN API
        .route("/vpn/wireguard/peers", get(api::vpn::list_wg_peers).post(api::vpn::add_wg_peer))
        .route("/vpn/wireguard/peers/:id", delete(api::vpn::delete_wg_peer))
        .route("/vpn/wireguard/config/:id", get(api::vpn::get_wg_config))
        .route("/vpn/openvpn/tunnels", get(api::vpn::list_ovpn_tunnels))
        .route("/vpn/ipsec/tunnels", get(api::vpn::list_ipsec_tunnels))

        // Network API
        .route("/network/interfaces", get(api::network::list_interfaces))
        .route("/network/interfaces/:name", put(api::network::update_interface))
        .route("/network/interfaces/:name/up", post(api::network::interface_up))
        .route("/network/interfaces/:name/down", post(api::network::interface_down))
        .route("/network/dhcp/pools", get(api::network::list_dhcp_pools))
        .route("/network/dhcp/leases", get(api::network::list_dhcp_leases))
        .route("/network/dns/records", get(api::network::list_dns_records))
        .route("/network/routes", get(api::network::list_routes))

        // System API
        .route("/system/users", get(api::system::list_users))
        .route("/system/backups", get(api::system::list_backups).post(api::system::create_backup))
        .route("/system/updates", get(api::system::list_updates))
        .route("/system/services", get(api::system::list_services))
        .route("/system/services/:name/start", post(api::system::start_service))
        .route("/system/services/:name/stop", post(api::system::stop_service))
        .route("/system/services/:name/restart", post(api::system::restart_service))
}
