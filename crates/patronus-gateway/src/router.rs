//! API Router

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub path: String,
    pub methods: Vec<String>,
    pub backend: String,
    pub requires_auth: bool,
    pub rate_limit: Option<u32>,
}

pub struct ApiRouter {
    routes: HashMap<String, Route>,
}

impl ApiRouter {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    pub fn add_route(&mut self, route: Route) {
        tracing::info!("Adding route: {} -> {}", route.path, route.backend);
        self.routes.insert(route.path.clone(), route);
    }

    pub fn find_route(&self, path: &str) -> Option<&Route> {
        // Exact match first
        if let Some(route) = self.routes.get(path) {
            return Some(route);
        }

        // Prefix match
        for (pattern, route) in &self.routes {
            if path.starts_with(pattern) {
                return Some(route);
            }
        }

        None
    }

    pub fn get_all_routes(&self) -> Vec<&Route> {
        self.routes.values().collect()
    }
}

impl Default for ApiRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router() {
        let mut router = ApiRouter::new();

        let route = Route {
            path: "/api/v1/tunnels".to_string(),
            methods: vec!["GET".to_string(), "POST".to_string()],
            backend: "http://backend:8080".to_string(),
            requires_auth: true,
            rate_limit: Some(100),
        };

        router.add_route(route);

        let found = router.find_route("/api/v1/tunnels").unwrap();
        assert_eq!(found.backend, "http://backend:8080");
        assert!(found.requires_auth);
    }

    #[test]
    fn test_prefix_match() {
        let mut router = ApiRouter::new();

        let route = Route {
            path: "/api/".to_string(),
            methods: vec!["GET".to_string()],
            backend: "http://backend:8080".to_string(),
            requires_auth: false,
            rate_limit: None,
        };

        router.add_route(route);

        assert!(router.find_route("/api/health").is_some());
        assert!(router.find_route("/api/v1/anything").is_some());
        assert!(router.find_route("/other/path").is_none());
    }
}
