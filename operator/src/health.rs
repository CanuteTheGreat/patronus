//! Health check endpoints for Kubernetes probes

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

/// Health status for the operator
#[derive(Clone)]
pub struct HealthStatus {
    /// Is the operator ready to serve traffic?
    ready: Arc<AtomicBool>,
    /// Is the operator alive?
    alive: Arc<AtomicBool>,
}

impl HealthStatus {
    /// Create a new health status
    pub fn new() -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(false)),
            alive: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Mark the operator as ready
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::SeqCst);
        if ready {
            info!("Operator is ready");
        } else {
            warn!("Operator is not ready");
        }
    }

    /// Mark the operator as alive/dead
    pub fn set_alive(&self, alive: bool) {
        self.alive.store(alive, Ordering::SeqCst);
        if !alive {
            warn!("Operator is not alive");
        }
    }

    /// Check if the operator is ready
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// Check if the operator is alive
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::new()
    }
}

/// Health check server
pub struct HealthServer {
    port: u16,
    status: HealthStatus,
}

impl HealthServer {
    /// Create a new health check server
    pub fn new(port: u16, status: HealthStatus) -> Self {
        Self { port, status }
    }

    /// Run the health check server
    pub async fn run(&self) -> anyhow::Result<()> {
        let addr: SocketAddr = ([0, 0, 0, 0], self.port).into();
        let listener = TcpListener::bind(&addr).await?;

        info!("Health check server listening on http://{}", addr);

        loop {
            let (socket, _) = listener.accept().await?;
            let status = self.status.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_health_request(socket, status).await {
                    debug!("Health check error: {}", e);
                }
            });
        }
    }
}

/// Handle a health check request
async fn handle_health_request(
    socket: tokio::net::TcpStream,
    status: HealthStatus,
) -> anyhow::Result<()> {
    let mut buf = vec![0; 1024];

    // Read request
    socket.readable().await?;
    let n = socket.try_read(&mut buf)?;

    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse request path
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    debug!("Health check request: {}", path);

    // Route to appropriate handler
    let (status_code, body) = match path {
        "/healthz" | "/health" => {
            if status.is_alive() {
                (200, "OK")
            } else {
                (503, "Service Unavailable")
            }
        }
        "/readyz" | "/ready" => {
            if status.is_ready() {
                (200, "Ready")
            } else {
                (503, "Not Ready")
            }
        }
        "/livez" | "/alive" => {
            if status.is_alive() {
                (200, "Alive")
            } else {
                (503, "Not Alive")
            }
        }
        _ => (404, "Not Found"),
    };

    // Send response
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        status_code,
        status_text(status_code),
        body.len(),
        body
    );

    socket.try_write(response.as_bytes())?;

    Ok(())
}

/// Get status text for HTTP status code
fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status() {
        let status = HealthStatus::new();

        // Initially not ready but alive
        assert!(!status.is_ready());
        assert!(status.is_alive());

        // Mark as ready
        status.set_ready(true);
        assert!(status.is_ready());
        assert!(status.is_alive());

        // Mark as not alive
        status.set_alive(false);
        assert!(status.is_ready());
        assert!(!status.is_alive());
    }

    #[test]
    fn test_status_text() {
        assert_eq!(status_text(200), "OK");
        assert_eq!(status_text(404), "Not Found");
        assert_eq!(status_text(503), "Service Unavailable");
    }
}
