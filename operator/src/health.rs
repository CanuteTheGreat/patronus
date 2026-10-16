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
    #[allow(dead_code)]
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
    mut socket: tokio::net::TcpStream,
    status: HealthStatus,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0; 1024];

    // Read request. `readable()` + `try_read()` could spuriously return
    // WouldBlock and drop the probe; a real async read waits for data.
    let n = socket.read(&mut buf).await?;

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

    // Send response. This server answers exactly one request per
    // connection, so it must say `Connection: close`: without it HTTP/1.1
    // clients (reqwest, kubelet with keep-alive) reused the connection we
    // had already closed and failed with "IncompleteMessage".
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_code,
        status_text(status_code),
        body.len(),
        body
    );

    socket.write_all(response.as_bytes()).await?;
    socket.shutdown().await?;

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

    /// Regression: a keep-alive HTTP/1.1 client (reqwest's pooled client,
    /// like the ignored integration test `test_health_response_time`) used
    /// to fail its second request with IncompleteMessage because the server
    /// closed the connection without sending `Connection: close`.
    #[tokio::test]
    async fn sequential_requests_on_a_pooled_client_all_succeed() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let status = HealthStatus::new();
        status.set_ready(true);
        let server = HealthServer::new(port, status);
        tokio::spawn(async move { server.run().await });

        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{}", port);
        for _ in 0..50 {
            if client.get(format!("{base}/healthz")).send().await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        for (path, want) in [("/healthz", 200), ("/readyz", 200), ("/nope", 404)]
            .iter()
            .cycle()
            .take(15)
        {
            let r = client
                .get(format!("{base}{path}"))
                .send()
                .await
                .unwrap_or_else(|e| panic!("GET {path} failed: {e}"));
            assert_eq!(r.status().as_u16(), *want, "{path}");
            assert_eq!(
                r.headers().get("connection").and_then(|v| v.to_str().ok()),
                Some("close")
            );
        }
    }
}
