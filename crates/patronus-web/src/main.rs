//! Patronus Web Interface binary
//!
//! This is the main entry point for the web-based management interface (the
//! server itself is `patronus_web::server`, shared with the embedded tier's
//! multi-call `patronus-cli`).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    patronus_web::server::init_tracing();
    patronus_web::server::run().await
}
