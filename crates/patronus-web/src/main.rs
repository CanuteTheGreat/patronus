//! Patronus Web Interface binary
//!
//! This is the main entry point for the web-based management interface (the
//! server itself is `patronus_web::server`, shared with the embedded tier's
//! multi-call `patronus-cli`).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --help / --version answer and exit; they must never start the server
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some((text, code)) = patronus_web::server::cli_flags(&args) {
        if code == 0 {
            print!("{text}");
        } else {
            eprint!("{text}");
        }
        std::process::exit(code);
    }
    patronus_web::server::init_tracing();
    // a server that could not start must END the process (so the init system sees it): returning the error from main
    // would first wait for the runtime's remaining background tasks, which keep it alive
    if let Err(e) = patronus_web::server::run().await {
        eprintln!("patronus-web: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}
