//! `patronus plugin`: make signing keys and signed plugin bundles, and check
//! a bundle against a public key (USE=plugins). Installing happens on the
//! Packages page / `POST /api/packages/plugins`.

use anyhow::{bail, Context, Result};
use patronus_network::plugins;
use std::path::Path;

pub fn keygen(out: &Path) -> Result<()> {
    let (secret, public) = plugins::keygen();
    let sec = out.with_extension("key");
    let pubf = out.with_extension("pub");
    if sec.exists() || pubf.exists() {
        bail!("{} or {} exists already", sec.display(), pubf.display());
    }
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&sec)
            .with_context(|| sec.display().to_string())?;
        writeln!(f, "{secret}")?;
    }
    std::fs::write(&pubf, format!("{public}\n"))?;
    println!("secret key: {} (keep it private)", sec.display());
    println!(
        "public key: {} (trust it on the Packages page)",
        pubf.display()
    );
    println!("key id:     {}", plugins::key_id(&public));
    Ok(())
}

pub fn pack(dir: &Path, key: &Path, out: &Path) -> Result<()> {
    let secret = std::fs::read_to_string(key).with_context(|| key.display().to_string())?;
    let bundle = plugins::pack(dir, secret.trim())?;
    std::fs::write(out, bundle)?;
    println!("wrote {}", out.display());
    Ok(())
}

pub fn verify(bundle: &Path, public: &Path) -> Result<()> {
    let text = std::fs::read_to_string(bundle).with_context(|| bundle.display().to_string())?;
    let public = std::fs::read_to_string(public)?.trim().to_string();
    let (m, kid) = plugins::verify(&text, &[(plugins::key_id(&public), public)])?;
    println!(
        "ok: {} {} signed by key {kid} ({} file(s){})",
        m.name,
        m.version,
        m.files.len(),
        if m.service.is_some() {
            ", runs a service"
        } else {
            ""
        }
    );
    Ok(())
}
