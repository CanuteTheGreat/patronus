//! `patronus import pfsense FILE` and `patronus import-uci`: thin CLI wrappers around the
//! importers in the patronus-import crate (shared with the web UI's import page).

use anyhow::{bail, Context, Result};
use patronus_import::{pfsense, uci};
use std::path::PathBuf;

/// `patronus import pfsense FILE [--plan] [--map OLD=NEW]... [--yes]`.
pub async fn pfsense(
    db: Option<PathBuf>,
    file: PathBuf,
    maps: Vec<String>,
    yes: bool,
) -> Result<()> {
    let maps = uci::parse_maps(&maps)?;
    let xml = std::fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))?;
    // ports not mapped with --map go to the port with the same role on this box (wan, lan, optN)
    let roles = match super::apply::open_store(db.as_deref()).await {
        Ok(s) => s.interface_roles().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let auto = pfsense::role_maps(&xml, &roles, &maps);
    for (o, n) in &auto {
        println!("port matched by role: {o} -> {n}");
    }
    let mut maps = maps;
    maps.extend(auto);
    let plan = pfsense::build_plan(&xml, &maps)?;
    print!("{}", pfsense::render(&plan, !yes));
    if !yes {
        println!("\nplan only, nothing written; add --yes to write it into the config store");
        return Ok(());
    }
    let store = super::apply::open_store(db.as_deref()).await?;
    println!("\nstore:");
    for l in pfsense::apply(&store, &plan).await? {
        println!("  {l}");
    }
    println!("\nreview with `patronus apply --dry-run`, then `patronus apply`");
    Ok(())
}

/// `patronus import-uci <dir|tar.gz> [--ssh root@router] [--dry-run] [--map UCI=DEVICE]... [--ddns-disabled]`.
pub async fn uci(
    db: Option<PathBuf>,
    input: Option<PathBuf>,
    ssh: Option<String>,
    dry_run: bool,
    maps: Vec<String>,
    ddns_disabled: bool,
) -> Result<()> {
    let maps = uci::parse_maps(&maps)?;
    // `--ssh root@router[:port]`: the configuration travels over ssh into a 0700 scratch dir, removed after
    let scratch = ssh.as_ref().map(|_| {
        let d = std::env::temp_dir().join(format!("patronus-import-ssh-{}", std::process::id()));
        uci::Scratch(d)
    });
    let input = match (&ssh, input) {
        (Some(t), _) => {
            let d = &scratch.as_ref().expect("scratch").0;
            std::fs::create_dir_all(d)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))?;
            }
            uci::fetch_over_ssh(t, d)?
        }
        (None, Some(i)) => i,
        (None, None) => bail!("give a tarball/directory or --ssh root@router[:port]"),
    };
    let (files, mut extras) = uci::load_input_full(&input)?;
    // the running odhcp6c names the IAID the old router really sends
    if let Some(live) = ssh.as_deref().and_then(uci::fetch_live_odhcp6c) {
        extras.0.insert(uci::LIVE_ODHCP6C.to_string(), live);
    }
    let mut plan = uci::build_plan_with(&files, &extras, &maps);
    if ddns_disabled {
        uci::disable_ddns(&mut plan);
    }
    print!("{}", uci::render(&plan, dry_run));
    if dry_run {
        return Ok(());
    }
    let store = super::apply::open_store(db.as_deref()).await?;
    println!("\nstore:");
    for l in uci::apply(&store, &plan).await? {
        println!("  {l}");
    }
    println!("\nreview with `patronus apply --dry-run`, then `patronus apply`");
    Ok(())
}
