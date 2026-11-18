//! `patronus ap-wifi`: the access-point Wi-Fi of a router-tier unit (`/etc/patronus/ap.env`, the same settings the
//! web UI's Wi-Fi page edits) as a declarative document: `export` it, edit it, `plan` shows what would change, `apply`
//! writes it, restarts the radios and checks every network (rolls back on failure). Passphrases are never exported;
//! a document keeps the stored passphrase of every network it names by `id`.

use anyhow::{Context, Result};
use patronus_network::apwifi;
use std::path::PathBuf;

fn read_doc(file: &PathBuf) -> Result<serde_json::Value> {
    let text = if file.as_os_str() == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
        s
    } else {
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?
    };
    // YAML is a superset of JSON: one parser takes both
    let v: serde_json::Value =
        serde_yaml::from_str(&text).context("the document is not YAML/JSON")?;
    Ok(v)
}

pub fn show() -> Result<()> {
    let v = apwifi::get(&apwifi::Paths::default()).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub fn export(json: bool) -> Result<()> {
    let v = apwifi::export_unit(&apwifi::Paths::default()).map_err(|e| anyhow::anyhow!("{e}"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        print!("# Access-point Wi-Fi of this unit. Edit, then `patronus ap-wifi plan FILE` / `apply FILE`.\n# Passphrases are not exported: a network listed with its id keeps its passphrase; set `key:` to change it.\n{}", serde_yaml::to_string(&v)?);
    }
    Ok(())
}

pub fn plan(file: PathBuf) -> Result<()> {
    let input = apwifi::parse_doc(&read_doc(&file)?).map_err(|e| anyhow::anyhow!("{e}"))?;
    let p =
        apwifi::plan_unit(&apwifi::Paths::default(), &input).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{}", serde_json::to_string_pretty(&p)?);
    Ok(())
}

pub fn apply(file: PathBuf) -> Result<()> {
    let input = apwifi::parse_doc(&read_doc(&file)?).map_err(|e| anyhow::anyhow!("{e}"))?;
    let r = apwifi::apply(&apwifi::Paths::default(), &input).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}
