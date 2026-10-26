//! Firewall aliases, backed by the config store and rendered as nftables
//! sets.
//!
//! An alias is a named list that rules reference as `$name` in their
//! source/destination (host aliases) or port (port aliases) field:
//!
//! | kind | entries | nft sets |
//! |---|---|---|
//! | host | IPv4/IPv6 addresses, CIDR networks, `a-b` ranges | `alias_<name>_v4`, `alias_<name>_v6` (`flags interval`) |
//! | port | ports and `a-b` port ranges | `alias_<name>_ports` (`inet_service`, `flags interval`) |
//!
//! A rule that references a host alias without an address-family
//! restriction renders an IPv4 and an IPv6 rule, so adding an IPv6 entry
//! later takes effect without touching the rule. Changing an alias's
//! entries only swaps the set elements in one nft transaction
//! ([`update_sets_script`]): the ruleset is not reloaded.
//!
//! Table: `firewall_aliases` (lane B migration 0100).

use crate::nftables::{
    alias_port_set_name, alias_set_name, is_valid_alias_name, AliasKind, AliasMap, TABLE,
};
use patronus_config::ConfigStore;
use patronus_core::types::IpVersion;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::net::IpAddr;

/// A stored alias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alias {
    pub name: String,
    pub kind: AliasKind,
    pub entries: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Set for aliases that fill themselves (URL table, GeoIP, threat
    /// feed): `entries` is then rewritten by [`crate::feeds`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<AliasSource>,
}

/// Where a self-filling alias gets its entries (table
/// `firewall_alias_sources`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasSource {
    /// `url`, `geoip` or `threat`.
    pub kind: String,
    #[serde(default)]
    pub url: Option<String>,
    /// geoip: ISO 3166-1 alpha-2 country codes.
    #[serde(default)]
    pub countries: Vec<String>,
    #[serde(default = "default_refresh")]
    pub refresh_secs: u64,
    #[serde(default = "default_max_entries")]
    pub max_entries: u64,
    /// threat: `in`, `out` or `both`.
    #[serde(default = "default_direction")]
    pub direction: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub last_attempt: Option<i64>,
    #[serde(default)]
    pub last_refresh: Option<i64>,
    #[serde(default)]
    pub last_status: Option<String>,
    #[serde(default)]
    pub last_count: Option<i64>,
}

impl AliasSource {
    /// A source of `kind` with the defaults (daily, 100 000 entries).
    pub fn new(kind: &str) -> Self {
        AliasSource {
            kind: kind.to_string(),
            url: None,
            countries: Vec::new(),
            refresh_secs: default_refresh(),
            max_entries: default_max_entries(),
            direction: default_direction(),
            enabled: true,
            last_attempt: None,
            last_refresh: None,
            last_status: None,
            last_count: None,
        }
    }
}

fn default_refresh() -> u64 {
    86_400
}
fn default_max_entries() -> u64 {
    100_000
}
fn default_direction() -> String {
    "both".into()
}
fn default_true() -> bool {
    true
}

impl Serialize for AliasKind {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(kind_str(*self))
    }
}

impl<'de> Deserialize<'de> for AliasKind {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        parse_kind(&s).map_err(serde::de::Error::custom)
    }
}

/// `host` or `port`.
pub fn kind_str(k: AliasKind) -> &'static str {
    match k {
        AliasKind::Host => "host",
        AliasKind::Port => "port",
    }
}

/// `host` (also `network`/`address`) or `port`.
pub fn parse_kind(s: &str) -> Result<AliasKind> {
    match s.trim().to_ascii_lowercase().as_str() {
        "host" | "hosts" | "network" | "networks" | "address" => Ok(AliasKind::Host),
        "port" | "ports" => Ok(AliasKind::Port),
        o => Err(Error::Config(format!(
            "Invalid alias type {o:?} (host or port)"
        ))),
    }
}

fn fam(a: &IpAddr) -> IpVersion {
    if a.is_ipv4() {
        IpVersion::V4
    } else {
        IpVersion::V6
    }
}

/// One validated host entry: its family and its nft element text.
pub(crate) fn host_entry(e: &str) -> Result<(IpVersion, String)> {
    let bad = || {
        Error::Config(format!(
            "Invalid alias entry {e:?} (address, CIDR or a-b range)"
        ))
    };
    if let Some((a, p)) = e.split_once('/') {
        let addr: IpAddr = a.parse().map_err(|_| bad())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        let plen: u8 = p.parse().map_err(|_| bad())?;
        if plen > max {
            return Err(bad());
        }
        return Ok((fam(&addr), format!("{addr}/{plen}")));
    }
    if let Some((a, b)) = e.split_once('-') {
        let (a, b): (IpAddr, IpAddr) =
            (a.parse().map_err(|_| bad())?, b.parse().map_err(|_| bad())?);
        if fam(&a) != fam(&b) || a > b {
            return Err(bad());
        }
        return Ok((fam(&a), format!("{a}-{b}")));
    }
    let a: IpAddr = e.parse().map_err(|_| bad())?;
    Ok((fam(&a), a.to_string()))
}

fn port_entry(e: &str) -> Result<String> {
    let bad = || {
        Error::Config(format!(
            "Invalid alias entry {e:?} (port or a-b port range)"
        ))
    };
    let p = |s: &str| s.parse::<u16>().ok().filter(|n| *n != 0).ok_or_else(bad);
    match e.split_once('-') {
        Some((a, b)) => {
            let (a, b) = (p(a)?, p(b)?);
            if a > b {
                return Err(bad());
            }
            Ok(format!("{a}-{b}"))
        }
        None => Ok(p(e)?.to_string()),
    }
}

impl Alias {
    /// Validate the name and every entry (nothing unvalidated ever reaches
    /// an nft script), trimming whitespace and dropping empty entries.
    pub fn validated(mut self) -> Result<Self> {
        if !is_valid_alias_name(&self.name) {
            return Err(Error::Config(format!(
                "Invalid alias name {:?} (a letter, then letters, digits or _, at most 31)",
                self.name
            )));
        }
        self.entries = self
            .entries
            .iter()
            .map(|e| e.trim().to_string())
            .filter(|e| !e.is_empty())
            .collect();
        self.elements()?;
        Ok(self)
    }

    /// (set name, element texts) for every set this alias owns.
    pub fn elements(&self) -> Result<Vec<(String, Vec<String>)>> {
        match self.kind {
            AliasKind::Host => {
                let (mut v4, mut v6) = (Vec::new(), Vec::new());
                for e in &self.entries {
                    match host_entry(e)? {
                        (IpVersion::V4, t) => v4.push(t),
                        (IpVersion::V6, t) => v6.push(t),
                    }
                }
                Ok(vec![
                    (alias_set_name(&self.name, IpVersion::V4), v4),
                    (alias_set_name(&self.name, IpVersion::V6), v6),
                ])
            }
            AliasKind::Port => {
                let p = self
                    .entries
                    .iter()
                    .map(|e| port_entry(e))
                    .collect::<Result<_>>()?;
                Ok(vec![(alias_port_set_name(&self.name), p)])
            }
        }
    }

    fn set_type(&self, set: &str) -> &'static str {
        match self.kind {
            AliasKind::Port => "inet_service",
            AliasKind::Host if set.ends_with("_v6") => "ipv6_addr",
            AliasKind::Host => "ipv4_addr",
        }
    }
}

/// `add set` + `add element` lines for the full ruleset.
pub fn sets_script(aliases: &[Alias]) -> Result<String> {
    let mut s = String::new();
    for a in aliases {
        for (set, elems) in a.elements()? {
            s.push_str(&format!(
                "add set {TABLE} {set} {{ type {}; flags interval; auto-merge; comment \"alias {}\"; }}\n",
                a.set_type(&set),
                a.name
            ));
            if !elems.is_empty() {
                s.push_str(&format!(
                    "add element {TABLE} {set} {{ {} }}\n",
                    elems.join(", ")
                ));
            }
        }
    }
    Ok(s)
}

/// Replace an existing alias's set contents in ONE nft transaction:
/// `flush set` + `add element`, no ruleset reload (rules, counters and the
/// rest of the table are untouched). Fails if the sets don't exist yet.
pub fn update_sets_script(alias: &Alias) -> Result<String> {
    let mut s = String::new();
    for (set, elems) in alias.elements()? {
        s.push_str(&format!("flush set {TABLE} {set}\n"));
        if !elems.is_empty() {
            s.push_str(&format!(
                "add element {TABLE} {set} {{ {} }}\n",
                elems.join(", ")
            ));
        }
    }
    Ok(s)
}

/// name -> kind map for the renderer.
pub fn alias_map(aliases: &[Alias]) -> AliasMap {
    aliases.iter().map(|a| (a.name.clone(), a.kind)).collect()
}

fn db(what: &'static str) -> impl Fn(sqlx::Error) -> Error {
    move |e| Error::Config(format!("{what}: {e}"))
}

/// All aliases, by name.
pub async fn load_aliases(store: &ConfigStore) -> Result<Vec<Alias>> {
    let rows = sqlx::query(
        "SELECT name, alias_type, entries, description FROM firewall_aliases ORDER BY name",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db("load aliases"))?;
    let mut sources = load_sources(store).await?;
    rows.iter()
        .map(|r| {
            let name: String = r.get(0);
            Ok(Alias {
                kind: parse_kind(&r.get::<String, _>(1))?,
                entries: serde_json::from_str(&r.get::<String, _>(2))
                    .map_err(|e| Error::Config(format!("alias {name}: bad entries: {e}")))?,
                description: r.get(3),
                source: sources.remove(&name),
                name,
            })
        })
        .collect()
}

/// Every alias source row, by alias name.
pub async fn load_sources(
    store: &ConfigStore,
) -> Result<std::collections::HashMap<String, AliasSource>> {
    let rows = sqlx::query(
        "SELECT alias, kind, url, countries, refresh_secs, max_entries, direction, enabled,
                last_attempt, last_refresh, last_status, last_count
         FROM firewall_alias_sources",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db("load alias sources"))?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get::<String, _>(0),
                AliasSource {
                    kind: r.get(1),
                    url: r.get(2),
                    countries: serde_json::from_str(&r.get::<String, _>(3)).unwrap_or_default(),
                    refresh_secs: r.get::<i64, _>(4).max(0) as u64,
                    max_entries: r.get::<i64, _>(5).max(0) as u64,
                    direction: r.get(6),
                    enabled: r.get::<i64, _>(7) != 0,
                    last_attempt: r.get(8),
                    last_refresh: r.get(9),
                    last_status: r.get(10),
                    last_count: r.get(11),
                },
            )
        })
        .collect())
}

/// One alias by name.
pub async fn get_alias(store: &ConfigStore, name: &str) -> Result<Option<Alias>> {
    Ok(load_aliases(store)
        .await?
        .into_iter()
        .find(|a| a.name == name))
}

/// Insert or replace an alias (validated).
pub async fn save_alias(store: &ConfigStore, alias: &Alias) -> Result<()> {
    let a = alias.clone().validated()?;
    sqlx::query(
        "INSERT INTO firewall_aliases (name, alias_type, entries, description, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET alias_type = excluded.alias_type,
             entries = excluded.entries, description = excluded.description,
             updated_at = excluded.updated_at",
    )
    .bind(&a.name)
    .bind(kind_str(a.kind))
    .bind(serde_json::to_string(&a.entries).expect("strings serialize"))
    .bind(&a.description)
    .bind(chrono::Utc::now().timestamp())
    .execute(store.pool()?)
    .await
    .map_err(db("save alias"))?;
    match &a.source {
        Some(src) => {
            let src = crate::feeds::check_source(&a, src)?;
            sqlx::query(
                "INSERT INTO firewall_alias_sources
                     (alias, kind, url, countries, refresh_secs, max_entries, direction, enabled)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(alias) DO UPDATE SET kind = excluded.kind, url = excluded.url,
                     countries = excluded.countries, refresh_secs = excluded.refresh_secs,
                     max_entries = excluded.max_entries, direction = excluded.direction,
                     enabled = excluded.enabled",
            )
            .bind(&a.name)
            .bind(&src.kind)
            .bind(&src.url)
            .bind(serde_json::to_string(&src.countries).expect("strings serialize"))
            .bind(src.refresh_secs as i64)
            .bind(src.max_entries as i64)
            .bind(&src.direction)
            .bind(src.enabled as i64)
            .execute(store.pool()?)
            .await
            .map_err(db("save alias source"))?;
        }
        None => {
            sqlx::query("DELETE FROM firewall_alias_sources WHERE alias = ?")
                .bind(&a.name)
                .execute(store.pool()?)
                .await
                .map_err(db("save alias"))?;
        }
    }
    Ok(())
}

/// Delete an alias. Refused while a filter or NAT rule references it.
pub async fn delete_alias(store: &ConfigStore, name: &str) -> Result<()> {
    let users = alias_users(store, name).await?;
    if !users.is_empty() {
        return Err(Error::Config(format!(
            "Invalid request: alias {name} is used by {}",
            users.join(", ")
        )));
    }
    sqlx::query("DELETE FROM firewall_aliases WHERE name = ?")
        .bind(name)
        .execute(store.pool()?)
        .await
        .map_err(db("delete alias"))?;
    sqlx::query("DELETE FROM firewall_alias_sources WHERE alias = ?")
        .bind(name)
        .execute(store.pool()?)
        .await
        .map_err(db("delete alias"))?;
    Ok(())
}

/// Names of the rules that reference `$name`.
pub async fn alias_users(store: &ConfigStore, name: &str) -> Result<Vec<String>> {
    let tok = format!("${name}");
    let port = patronus_core::types::PortSpec::Alias(name.to_string());
    let mut users = Vec::new();
    for r in store.load_firewall_rules().await? {
        if r.source.as_deref() == Some(&tok)
            || r.destination.as_deref() == Some(&tok)
            || r.dport.as_ref() == Some(&port)
            || r.sport.as_ref() == Some(&port)
        {
            users.push(format!("rule {:?}", r.name));
        }
    }
    for r in store.load_nat_rules().await? {
        if r.source.as_deref() == Some(&tok)
            || r.destination.as_deref() == Some(&tok)
            || r.dport.as_ref() == Some(&port)
        {
            users.push(format!("NAT rule {:?}", r.name));
        }
    }
    Ok(users)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str, e: &[&str]) -> Alias {
        Alias {
            name: name.into(),
            kind: AliasKind::Host,
            entries: e.iter().map(|s| s.to_string()).collect(),
            description: None,
            source: None,
        }
    }

    #[test]
    fn host_alias_splits_families_and_validates() {
        let a = host(
            "web",
            &[
                "192.0.2.1",
                " 10.0.0.0/8",
                "2001:db8::/32",
                "10.1.1.1-10.1.1.9",
                "",
            ],
        )
        .validated()
        .unwrap();
        let el = a.elements().unwrap();
        assert_eq!(el[0].0, "alias_web_v4");
        assert_eq!(
            el[0].1,
            vec!["192.0.2.1", "10.0.0.0/8", "10.1.1.1-10.1.1.9"]
        );
        assert_eq!(el[1].1, vec!["2001:db8::/32"]);
        let sc = sets_script(std::slice::from_ref(&a)).unwrap();
        assert!(
            sc.contains("add set inet patronus alias_web_v6 { type ipv6_addr; flags interval;"),
            "{sc}"
        );
        assert!(sc.contains(
            "add element inet patronus alias_web_v4 { 192.0.2.1, 10.0.0.0/8, 10.1.1.1-10.1.1.9 }"
        ));
        let up = update_sets_script(&a).unwrap();
        assert!(
            up.starts_with("flush set inet patronus alias_web_v4\n"),
            "{up}"
        );
        for bad in [
            "10.0.0.0/33",
            "host.example",
            "1.2.3.4; flush ruleset",
            "10.0.0.9-10.0.0.1",
            "10.0.0.1-::1",
            "10.0.0.0/+8",
        ] {
            assert!(host("x", &[bad]).validated().is_err(), "{bad}");
        }
        for bad in [
            "1x",
            "",
            "a-b",
            "x;y",
            "this_alias_name_is_far_too_long_for_nft",
        ] {
            assert!(host(bad, &[]).validated().is_err(), "{bad}");
        }
    }

    #[test]
    fn port_alias() {
        let a = Alias {
            name: "webports".into(),
            kind: AliasKind::Port,
            entries: vec!["80".into(), "8000-8010".into()],
            description: None,
            source: None,
        };
        assert_eq!(a.elements().unwrap()[0].1, vec!["80", "8000-8010"]);
        assert!(sets_script(std::slice::from_ref(&a))
            .unwrap()
            .contains("type inet_service"));
        let mut b = a.clone();
        b.entries = vec!["0".into()];
        assert!(b.clone().validated().is_err());
        b.entries = vec!["90-80".into()];
        assert!(b.validated().is_err());
    }

    #[tokio::test]
    async fn store_round_trip_and_in_use_aliases_cannot_be_deleted() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        save_alias(&s, &host("bad", &["198.51.100.7"]))
            .await
            .unwrap();
        save_alias(&s, &host("bad", &["198.51.100.8"]))
            .await
            .unwrap();
        assert_eq!(
            load_aliases(&s).await.unwrap()[0].entries,
            vec!["198.51.100.8"]
        );
        let mut r = patronus_core::types::FirewallRule::new(
            "block bad".into(),
            patronus_core::types::ChainType::Forward,
            patronus_core::types::FirewallAction::Drop,
        );
        r.source = Some("$bad".into());
        let id = s.save_firewall_rule(&r).await.unwrap();
        let e = delete_alias(&s, "bad").await.unwrap_err().to_string();
        assert!(e.contains("Invalid") && e.contains("block bad"), "{e}");
        s.delete_firewall_rule(id as u64).await.unwrap();
        delete_alias(&s, "bad").await.unwrap();
        assert!(load_aliases(&s).await.unwrap().is_empty());
    }
}
