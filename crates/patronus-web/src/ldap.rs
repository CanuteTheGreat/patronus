//! LDAP / Active Directory login for the web UI (USE=ldap). A person whose
//! account lives in a directory logs in with those credentials: the server
//! is searched (with an optional service account) for exactly one entry that
//! matches the configured filter, then that entry is bound with the password
//! the person typed. An empty password is never sent (it would be an
//! anonymous bind that "succeeds"), and the user name is escaped
//! (RFC 4515) before it goes into the filter.

use ldap3::{ldap_escape, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use std::time::Duration;

use crate::radius::AuthServer;

/// The search filter for `user`: `{u}` replaced by the escaped name.
pub fn user_filter(template: &str, user: &str) -> String {
    template.replace("{u}", &ldap_escape(user))
}

/// A usable filter template: parenthesised and naming the user.
pub fn check_filter(t: &str) -> bool {
    let t = t.trim();
    t.starts_with('(') && t.ends_with(')') && t.contains("{u}") && t.len() <= 256
}

pub fn url(s: &AuthServer) -> String {
    let host = if s.host.contains(':') {
        format!("[{}]", s.host)
    } else {
        s.host.clone()
    };
    let scheme = if s.tls == "ldaps" { "ldaps" } else { "ldap" };
    format!("{scheme}://{host}:{}", s.port)
}

async fn connect(s: &AuthServer) -> Result<ldap3::Ldap, String> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(u64::from(s.timeout_secs)))
        .set_starttls(s.tls == "starttls");
    let (conn, ldap) = LdapConnAsync::with_settings(settings, &url(s))
        .await
        .map_err(|e| format!("connecting: {e}"))?;
    ldap3::drive!(conn);
    Ok(ldap)
}

/// What a successful login learned.
#[derive(Debug, PartialEq, Eq)]
pub struct Found {
    pub dn: String,
    pub operator: bool,
}

/// Ok(None): the directory answered and refused (no/ambiguous entry, wrong
/// password). Err: the server could not be asked.
pub async fn authenticate(
    s: &AuthServer,
    user: &str,
    password: &str,
) -> Result<Option<Found>, String> {
    if password.is_empty() || user.is_empty() {
        return Ok(None);
    }
    let mut svc = connect(s).await?;
    if !s.bind_dn.is_empty() {
        svc.simple_bind(&s.bind_dn, &s.secret)
            .await
            .map_err(|e| format!("search account bind: {e}"))?
            .success()
            .map_err(|e| format!("search account bind refused: {e}"))?;
    }
    let (rows, _) = svc
        .search(
            &s.base_dn,
            Scope::Subtree,
            &user_filter(&s.user_filter, user),
            vec!["1.1"],
        )
        .await
        .map_err(|e| format!("search: {e}"))?
        .success()
        .map_err(|e| format!("search: {e}"))?;
    let mut dns: Vec<String> = rows
        .into_iter()
        .map(|r| SearchEntry::construct(r).dn)
        .collect();
    if dns.len() != 1 {
        let _ = svc.unbind().await;
        return Ok(None);
    }
    let dn = dns.remove(0);
    let operator = if s.operator_group.is_empty() {
        false
    } else {
        svc.compare(&s.operator_group, "member", dn.as_bytes())
            .await
            .map(|r| r.equal().unwrap_or(false))
            .unwrap_or(false)
    };
    let _ = svc.unbind().await;
    let mut usr = connect(s).await?;
    let res = usr
        .simple_bind(&dn, password)
        .await
        .map_err(|e| format!("user bind: {e}"))?;
    let _ = usr.unbind().await;
    Ok((res.rc == 0).then_some(Found { dn, operator }))
}

/// Try the enabled LDAP servers in order: the first that accepts wins; a
/// refusal ends the attempt; an unreachable server is skipped.
pub async fn check_login(
    store: &patronus_config::ConfigStore,
    user: &str,
    password: &str,
) -> Option<(AuthServer, Found)> {
    let list = crate::radius::servers(store).await.ok()?;
    for s in list.into_iter().filter(|s| s.enabled && s.kind == "ldap") {
        match tokio::time::timeout(
            Duration::from_secs(u64::from(s.timeout_secs) * 3),
            authenticate(&s, user, password),
        )
        .await
        {
            Ok(Ok(Some(f))) => return Some((s, f)),
            Ok(Ok(None)) => return None,
            Ok(Err(e)) => tracing::warn!("LDAP server {} ({}): {e}", s.name, url(&s)),
            Err(_) => tracing::warn!("LDAP server {} ({}): timed out", s.name, url(&s)),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_user_name_cannot_rewrite_the_filter() {
        assert_eq!(user_filter("(uid={u})", "alice"), "(uid=alice)");
        let f = user_filter("(uid={u})", "*)(uid=*))(|(uid=*");
        assert!(!f.contains("*)(") && f.starts_with("(uid=") && f.ends_with(')'));
        assert!(f.contains("\\2a") && f.contains("\\28") && f.contains("\\29"));
    }

    #[test]
    fn filters_must_name_the_user() {
        assert!(check_filter("(uid={u})"));
        assert!(check_filter("(&(objectClass=person)(sAMAccountName={u}))"));
        assert!(!check_filter("uid={u}"));
        assert!(!check_filter("(uid=*)"));
    }
}
