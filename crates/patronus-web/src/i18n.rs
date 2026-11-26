//! UI and API languages.
//!
//! * Catalogs are Fluent files (`i18n/<tag>.ftl`, compiled in). English is the source; a language
//!   is added by dropping `i18n/<tag>.ftl` next to it and naming it in [`CATALOGS`]. A key a
//!   catalog lacks falls back to English, then to the key itself.
//! * The language of a request is decided by [`choose`]: the signed-in account's own choice, then
//!   the browser's choice on the login page (`?lang=` / cookie), then the system default
//!   (`patronus_config::uilang`, `auto` = no preference), then the browser's `Accept-Language`,
//!   then English.
//! * Templates translate with the `t` filter (`{{ "nav-firewall"|t }}`); JavaScript reads the
//!   `js-*` keys from `window.PATRONUS_I18N`. API error messages are translated on the way out
//!   ([`middleware`]): a catalog entry `err-*` whose English text is the message (with `$v1`..`$v9`
//!   for the variable parts) translates the message that handlers still write in English, and new
//!   code uses [`api_error`] with a catalog key. `ci/check-i18n.py` keeps the catalogs complete
//!   and stops new hard-coded text.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::{FromRequestParts, State},
    http::{header, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use fluent_bundle::concurrent::FluentBundle;
use fluent_bundle::{FluentArgs, FluentResource, FluentValue};
use patronus_config::store::ConfigStore;
use patronus_config::uilang;
use unic_langid::LanguageIdentifier;

/// Every catalog, English first (the fallback). One line per language.
pub const CATALOGS: &[(&str, &str)] = &[
    ("en", include_str!("../i18n/en.ftl")),
    ("de", include_str!("../i18n/de.ftl")),
];

/// Cookie holding the browser's own choice (set from the login page's `?lang=`).
pub const COOKIE: &str = "patronus_lang";
/// The language every missing key falls back to.
pub const FALLBACK: &str = uilang::FALLBACK_LANGUAGE;

const CACHE_TTL: Duration = Duration::from_secs(30);

enum Seg {
    Lit(String),
    Var(String),
}

struct Catalog {
    code: &'static str,
    name: String,
    bundle: FluentBundle<FluentResource>,
    /// `err-*` messages of the English catalog as (id, segments), longest literal text first.
    patterns: Vec<(String, Vec<Seg>)>,
    exact: HashMap<String, String>,
}

static ALL: OnceLock<Vec<Catalog>> = OnceLock::new();

const SENTINEL: char = '\u{1}';

fn build(code: &'static str, src: &'static str) -> Catalog {
    let res = FluentResource::try_new(src.to_string()).unwrap_or_else(|(r, _)| r);
    let id: LanguageIdentifier = code.parse().unwrap_or_default();
    let mut bundle = FluentBundle::new_concurrent(vec![id]);
    // the output goes into HTML and JSON: no bidi isolation marks around placeables
    bundle.set_use_isolating(false);
    let _ = bundle.add_resource(res);
    let name = format_in(&bundle, "lang-name", None).unwrap_or_else(|| code.to_string());
    Catalog {
        code,
        name,
        bundle,
        patterns: Vec::new(),
        exact: HashMap::new(),
    }
}

fn format_in(
    b: &FluentBundle<FluentResource>,
    key: &str,
    args: Option<&FluentArgs>,
) -> Option<String> {
    let msg = b.get_message(key)?;
    let pat = msg.value()?;
    let mut errs = vec![];
    Some(b.format_pattern(pat, args, &mut errs).into_owned())
}

fn catalogs() -> &'static Vec<Catalog> {
    ALL.get_or_init(|| {
        let mut v: Vec<Catalog> = CATALOGS.iter().map(|(c, s)| build(c, s)).collect();
        // error patterns: the English text of every err-* message, with the variables marked
        let src = CATALOGS[0].1;
        let ids: Vec<String> = src
            .lines()
            .filter(|l| !l.starts_with(char::is_whitespace))
            .filter_map(|l| l.split_once(" =").map(|(k, _)| k.trim().to_string()))
            .filter(|k| k.starts_with("err-"))
            .collect();
        let en = &v[0];
        let mut patterns = Vec::new();
        let mut exact = HashMap::new();
        for id in ids {
            let mut args = FluentArgs::new();
            for i in 1..=9 {
                args.set(
                    format!("v{i}"),
                    FluentValue::from(format!("{SENTINEL}{i}{SENTINEL}")),
                );
            }
            let Some(text) = format_in(&en.bundle, &id, Some(&args)) else {
                continue;
            };
            let mut segs = Vec::new();
            let mut cur = String::new();
            let mut it = text.chars().peekable();
            while let Some(c) = it.next() {
                if c == SENTINEL {
                    let n: String = it.by_ref().take_while(|x| *x != SENTINEL).collect();
                    if !cur.is_empty() {
                        segs.push(Seg::Lit(std::mem::take(&mut cur)));
                    }
                    segs.push(Seg::Var(format!("v{n}")));
                } else {
                    cur.push(c);
                }
            }
            if !cur.is_empty() {
                segs.push(Seg::Lit(cur));
            }
            if segs.iter().all(|s| matches!(s, Seg::Lit(_))) {
                exact.insert(text, id);
            } else {
                patterns.push((id, segs));
            }
        }
        let weight = |s: &Vec<Seg>| -> usize {
            s.iter()
                .map(|x| if let Seg::Lit(l) = x { l.len() } else { 0 })
                .sum()
        };
        patterns.sort_by_key(|p| std::cmp::Reverse(weight(&p.1)));
        v[0].patterns = patterns;
        v[0].exact = exact;
        v
    })
}

fn catalog(code: &str) -> Option<&'static Catalog> {
    catalogs().iter().find(|c| c.code == code)
}

/// The language codes that have a catalog, English first.
pub fn supported() -> Vec<&'static str> {
    catalogs().iter().map(|c| c.code).collect()
}

/// (code, native name) of every language, for the pickers.
pub fn languages() -> Vec<(&'static str, String)> {
    catalogs()
        .iter()
        .map(|c| (c.code, c.name.clone()))
        .collect()
}

// ---- translating ----

/// `key` in `lang` (falls back to English, then to the key).
pub fn tr_in(lang: &str, key: &str, args: &[(&str, String)]) -> String {
    let mut fa = FluentArgs::new();
    for (k, v) in args {
        fa.set(k.to_string(), FluentValue::from(v.clone()));
    }
    let a = if args.is_empty() { None } else { Some(&fa) };
    for code in [lang, FALLBACK] {
        if let Some(c) = catalog(code) {
            if let Some(s) = format_in(&c.bundle, key, a) {
                return s;
            }
        }
    }
    key.to_string()
}

tokio::task_local! {
    /// The language of the request being served.
    pub static LANG: String;
}

/// The language of the current request (English outside one).
pub fn current() -> String {
    LANG.try_with(|l| l.clone())
        .unwrap_or_else(|_| FALLBACK.to_string())
}

/// `key` in the current request's language.
pub fn tr(key: &str) -> String {
    tr_in(&current(), key, &[])
}

pub fn tr_with(key: &str, args: &[(&str, String)]) -> String {
    tr_in(&current(), key, args)
}

/// A message with one numeric argument `$n` (plural selection): `wait-seconds`.
pub fn tr_num(key: &str, n: u64) -> String {
    let lang = current();
    let mut fa = FluentArgs::new();
    fa.set("n", FluentValue::from(n));
    for code in [lang.as_str(), FALLBACK] {
        if let Some(c) = catalog(code) {
            if let Some(s) = format_in(&c.bundle, key, Some(&fa)) {
                return s;
            }
        }
    }
    key.to_string()
}

fn match_pattern(segs: &[Seg], msg: &str) -> Option<Vec<(String, String)>> {
    let mut vars = Vec::new();
    let mut rest = msg;
    let mut i = 0;
    while i < segs.len() {
        match &segs[i] {
            Seg::Lit(l) => {
                rest = rest.strip_prefix(l.as_str())?;
                i += 1;
            }
            Seg::Var(name) => match segs.get(i + 1) {
                None => {
                    vars.push((name.clone(), rest.to_string()));
                    rest = "";
                    i += 1;
                }
                Some(Seg::Lit(next)) => {
                    let at = rest.find(next.as_str())?;
                    vars.push((name.clone(), rest[..at].to_string()));
                    rest = &rest[at..];
                    i += 1;
                }
                Some(Seg::Var(_)) => return None,
            },
        }
    }
    rest.is_empty().then_some(vars)
}

/// An English API message in `lang`; None when no catalog entry covers it.
pub fn translate_message(lang: &str, english: &str) -> Option<String> {
    if lang == FALLBACK {
        return None;
    }
    let en = catalog(FALLBACK)?;
    if let Some(id) = en.exact.get(english) {
        let t = tr_in(lang, id, &[]);
        return (t != *id).then_some(t);
    }
    for (id, segs) in &en.patterns {
        if let Some(vars) = match_pattern(segs, english) {
            let args: Vec<(&str, String)> =
                vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
            let t = tr_in(lang, id, &args);
            return (t != *id).then_some(t);
        }
    }
    None
}

/// A JSON error body for new handlers: `{"error": <message in the request language>, "code": key}`.
pub fn api_error(status: StatusCode, key: &str, args: &[(&str, String)]) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": tr_with(key, args), "code": key })),
    )
        .into_response()
}

// ---- choosing the language ----

/// `Accept-Language` as (tag, q), best first.
pub fn parse_accept_language(h: &str) -> Vec<(String, f32)> {
    let mut v: Vec<(String, f32)> = h
        .split(',')
        .filter_map(|p| {
            let mut it = p.split(';');
            let tag = it.next()?.trim().to_ascii_lowercase();
            if tag.is_empty() {
                return None;
            }
            let q = it
                .find_map(|x| {
                    x.trim()
                        .strip_prefix("q=")
                        .and_then(|q| q.trim().parse::<f32>().ok())
                })
                .unwrap_or(1.0);
            (q > 0.0).then_some((tag, q))
        })
        .collect();
    v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    v
}

/// The catalog that serves `tag` (`de-AT` -> `de`), if any.
pub fn match_supported(tag: &str, supported: &[&str]) -> Option<String> {
    let t = tag.trim().to_ascii_lowercase().replace('_', "-");
    if let Some(s) = supported.iter().find(|s| **s == t) {
        return Some(s.to_string());
    }
    let primary = t.split('-').next().unwrap_or("");
    supported
        .iter()
        .find(|s| **s == primary)
        .map(|s| s.to_string())
}

pub struct Inputs<'a> {
    /// The account's own language ("" = none).
    pub user: &'a str,
    /// The browser's choice on the login page ("" = none).
    pub picked: &'a str,
    /// The system default (`auto` or a tag).
    pub system: &'a str,
    /// The `Accept-Language` header ("" = none).
    pub accept: &'a str,
}

/// The language a request is served in.
pub fn choose(i: &Inputs, supported: &[&str]) -> String {
    for t in [i.user, i.picked] {
        if let Some(m) = match_supported(t, supported) {
            return m;
        }
    }
    if i.system != uilang::AUTO {
        if let Some(m) = match_supported(i.system, supported) {
            return m;
        }
    }
    for (tag, _) in parse_accept_language(i.accept) {
        if let Some(m) = match_supported(&tag, supported) {
            return m;
        }
    }
    FALLBACK.to_string()
}

// ---- stored preferences ----

/// Accounts' languages and the system default, cached for a few seconds so a page or an API
/// poll does not read the store each time.
pub struct Prefs {
    store: Arc<ConfigStore>,
    users: RwLock<HashMap<u32, (Instant, String)>>,
    system: RwLock<Option<(Instant, String)>>,
}

impl Prefs {
    pub fn new(store: Arc<ConfigStore>) -> Self {
        Self {
            store,
            users: RwLock::new(HashMap::new()),
            system: RwLock::new(None),
        }
    }

    /// The account's own language ("" = none).
    pub async fn user(&self, id: u32) -> String {
        if let Some((at, v)) = self.users.read().ok().and_then(|m| m.get(&id).cloned()) {
            if at.elapsed() < CACHE_TTL {
                return v;
            }
        }
        let v: String = match self.store.pool() {
            Ok(p) => sqlx::query_scalar("SELECT language FROM web_users WHERE id = ?")
                .bind(id as i64)
                .fetch_optional(p)
                .await
                .ok()
                .flatten()
                .unwrap_or_default(),
            Err(_) => String::new(),
        };
        if let Ok(mut m) = self.users.write() {
            m.insert(id, (Instant::now(), v.clone()));
        }
        v
    }

    /// Store an account's language ("" = back to the system default). The tag must have a catalog.
    pub async fn set_user(&self, id: u32, lang: &str) -> anyhow::Result<()> {
        let v = if lang.trim().is_empty() {
            String::new()
        } else {
            match_supported(lang, &supported()).ok_or_else(|| {
                anyhow::anyhow!("Invalid language '{}': no catalog for it", lang.trim())
            })?
        };
        let p = self
            .store
            .pool()
            .map_err(|e| anyhow::anyhow!("store: {e}"))?;
        sqlx::query("UPDATE web_users SET language = ? WHERE id = ?")
            .bind(&v)
            .bind(id as i64)
            .execute(p)
            .await
            .map_err(|e| anyhow::anyhow!("store: {e}"))?;
        if let Ok(mut m) = self.users.write() {
            m.insert(id, (Instant::now(), v));
        }
        Ok(())
    }

    /// The effective system default (`auto` or a tag).
    pub async fn system_default(&self) -> String {
        if let Some((at, v)) = self.system.read().ok().and_then(|m| m.clone()) {
            if at.elapsed() < CACHE_TTL {
                return v;
            }
        }
        let v = uilang::resolve(Some(&self.store)).await;
        if let Ok(mut m) = self.system.write() {
            *m = Some((Instant::now(), v.clone()));
        }
        v
    }

    /// Store the system default (`auto`, a tag with a catalog, or "" = back to the lower layers).
    pub async fn set_system(&self, lang: &str) -> anyhow::Result<()> {
        let l = lang.trim();
        if !l.is_empty() && l != uilang::AUTO && match_supported(l, &supported()).is_none() {
            anyhow::bail!("Invalid language '{l}': no catalog for it");
        }
        uilang::save(&self.store, l)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if let Ok(mut m) = self.system.write() {
            *m = None;
        }
        Ok(())
    }
}

// ---- request middleware ----

fn query_param(q: Option<&str>, name: &str) -> Option<String> {
    q?.split('&').find_map(|kv| {
        kv.split_once('=')
            .filter(|(k, _)| *k == name)
            .map(|(_, v)| v.to_string())
    })
}

/// Decides the request's language, makes it the task's current one (templates and handlers read
/// it), and translates JSON error messages on the way out.
pub async fn middleware(
    State(app): State<crate::state::AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let user_id = crate::auth::AuthUser::from_request_parts(&mut parts, &())
        .await
        .ok()
        .map(|u| u.session.user_id)
        .filter(|id| *id != 0);
    let user = match user_id {
        Some(id) => app.auth.lang.user(id).await,
        None => String::new(),
    };
    let system = app.auth.lang.system_default().await;
    let accept = parts
        .headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let sup = supported();
    // the login page's picker: /login?lang=de
    let picked_now = (parts.method == Method::GET)
        .then(|| query_param(parts.uri.query(), "lang"))
        .flatten()
        .and_then(|l| match_supported(&l, &sup));
    let picked_cookie = crate::auth::request_cookies(&parts.headers)
        .into_iter()
        .find(|(k, _)| k == COOKIE)
        .map(|(_, v)| v)
        .unwrap_or_default();
    let picked = picked_now.clone().unwrap_or(picked_cookie);
    let lang = choose(
        &Inputs {
            user: &user,
            picked: &picked,
            system: &system,
            accept: &accept,
        },
        &sup,
    );
    let req = Request::from_parts(parts, body);
    let l2 = lang.clone();
    let mut resp = LANG
        .scope(lang.clone(), async move {
            let r = next.run(req).await;
            translate_response(r, &l2).await
        })
        .await;
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&lang) {
        h.insert(header::CONTENT_LANGUAGE, v);
    }
    h.append(
        header::VARY,
        HeaderValue::from_static("Accept-Language, Cookie"),
    );
    if let Some(p) = picked_now {
        if let Ok(v) = HeaderValue::from_str(&format!(
            "{COOKIE}={p}; Path=/; Max-Age=31536000; SameSite=Strict; HttpOnly"
        )) {
            h.append(header::SET_COOKIE, v);
        }
    }
    resp
}

async fn translate_response(resp: Response, lang: &str) -> Response {
    if lang == FALLBACK || !(resp.status().is_client_error() || resp.status().is_server_error()) {
        return resp;
    }
    let is_json = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if !is_json {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 1 << 20).await else {
        return Response::from_parts(parts, Body::empty());
    };
    let out = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(mut v) => {
            let mut changed = false;
            if let Some(msg) = v.get("error").and_then(|e| e.as_str()).map(String::from) {
                if let Some(t) = translate_message(lang, &msg) {
                    v["error"] = serde_json::Value::String(t);
                    changed = true;
                }
            }
            if changed {
                serde_json::to_vec(&v).unwrap_or_else(|_| bytes.to_vec())
            } else {
                bytes.to_vec()
            }
        }
        Err(_) => bytes.to_vec(),
    };
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(out))
}

// ---- Askama filters ----

/// Filters for templates; every module that defines a template struct has `use
/// crate::i18n::filters;` in scope.
pub mod filters {
    use std::fmt::Display;

    /// `{{ "nav-firewall"|t }}`
    pub fn t(key: &str) -> askama::Result<String> {
        Ok(super::tr(key))
    }

    /// `{{ "greeting"|t_with("name", user) }}` (the catalog message uses `{ $name }`)
    pub fn t_with<T: Display + ?Sized>(key: &str, name: &str, v: &T) -> askama::Result<String> {
        Ok(super::tr_with(key, &[(name, v.to_string())]))
    }

    /// The breadcrumb text of a page slug: `crumb-<slug>`, else the slug capitalised.
    pub fn crumb(page: &str) -> askama::Result<String> {
        let key = format!("crumb-{page}");
        let s = super::tr(&key);
        if s != key {
            return Ok(s);
        }
        let mut c = page.chars();
        Ok(match c.next() {
            Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            None => String::new(),
        })
    }

    /// `<html lang="{{ ""|lang_code }}">`
    pub fn lang_code(_: &str) -> askama::Result<String> {
        Ok(super::current())
    }

    /// Links that switch the page to each language (`/login?lang=de`), for the sign-in page
    /// (no session yet, so the choice is kept in a cookie): `{{ ""|lang_links|safe }}`
    pub fn lang_links(_: &str) -> askama::Result<String> {
        let cur = super::current();
        let mut out = String::new();
        for (code, name) in super::languages() {
            let name = name
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            let here = if code == cur {
                " aria-current=\"true\""
            } else {
                ""
            };
            out.push_str(&format!(
                "<a href=\"/login?lang={code}\" lang=\"{code}\" hreflang=\"{code}\"{here}>{name}</a>"
            ));
        }
        Ok(out)
    }

    /// The `js-*` messages as a JSON object, safe inside a `<script>` element:
    /// `window.PATRONUS_I18N = {{ ""|js_catalog|safe }};`
    pub fn js_catalog(_: &str) -> askama::Result<String> {
        Ok(super::js_catalog_json(&super::current()))
    }
}

/// The `js-*` messages of `lang` (English for what it lacks) as JSON.
pub fn js_catalog_json(lang: &str) -> String {
    let mut m = serde_json::Map::new();
    for line in CATALOGS[0]
        .1
        .lines()
        .filter(|l| !l.starts_with(char::is_whitespace))
    {
        if let Some((k, _)) = line.split_once(" =") {
            let k = k.trim();
            if k.starts_with("js-") {
                m.insert(
                    k.to_string(),
                    serde_json::Value::String(tr_in(lang, k, &[])),
                );
            }
        }
    }
    serde_json::to_string(&m)
        .unwrap_or_else(|_| "{}".into())
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_language_is_ordered_by_q() {
        let v = parse_accept_language("fr;q=0.5, de-AT, en;q=0.8, xx;q=0");
        let tags: Vec<&str> = v.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(tags, ["de-at", "en", "fr"]);
    }

    #[test]
    fn region_tags_use_the_primary_catalog() {
        let s = ["en", "de"];
        assert_eq!(match_supported("de-AT", &s).as_deref(), Some("de"));
        assert_eq!(match_supported("DE", &s).as_deref(), Some("de"));
        assert_eq!(match_supported("fr", &s), None);
    }

    #[test]
    fn order_user_then_picked_then_system_then_browser() {
        let s = ["en", "de"];
        let c = |user, picked, system, accept| {
            choose(
                &Inputs {
                    user,
                    picked,
                    system,
                    accept,
                },
                &s,
            )
        };
        assert_eq!(c("de", "en", "en", "en"), "de");
        assert_eq!(c("", "de", "en", "en"), "de");
        assert_eq!(c("", "", "de", "en"), "de");
        assert_eq!(c("", "", "auto", "de-DE,de;q=0.9"), "de");
        assert_eq!(c("", "", "auto", "fr"), "en");
        // a system default that has no catalog does not hide the browser's language
        assert_eq!(c("", "", "fr", "de"), "de");
        assert_eq!(c("xx", "", "auto", ""), "en");
    }

    #[test]
    fn catalogs_load_and_name_themselves() {
        let l = languages();
        assert_eq!(l[0].0, "en");
        assert!(l.iter().any(|(c, n)| *c == "de" && n == "Deutsch"));
    }

    #[test]
    fn missing_keys_fall_back_to_english_then_the_key() {
        assert_eq!(
            tr_in("de", "no-such-key-anywhere", &[]),
            "no-such-key-anywhere"
        );
        assert_eq!(
            tr_in("fr", "nav-firewall", &[]),
            tr_in("en", "nav-firewall", &[])
        );
    }

    #[test]
    fn error_messages_translate_with_their_variables() {
        // a fixed message
        assert_eq!(
            translate_message("de", "read-only account").as_deref(),
            Some("Schreibgeschütztes Konto")
        );
        // a message with a variable part
        let t = translate_message("de", "Invalid username: bob already exists").expect("pattern");
        assert!(t.contains("bob"), "{t}");
        assert_ne!(t, "Invalid username: bob already exists");
        // English and unknown messages are left alone
        assert_eq!(translate_message("en", "read-only account"), None);
        assert_eq!(translate_message("de", "something nobody catalogued"), None);
    }

    #[test]
    fn js_catalog_cannot_close_the_script_element() {
        let j = js_catalog_json("de");
        assert!(!j.contains('<') && !j.contains('>'));
        assert!(j.starts_with('{'));
    }
}
