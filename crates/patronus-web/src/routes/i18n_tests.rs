//! Languages end to end through the real router: the sign-in page, the menu, API error messages,
//! the account's own choice and the system default.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt;

async fn app() -> (axum::Router, String) {
    let dir = std::env::temp_dir().join(format!("patronus-web-i18n-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = std::sync::Arc::new(
        patronus_config::ConfigStore::open(dir.join("config.db"))
            .await
            .unwrap(),
    );
    let state = crate::AppState::new(
        store,
        std::sync::Arc::new(crate::state::firewall::NoopApplier),
    )
    .await
    .unwrap();
    let pw = "I18n-Test-Passw0rd!".to_string();
    state
        .auth
        .user_store
        .provision_admin(Some(pw.clone()), &dir.join("pw"))
        .await
        .unwrap();
    let ws = std::sync::Arc::new(crate::WsBroadcaster::new());
    (super::build_router(state, ws), pw)
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Reply {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    let r = app
        .clone()
        .oneshot(
            b.body(
                body.map(|s| Body::from(s.to_string()))
                    .unwrap_or_else(Body::empty),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let status = r.status();
    let headers = r.headers().clone();
    let bytes = axum::body::to_bytes(r.into_body(), 8 << 20).await.unwrap();
    Reply {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).to_string(),
    }
}

async fn login(app: &axum::Router, pw: &str, lang: &str) -> String {
    let body = format!(r#"{{"username":"admin","password":"{pw}"}}"#);
    let r = send(
        app,
        Method::POST,
        "/api/auth/login",
        &[("accept-language", lang)],
        Some(&body),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    r.headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("session_id="))
        .expect("session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn sign_in_page_follows_the_browser_then_the_picked_language() {
    let (app, _) = app().await;
    let en = send(&app, Method::GET, "/login", &[], None).await;
    assert!(en.body.contains("Sign In") && en.body.contains("lang=\"en\""));
    assert_eq!(en.headers[header::CONTENT_LANGUAGE], "en");

    let de = send(
        &app,
        Method::GET,
        "/login",
        &[("accept-language", "de-DE,de;q=0.9,en;q=0.5")],
        None,
    )
    .await;
    assert!(
        de.body.contains("Anmelden") && de.body.contains("Benutzername"),
        "{}",
        de.body
    );
    assert!(de.body.contains("lang=\"de\""));
    assert!(!de.body.contains(">Sign In<"));
    assert_eq!(de.headers[header::CONTENT_LANGUAGE], "de");

    // no catalog for the browser's language: English
    let fr = send(
        &app,
        Method::GET,
        "/login",
        &[("accept-language", "fr-FR")],
        None,
    )
    .await;
    assert!(fr.body.contains("Sign In"));

    // the picker: ?lang=de sets a cookie that outranks the browser's header
    let pick = send(
        &app,
        Method::GET,
        "/login?lang=de",
        &[("accept-language", "en")],
        None,
    )
    .await;
    assert!(pick.body.contains("Anmelden"));
    let set = pick.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        set.starts_with("patronus_lang=de;") && set.contains("SameSite=Strict"),
        "{set}"
    );
    let again = send(
        &app,
        Method::GET,
        "/login",
        &[("cookie", "patronus_lang=de"), ("accept-language", "en")],
        None,
    )
    .await;
    assert!(again.body.contains("Anmelden"));
    // junk is ignored, nothing is set
    let junk = send(&app, Method::GET, "/login?lang=../../etc", &[], None).await;
    assert!(junk.body.contains("Sign In") && junk.headers.get(header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn api_error_messages_are_translated_and_codes_stay() {
    let (app, pw) = app().await;
    let en = send(&app, Method::GET, "/api/status", &[], None).await;
    assert_eq!(en.status, StatusCode::UNAUTHORIZED);
    assert!(en.body.contains("authentication required"));

    let de = send(
        &app,
        Method::GET,
        "/api/status",
        &[("accept-language", "de")],
        None,
    )
    .await;
    assert_eq!(de.status, StatusCode::UNAUTHORIZED);
    assert!(de.body.contains("Anmeldung erforderlich"), "{}", de.body);
    assert_eq!(de.headers[header::CONTENT_LANGUAGE], "de");

    let bad = r#"{"username":"admin","password":"wrong-password-123"}"#;
    let de = send(
        &app,
        Method::POST,
        "/api/auth/login",
        &[("accept-language", "de")],
        Some(bad),
    )
    .await;
    assert_eq!(de.status, StatusCode::UNAUTHORIZED);
    assert!(
        de.body
            .contains("Ungültiger Benutzername oder ungültiges Passwort"),
        "{}",
        de.body
    );

    // an unknown message is never mangled
    let cookie = login(&app, &pw, "en").await;
    let r = send(
        &app,
        Method::PUT,
        "/api/i18n/me",
        &[("cookie", &cookie), ("accept-language", "de")],
        Some(r#"{"language":"xx"}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let j: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(j["code"], "err-bad-language");
    assert!(
        j["error"]
            .as_str()
            .unwrap()
            .contains("Ungültige Sprache 'xx'"),
        "{j}"
    );
}

#[tokio::test]
async fn account_choice_beats_the_browser_and_the_system_default() {
    let (app, pw) = app().await;
    let cookie = login(&app, &pw, "en").await;
    let h = |extra: &'static str| -> Vec<(&'static str, String)> {
        vec![
            ("cookie", cookie.clone()),
            ("accept-language", extra.to_string()),
        ]
    };
    let get = |uri: &'static str, accept: &'static str| {
        let app = app.clone();
        let hh = h(accept);
        async move {
            let hv: Vec<(&str, &str)> = hh.iter().map(|(k, v)| (*k, v.as_str())).collect();
            send(&app, Method::GET, uri, &hv, None).await
        }
    };

    // English account, English menu
    let sys = get("/system", "en").await;
    assert_eq!(sys.status, StatusCode::OK);
    assert!(sys.body.contains("Security") && sys.body.contains("Device segmentation"));

    // the account picks German: the menu, the language card and the breadcrumb follow
    let hv = h("en");
    let hv: Vec<(&str, &str)> = hv.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let r = send(
        &app,
        Method::PUT,
        "/api/i18n/me",
        &hv,
        Some(r#"{"language":"de"}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let sys = get("/system", "en").await;
    for want in [
        "Sicherheit",
        "Gerätesegmentierung",
        "Hochverfügbarkeit",
        "Systemvorgabe für die Sprache",
        "Dunkelmodus umschalten",
    ] {
        assert!(sys.body.contains(want), "German /system lacks {want:?}");
    }
    assert!(!sys.body.contains(">Security<"));
    assert!(sys.body.contains("<html lang=\"de\">"));
    // the same account asking for an API error in a different Accept-Language still gets its own
    let st = send(&app, Method::GET, "/api/i18n", &hv, None).await;
    let j: serde_json::Value = serde_json::from_str(&st.body).unwrap();
    assert_eq!(j["current"], "de");
    assert_eq!(j["user"], "de");
    assert_eq!(j["available"].as_array().unwrap().len(), 2);

    // back to the system default: the browser's language applies again
    let r = send(
        &app,
        Method::PUT,
        "/api/i18n/me",
        &hv,
        Some(r#"{"language":""}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let sys = get("/system", "en").await;
    assert!(sys.body.contains(">Security<"));

    // the system default: a language for everyone who has no choice of their own
    let r = send(
        &app,
        Method::PUT,
        "/api/i18n/system",
        &hv,
        Some(r#"{"language":"de"}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let anon = send(
        &app,
        Method::GET,
        "/login",
        &[("accept-language", "en")],
        None,
    )
    .await;
    assert!(
        anon.body.contains("Anmelden"),
        "system default applies to the sign-in page too"
    );
    let r = send(
        &app,
        Method::PUT,
        "/api/i18n/system",
        &hv,
        Some(r#"{"language":"auto"}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let anon = send(
        &app,
        Method::GET,
        "/login",
        &[("accept-language", "en")],
        None,
    )
    .await;
    assert!(anon.body.contains("Sign In"));
    // a tag that is no language tag at all
    let r = send(
        &app,
        Method::PUT,
        "/api/i18n/system",
        &hv,
        Some(r#"{"language":"!!"}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}
