//! The pages clients see: splash/login, signed-in status with logout, the
//! signed-out page, and the voucher print sheet. Every visible text comes from
//! the zone's settings (`patronus_network::captive::PageText`); values are
//! HTML-escaped. Light and dark follow the device (`prefers-color-scheme`),
//! the layout works from a 320 px phone up, controls have labels and visible
//! focus, and colours meet WCAG AA contrast.

use patronus_network::captive::{PageText, Zone};

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

/// `#rrggbb` -> relative luminance (WCAG 2.x).
fn luminance(hex: &str) -> Option<f64> {
    if hex.len() != 7 || !hex.starts_with('#') {
        return None;
    }
    let ch = |i: usize| -> Option<f64> {
        let v = f64::from(u8::from_str_radix(&hex[i..i + 2], 16).ok()?) / 255.0;
        Some(if v <= 0.03928 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        })
    };
    Some(0.2126 * ch(1)? + 0.7152 * ch(3)? + 0.0722 * ch(5)?)
}

/// Text colour on an accent background: whichever of black/white has the
/// higher contrast (so any accent the admin picks stays readable).
pub fn on_accent(accent: &str) -> &'static str {
    match luminance(accent) {
        Some(l) if (l + 0.05) / 0.05 > 1.05 / (l + 0.05) => "#000000",
        Some(_) => "#ffffff",
        None => "#ffffff",
    }
}

const STYLE: &str = r#"
:root{color-scheme:light dark;--bg:#f4f6f8;--card:#ffffff;--fg:#14181f;--muted:#4a5260;--line:#c5ccd6;--accent:#1d4ed8;--on-accent:#ffffff;--err-bg:#fde8e8;--err-fg:#8a1c1c;--ok-bg:#e6f4ea;--ok-fg:#14532d}
@media (prefers-color-scheme:dark){:root{--bg:#0f141b;--card:#18202b;--fg:#e8edf3;--muted:#b4bfcc;--line:#3a4656;--accent:#60a5fa;--on-accent:#0b1220;--err-bg:#3b1414;--err-fg:#fecaca;--ok-bg:#0f2e1c;--ok-fg:#bbf7d0}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:16px}
main{width:100%;max-width:420px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px}
h1{font-size:1.5rem;margin:0 0 8px}
p{margin:0 0 16px;color:var(--muted)}
label{display:block;font-weight:600;margin:12px 0 4px}
input[type=text],input[type=password]{width:100%;font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);min-height:44px}
.check{display:flex;gap:10px;align-items:flex-start;margin:16px 0;font-weight:400}
.check input{width:22px;height:22px;margin:2px 0 0;flex:none}
button{width:100%;min-height:48px;margin-top:16px;font:inherit;font-weight:700;border:0;border-radius:8px;background:var(--accent);color:var(--on-accent);cursor:pointer}
button:focus-visible,input:focus-visible,a:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.err{background:var(--err-bg);color:var(--err-fg);padding:10px 12px;border-radius:8px;margin:0 0 12px}
.ok{background:var(--ok-bg);color:var(--ok-fg);padding:10px 12px;border-radius:8px;margin:0 0 12px}
dl{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;margin:0 0 8px}
dt{color:var(--muted)}dd{margin:0;font-variant-numeric:tabular-nums}
"#;

fn shell(p: &PageText, body: &str) -> String {
    let accent = if p.accent.is_empty() {
        String::new()
    } else {
        // validated #rrggbb (patronus_network::captive), both schemes
        format!(
            "<style>:root{{--accent:{a};--on-accent:{o}}}@media (prefers-color-scheme:dark){{:root{{--accent:{a};--on-accent:{o}}}}}</style>",
            a = esc(&p.accent),
            o = on_accent(&p.accent)
        )
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex\"><title>{}</title><style>{STYLE}</style>{accent}</head>\
         <body><main>{body}</main></body></html>",
        esc(&p.title)
    )
}

/// The splash page with the zone's login form.
pub fn splash(z: &Zone, action: &str, redirurl: &str, error: bool) -> String {
    let p = &z.page;
    let mut b = format!("<h1>{}</h1><p>{}</p>", esc(&p.title), esc(&p.welcome));
    if error {
        b.push_str(&format!(
            "<div class=\"err\" role=\"alert\" id=\"cp-error\">{}</div>",
            esc(&p.error)
        ));
    }
    b.push_str(&format!(
        "<form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"redirurl\" value=\"{}\">",
        esc(action),
        esc(redirurl)
    ));
    match z.auth.as_str() {
        "local" | "radius" => b.push_str(&format!(
            "<label for=\"cp-user\">{}</label><input type=\"text\" id=\"cp-user\" name=\"username\" autocomplete=\"username\" autocapitalize=\"none\" required>\
             <label for=\"cp-pass\">{}</label><input type=\"password\" id=\"cp-pass\" name=\"password\" autocomplete=\"current-password\" required>",
            esc(&p.user_label),
            esc(&p.password_label)
        )),
        "voucher" => b.push_str(&format!(
            "<label for=\"cp-voucher\">{}</label><input type=\"text\" id=\"cp-voucher\" name=\"voucher\" autocomplete=\"one-time-code\" autocapitalize=\"characters\" spellcheck=\"false\" required>",
            esc(&p.voucher_label)
        )),
        _ => {}
    }
    if z.terms_required {
        b.push_str(&format!(
            "<label class=\"check\"><input type=\"checkbox\" name=\"terms\" value=\"1\" id=\"cp-terms\" required> <span>{}</span></label>",
            esc(&p.terms)
        ));
    } else if !p.terms.is_empty() {
        b.push_str(&format!("<p>{}</p>", esc(&p.terms)));
    }
    b.push_str(&format!(
        "<button type=\"submit\" id=\"cp-login\">{}</button></form>",
        esc(&p.button)
    ));
    shell(p, &b)
}

fn mins(secs: i64) -> String {
    let m = (secs.max(0) + 59) / 60;
    if m >= 120 {
        format!("{} h {:02} min", m / 60, m % 60)
    } else {
        format!("{m} min")
    }
}

/// Signed in: remaining time and the logout button.
pub fn status(z: &Zone, logout_action: &str, left: Option<i64>, continue_to: &str) -> String {
    let p = &z.page;
    let mut b = format!(
        "<h1>{}</h1><div class=\"ok\" role=\"status\" id=\"cp-online\">{}</div>",
        esc(&p.title),
        esc(&p.success)
    );
    if let Some(l) = left {
        // a number and a unit only: no sentence to translate
        b.push_str(&format!(
            "<dl><dt>&#9201;</dt><dd id=\"cp-left\" data-seconds=\"{l}\">{}</dd></dl>",
            esc(&mins(l))
        ));
    }
    if !continue_to.is_empty() {
        b.push_str(&format!(
            "<p><a href=\"{}\" id=\"cp-continue\">{}</a></p>",
            esc(continue_to),
            esc(continue_to)
        ));
    }
    b.push_str(&format!(
        "<form method=\"post\" action=\"{}\"><button type=\"submit\" id=\"cp-logout\">{}</button></form>",
        esc(logout_action),
        esc(&p.logout)
    ));
    shell(p, &b)
}

/// After logout: the splash again (a fresh start).
pub fn signed_out(z: &Zone, action: &str) -> String {
    splash(z, action, "", false)
}

/// A page for a client that is not on any portal zone.
pub fn not_a_zone() -> String {
    // reached only by a request from outside every zone (a probe, an admin
    // from the LAN): no zone text exists to show
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>404</title></head><body><main><h1>404</h1></main></body></html>".into()
}

/// The printable voucher sheet: codes in a grid with the roll's minutes.
pub fn print_sheet(z: &Zone, roll: &str, minutes: i64, codes: &[String]) -> String {
    let p = &z.page;
    let cells: String = codes
        .iter()
        .map(|c| {
            format!(
                "<div class=\"v\"><div class=\"t\">{}</div><div class=\"c\">{}</div><div class=\"m\">{} &middot; {}</div></div>",
                esc(&p.title),
                esc(c),
                esc(&p.voucher_label),
                esc(&mins(minutes * 60))
            )
        })
        .collect();
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{} &middot; {}</title><style>\
         body{{font:14px system-ui,sans-serif;margin:12px;color:#000;background:#fff}}\
         .g{{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px}}\
         .v{{border:1px dashed #444;padding:10px;break-inside:avoid;text-align:center}}\
         .t{{font-weight:700}}.c{{font:700 20px ui-monospace,monospace;letter-spacing:2px;margin:6px 0}}.m{{color:#333}}\
         @media print{{body{{margin:0}}}}</style></head><body><h1>{}</h1><div class=\"g\">{cells}</div></body></html>",
        esc(&p.title),
        esc(roll),
        esc(roll)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Map, Value};

    fn zone(auth: &str, title: &str) -> Zone {
        let mut r: Map<String, Value> = Map::new();
        r.insert("id".into(), json!(1));
        r.insert("name".into(), json!("z"));
        r.insert("interface".into(), json!("@lan"));
        r.insert("auth".into(), json!(auth));
        r.insert("page_title".into(), json!(title));
        r.insert("accent_color".into(), json!("#ffcc00"));
        patronus_network::captive::zone_from_row(&r)
    }

    #[test]
    fn splash_carries_only_zone_texts_escaped() {
        let z = zone("local", "Caf\u{e9} <b>&</b>");
        let h = splash(&z, "/login", "http://example.org/?a=1&b=\"2\"", true);
        assert!(h.contains("Caf\u{e9} &lt;b&gt;&amp;&lt;/b&gt;"));
        assert!(!h.contains("<b>&</b>"));
        assert!(h.contains("value=\"http://example.org/?a=1&amp;b=&quot;2&quot;\""));
        assert!(h.contains("name=\"username\"") && h.contains("name=\"password\""));
        assert!(h.contains("for=\"cp-user\">User name<"));
        assert!(h.contains("role=\"alert\""));
        assert!(h.contains("name=\"viewport\""));
        // yellow accent gets black text
        assert!(h.contains("--on-accent:#000000"));
        let v = splash(&zone("voucher", "x"), "/login", "", false);
        assert!(v.contains("name=\"voucher\"") && !v.contains("name=\"password\""));
        let n = splash(&zone("none", "x"), "/login", "", false);
        assert!(n.contains("name=\"terms\"") && !n.contains("name=\"voucher\""));
    }

    #[test]
    fn accent_text_contrast_is_aa() {
        for a in [
            "#000000", "#ffffff", "#1d4ed8", "#ffcc00", "#808080", "#22c55e",
        ] {
            let l = luminance(a).unwrap();
            let t = if on_accent(a) == "#000000" { 0.0 } else { 1.0 };
            let (hi, lo) = if l > t { (l, t) } else { (t, l) };
            assert!((hi + 0.05) / (lo + 0.05) >= 4.5, "{a}");
        }
    }

    #[test]
    fn status_and_sheet() {
        let z = zone("voucher", "Lobby");
        let s = status(&z, "/logout", Some(3601), "");
        assert!(
            s.contains("id=\"cp-logout\"") && !s.contains("1 h 01 min") && s.contains("61 min")
        );
        let sheet = print_sheet(&z, "roll-1", 90, &["AAAA2222".into(), "BBBB3333".into()]);
        assert_eq!(sheet.matches("class=\"v\"").count(), 2);
        assert!(sheet.contains("90 min"));
    }
}
