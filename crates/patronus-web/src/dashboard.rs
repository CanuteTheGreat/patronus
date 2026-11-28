//! The dashboard's widgets: a registry (one line per widget) and the
//! per-user layout resolved against it.
//!
//! Adding a widget (another lane's "smart" or "ups" card): add ONE line to
//! [`REGISTRY`] and one `{% else if w.id == "<id>" %}{% include ... %}` branch
//! in `templates/dashboard.html`. Everything else (the layout store, the
//! customize mode, the API validation, defaults for users who never
//! customized, new widgets showing up for users who did) is generic.
//!
//! A layout is `{"v":1,"widgets":[{"id":"internet","on":true}, ...]}` in
//! display order. Reading drops ids the registry no longer knows (and ids this
//! user's role or this build cannot show), and puts widgets the layout never
//! heard of in at their default position, so a layout survives upgrades.

use crate::auth::UserRole;
use serde::{Deserialize, Serialize};

/// Who may see a widget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinRole {
    ReadOnly,
    Operator,
    Admin,
}

impl MinRole {
    fn allows(self, role: UserRole) -> bool {
        let rank = |r: UserRole| match r {
            UserRole::ReadOnly => 0,
            UserRole::Operator => 1,
            UserRole::Admin => 2,
        };
        let need = match self {
            MinRole::ReadOnly => 0,
            MinRole::Operator => 1,
            MinRole::Admin => 2,
        };
        rank(role) >= need
    }
}

/// Build/device condition for a widget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Always,
    /// Only on an access point (not on the main router).
    AccessPoint,
    /// Only when this build has at least one of these Cargo features.
    AnyFeature(&'static [&'static str]),
    /// Only on the main router (an access point forwards nothing: no rules, leases or tunnels of its own).
    Router,
    /// [`Gate::Router`] and [`Gate::AnyFeature`] together.
    RouterAnyFeature(&'static [&'static str]),
}

#[derive(Debug, Clone, Copy)]
pub struct WidgetDef {
    /// Stable id: stored in layouts, never renamed.
    pub id: &'static str,
    pub title: &'static str,
    pub default_on: bool,
    /// Spans the whole row (tables and lists) instead of one tile.
    pub wide: bool,
    pub min_role: MinRole,
    pub gate: Gate,
}

const fn w(
    id: &'static str,
    title: &'static str,
    default_on: bool,
    wide: bool,
    min_role: MinRole,
    gate: Gate,
) -> WidgetDef {
    WidgetDef {
        id,
        title,
        default_on,
        wide,
        min_role,
        gate,
    }
}

const VPN_FEATURES: &[&str] = &["wireguard", "ipsec", "openvpn", "l2tp"];

/// Default order = this order. ONE line per widget.
pub const REGISTRY: &[WidgetDef] = &[
    w(
        "ap-uplink",
        "Access point",
        true,
        true,
        MinRole::ReadOnly,
        Gate::AccessPoint,
    ),
    w(
        "internet",
        "Internet",
        true,
        false,
        MinRole::ReadOnly,
        Gate::Always,
    ),
    w(
        "interfaces",
        "Interfaces",
        true,
        false,
        MinRole::ReadOnly,
        Gate::Always,
    ),
    w(
        "firewall-rules",
        "Active firewall rules",
        true,
        false,
        MinRole::ReadOnly,
        Gate::Router,
    ),
    w(
        "vpn",
        "VPN connections",
        true,
        false,
        MinRole::ReadOnly,
        Gate::RouterAnyFeature(VPN_FEATURES),
    ),
    w(
        "dhcp",
        "DHCP leases",
        true,
        false,
        MinRole::ReadOnly,
        Gate::Router,
    ),
    w(
        "traffic",
        "Traffic",
        true,
        false,
        MinRole::ReadOnly,
        Gate::Always,
    ),
    w(
        "system",
        "System",
        true,
        false,
        MinRole::ReadOnly,
        Gate::Always,
    ),
    w(
        "activity",
        "System activity",
        false,
        true,
        MinRole::ReadOnly,
        Gate::Always,
    ),
    w(
        "network-interfaces",
        "Network interfaces",
        true,
        true,
        MinRole::ReadOnly,
        Gate::Always,
    ),
    w(
        "services",
        "Services",
        true,
        true,
        MinRole::ReadOnly,
        Gate::Always,
    ),
];

fn feature_built(name: &str) -> bool {
    (name == "wireguard" && cfg!(feature = "wireguard"))
        || (name == "ipsec" && cfg!(feature = "ipsec"))
        || (name == "openvpn" && cfg!(feature = "openvpn"))
        || (name == "l2tp" && cfg!(feature = "l2tp"))
}

/// What decides which widgets exist for the viewer.
#[derive(Debug, Clone, Copy)]
pub struct Viewer {
    pub role: UserRole,
    pub access_point: bool,
}

pub fn eligible(d: &WidgetDef, v: Viewer) -> bool {
    d.min_role.allows(v.role)
        && match d.gate {
            Gate::Always => true,
            Gate::AccessPoint => v.access_point,
            Gate::AnyFeature(fs) => fs.iter().any(|f| feature_built(f)),
            Gate::Router => !v.access_point,
            Gate::RouterAnyFeature(fs) => !v.access_point && fs.iter().any(|f| feature_built(f)),
        }
}

pub fn find(id: &str) -> Option<&'static WidgetDef> {
    REGISTRY.iter().find(|d| d.id == id)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedWidget {
    pub id: String,
    pub on: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Layout {
    #[serde(default = "one")]
    pub v: u32,
    pub widgets: Vec<SavedWidget>,
}

fn one() -> u32 {
    1
}

/// Most entries a saved layout may have.
pub const MAX_WIDGETS: usize = 64;

impl Layout {
    /// The layout a user who never customized gets.
    pub fn default_for(v: Viewer) -> Layout {
        Layout {
            v: 1,
            widgets: REGISTRY
                .iter()
                .filter(|d| eligible(d, v))
                .map(|d| SavedWidget {
                    id: d.id.into(),
                    on: d.default_on,
                })
                .collect(),
        }
    }

    /// Check a layout a client wants to save: every id must be a registry id,
    /// no id twice, not absurdly many. Returns the layout as it will be
    /// stored (ids this viewer cannot see are dropped).
    pub fn validate(self, v: Viewer) -> Result<Layout, String> {
        if self.widgets.len() > MAX_WIDGETS {
            return Err(format!("too many widgets (at most {MAX_WIDGETS})"));
        }
        let mut seen = std::collections::HashSet::new();
        let mut unknown = Vec::new();
        for s in &self.widgets {
            if find(&s.id).is_none() {
                unknown.push(s.id.clone());
            } else if !seen.insert(s.id.clone()) {
                return Err(format!("widget {:?} is listed twice", s.id));
            }
        }
        if !unknown.is_empty() {
            let shown: Vec<String> = unknown
                .iter()
                .take(5)
                .map(|u| u.chars().take(40).collect())
                .collect();
            return Err(format!("unknown widget id(s): {}", shown.join(", ")));
        }
        Ok(Layout {
            v: 1,
            widgets: self
                .widgets
                .into_iter()
                .filter(|s| find(&s.id).is_some_and(|d| eligible(d, v)))
                .collect(),
        })
    }

    /// The layout as the viewer sees it: unknown, ineligible and repeated ids
    /// dropped, widgets the layout never named inserted at their default
    /// position (after the nearest earlier registry widget that is present).
    pub fn resolve(saved: Option<Layout>, v: Viewer) -> Layout {
        let Some(saved) = saved else {
            return Layout::default_for(v);
        };
        let mut out: Vec<SavedWidget> = Vec::new();
        for s in saved.widgets {
            if find(&s.id).is_some_and(|d| eligible(d, v)) && !out.iter().any(|o| o.id == s.id) {
                out.push(s);
            }
        }
        let elig: Vec<&WidgetDef> = REGISTRY.iter().filter(|d| eligible(d, v)).collect();
        for (i, d) in elig.iter().enumerate() {
            if out.iter().any(|o| o.id == d.id) {
                continue;
            }
            let at = elig[..i]
                .iter()
                .rev()
                .find_map(|p| out.iter().position(|o| o.id == p.id))
                .map_or(0, |p| p + 1);
            out.insert(
                at,
                SavedWidget {
                    id: d.id.into(),
                    on: d.default_on,
                },
            );
        }
        Layout { v: 1, widgets: out }
    }

    pub fn is_default_for(&self, v: Viewer) -> bool {
        *self == Layout::default_for(v)
    }
}

/// Parse a stored document; garbage reads as "no layout" (the default).
pub fn parse_stored(json: &str) -> Option<Layout> {
    serde_json::from_str(json).ok()
}

/// One widget of a rendered page.
#[derive(Debug, Clone)]
pub struct DashWidget {
    pub id: &'static str,
    pub title: &'static str,
    pub wide: bool,
}

impl From<&WidgetDef> for DashWidget {
    fn from(d: &WidgetDef) -> Self {
        DashWidget {
            id: d.id,
            title: d.title,
            wide: d.wide,
        }
    }
}

/// Split a resolved layout into the widgets to draw (in order) and the ones
/// switched off (for the "add" list).
pub fn split(layout: &Layout) -> (Vec<DashWidget>, Vec<DashWidget>) {
    let mut on = Vec::new();
    let mut off = Vec::new();
    for s in &layout.widgets {
        if let Some(d) = find(&s.id) {
            if s.on {
                on.push(d.into());
            } else {
                off.push(d.into());
            }
        }
    }
    (on, off)
}

/// Every widget the viewer may see, all on (tests and previews).
pub fn all_on(v: Viewer) -> Vec<DashWidget> {
    REGISTRY
        .iter()
        .filter(|d| eligible(d, v))
        .map(DashWidget::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADMIN: Viewer = Viewer {
        role: UserRole::Admin,
        access_point: false,
    };
    const AP: Viewer = Viewer {
        role: UserRole::ReadOnly,
        access_point: true,
    };

    fn ids(l: &Layout) -> Vec<&str> {
        l.widgets.iter().map(|w| w.id.as_str()).collect()
    }

    fn sw(id: &str, on: bool) -> SavedWidget {
        SavedWidget { id: id.into(), on }
    }

    #[test]
    fn registry_ids_are_unique_and_stable_looking() {
        let mut seen = std::collections::HashSet::new();
        for d in REGISTRY {
            assert!(seen.insert(d.id), "duplicate id {}", d.id);
            assert!(
                d.id.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{}",
                d.id
            );
            assert!(!d.title.is_empty());
        }
    }

    #[test]
    fn default_layout_follows_the_registry_and_the_viewer() {
        let d = Layout::resolve(None, ADMIN);
        assert_eq!(ids(&d)[0], "internet", "no access-point card on a router");
        assert!(!ids(&d).contains(&"ap-uplink"));
        assert!(
            d.widgets.iter().any(|w| w.id == "activity" && !w.on),
            "activity is off by default"
        );
        assert!(Layout::resolve(None, AP)
            .widgets
            .iter()
            .any(|w| w.id == "ap-uplink"));
        let ap = Layout::resolve(None, AP);
        for router_only in ["firewall-rules", "dhcp", "vpn"] {
            assert!(!ids(&ap).contains(&router_only), "{router_only} on an access point");
        }
        assert!(d.is_default_for(ADMIN));
    }

    #[test]
    fn unknown_duplicate_and_ineligible_ids_are_dropped_on_read() {
        let saved = Layout {
            v: 1,
            widgets: vec![
                sw("system", true),
                sw("from-the-future", true),
                sw("system", false),
                sw("ap-uplink", true),
                sw("internet", false),
            ],
        };
        let r = Layout::resolve(Some(saved), ADMIN);
        let at = |id: &str| ids(&r).iter().position(|x| *x == id).unwrap();
        assert_eq!(ids(&r)[0], "system");
        assert!(at("system") < at("internet"), "{:?}", ids(&r));
        assert_eq!(r.widgets.iter().filter(|w| w.id == "system").count(), 1);
        assert!(
            r.widgets.iter().find(|w| w.id == "system").unwrap().on,
            "first copy wins"
        );
        assert!(r
            .widgets
            .iter()
            .all(|w| w.id != "from-the-future" && w.id != "ap-uplink"));
        assert!(!r.widgets.iter().find(|w| w.id == "internet").unwrap().on);
    }

    #[test]
    fn a_widget_added_later_appears_at_its_default_position() {
        // a layout saved before "interfaces", "dhcp" and "activity" existed
        let saved = Layout {
            v: 1,
            widgets: vec![
                sw("services", true),
                sw("internet", true),
                sw("firewall-rules", true),
                sw("system", true),
            ],
        };
        let r = Layout::resolve(Some(saved), ADMIN);
        let i = |id: &str| ids(&r).iter().position(|x| *x == id).unwrap();
        assert!(i("interfaces") == i("internet") + 1, "{:?}", ids(&r));
        assert!(i("activity") == i("system") + 1);
        assert!(
            !r.widgets[i("activity")].on,
            "new widgets keep their default on/off"
        );
        assert!(r.widgets[i("interfaces")].on);
        // the user's own order is untouched
        assert_eq!(ids(&r)[0], "services");
    }

    #[test]
    fn saving_rejects_unknown_and_repeated_ids_and_keeps_order() {
        let ok = Layout {
            v: 1,
            widgets: vec![sw("system", true), sw("internet", false)],
        };
        let stored = ok.clone().validate(ADMIN).unwrap();
        assert_eq!(stored, ok);
        let e = Layout {
            v: 1,
            widgets: vec![sw("system", true), sw("nope", true)],
        }
        .validate(ADMIN)
        .unwrap_err();
        assert!(e.contains("nope"), "{e}");
        assert!(Layout {
            v: 1,
            widgets: vec![sw("system", true), sw("system", true)]
        }
        .validate(ADMIN)
        .is_err());
        let many = Layout {
            v: 1,
            widgets: (0..=MAX_WIDGETS)
                .map(|i| sw(&format!("w{i}"), true))
                .collect(),
        };
        assert!(many.validate(ADMIN).is_err());
        // an id this viewer cannot see is accepted but not stored
        let st = Layout {
            v: 1,
            widgets: vec![sw("ap-uplink", true), sw("system", true)],
        }
        .validate(ADMIN)
        .unwrap();
        assert_eq!(ids(&st), ["system"]);
    }

    #[test]
    fn garbage_in_the_store_reads_as_no_layout() {
        assert!(parse_stored("not json").is_none());
        assert!(parse_stored("{}").is_none());
        assert!(parse_stored(r#"{"v":1,"widgets":[{"id":"system","on":true}]}"#).is_some());
    }

    #[test]
    fn split_gives_drawn_and_hidden_widgets() {
        let l = Layout {
            v: 1,
            widgets: vec![sw("system", true), sw("internet", false)],
        };
        let (on, off) = split(&l);
        assert_eq!(on.iter().map(|w| w.id).collect::<Vec<_>>(), ["system"]);
        assert_eq!(off[0].id, "internet");
    }
}
