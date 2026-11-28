//! The effective Wi-Fi generation plan of one network (docs/WIFI-MODERN.md): what was asked for
//! (`seg_wifi_gen::GenSettings` + the channel width) against what the radio (`radio::RadioCaps`, probed with
//! `iw phy`) and the installed hostapd (`radio::HostapdCaps`, its build options) can really run.
//!
//! Rules:
//! - `auto` climbs to the newest generation both support; an explicit generation above that runs at the
//!   best supported one with a warning naming the missing piece (card or hostapd build), never claimed;
//! - a channel width the radio cannot carry at that generation is narrowed to the widest it can, with a warning;
//! - 6 GHz fails closed: no HE on 6 GHz, a hostapd without 802.11ax, or a regulatory domain that marks the
//!   block "no IR"/disabled (the US database marks 6 GHz passive-scan on Linux) stop the network with a
//!   message saying which;
//! - 6 GHz discovery frames are sent only when the driver advertises them;
//! - multi-link (MLO) needs Wi-Fi 7 on every link, a hostapd with AP MLD support, and finally the driver,
//!   which `iw` does not report: the applier tries it and falls back to one link (`mlo_failed`).
//!
//! With no radio information (no `iw`, a radio that is not there yet) nothing is narrowed and `auto` keeps
//! the pre-Wi-Fi 6 behaviour (HT, plus VHT at 80 MHz and wider on 5 GHz).

use crate::radio::{std_rank, HostapdCaps, RadioCaps};
use patronus_config::seg_wifi::Network;
use patronus_config::seg_wifi_gen::{band_name, Link};
use patronus_core::{Error, Result};

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Plan {
    /// effective generation: n | ac | ax | be
    pub standard: String,
    /// effective channel width (MHz)
    pub width: i64,
    /// 6 GHz discovery frames: (`probe` | `fils`, interval in TU)
    pub discovery: Option<(String, i64)>,
    /// HE BSS colour (1-63) when HE runs
    pub bss_color: Option<i64>,
    /// the extra multi-link links that will be tried
    pub links: Vec<Link>,
    /// why something runs below what was asked (shown as warnings)
    pub warnings: Vec<String>,
    /// what runs and why (shown as information)
    pub notes: Vec<String>,
}

fn err(m: impl std::fmt::Display) -> Error {
    Error::Network(format!("Wi-Fi: {m}"))
}

/// Human name of a generation.
pub fn std_name(s: &str) -> &'static str {
    match s {
        "n" => "Wi-Fi 4 (802.11n)",
        "ac" => "Wi-Fi 5 (802.11ac)",
        "ax" => "Wi-Fi 6 (802.11ax)",
        "be" => "Wi-Fi 7 (802.11be)",
        _ => "?",
    }
}

const STD: [&str; 4] = ["n", "ac", "ax", "be"];

/// A stable BSS colour from the network name (1-63): two of our networks rarely share one.
pub fn auto_color(name: &str) -> i64 {
    let h = name.bytes().fold(0x811c9dc5u32, |h, b| {
        (h ^ b as u32).wrapping_mul(0x01000193)
    });
    (h % 63) as i64 + 1
}

/// The newest generation the installed hostapd can run, and why it stops there.
fn hostapd_max(h: &HostapdCaps) -> (usize, &'static str) {
    if h.be {
        (3, "")
    } else if h.ax {
        (2, "the installed hostapd was built without 802.11be (Wi-Fi 7 needs hostapd 2.11 or newer built with CONFIG_IEEE80211BE, as Gentoo's net-wireless/hostapd-2.11+ is)")
    } else {
        (
            1,
            "the installed hostapd was built without 802.11ax (CONFIG_IEEE80211AX)",
        )
    }
}

/// Resolve the plan of `n` on a radio. `caps` = `None` when the radio could not be probed.
pub fn plan(n: &Network, caps: Option<&RadioCaps>, h: &HostapdCaps) -> Result<Plan> {
    let band = n.band.as_str();
    let g = &n.gen;
    let mut warnings = Vec::new();
    let mut notes = Vec::new();
    let (hmax, hwhy) = hostapd_max(h);
    let want = if g.standard == "auto" {
        3
    } else {
        std_rank(&g.standard)
    };
    let (mut eff, width) = match caps {
        None => {
            // unknown radio: what was asked (auto = the pre-Wi-Fi 6 behaviour), capped by hostapd only
            let base = if g.standard != "auto" {
                want
            } else if band == "6g" {
                2
            } else if band == "5g" && n.chan.width >= 80 {
                1
            } else {
                0
            };
            (base.min(hmax), n.chan.width)
        }
        Some(c) => {
            if !c.ap {
                return Err(err(format!(
                    "{}: this radio has no access point mode",
                    n.ifname
                )));
            }
            let Some(b) = c.band(band) else {
                return Err(err(format!(
                    "{}: this radio has no {} band (it has {})",
                    n.ifname,
                    band_name(band),
                    c.bands
                        .iter()
                        .map(|x| band_name(&x.band))
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            };
            let rmax = std_rank(c.max_standard(band));
            let mut e = want.min(rmax).min(hmax);
            if band == "2g" && e == 1 {
                e = 0; // Wi-Fi 5 does not exist on 2.4 GHz
            }
            if g.standard != "auto" && e < want {
                let why = if rmax < want.min(hmax) || hmax >= want {
                    format!(
                        "this radio offers {} at most on {}",
                        std_name(STD[rmax]),
                        band_name(band)
                    )
                } else {
                    hwhy.to_string()
                };
                warnings.push(format!(
                    "asked for {}, running {}: {why}",
                    std_name(&g.standard),
                    std_name(STD[e])
                ));
            }
            if band == "6g" && !b.he {
                return Err(err(format!(
                    "{}: this radio cannot run an access point on 6 GHz (no 802.11ax access point capability there)",
                    n.ifname
                )));
            }
            let maxw = c.max_width(band, STD[e]);
            let mut w = n.chan.width;
            if w > maxw && maxw > 0 {
                warnings.push(format!(
                    "asked for {w} MHz, running {maxw} MHz: the widest this radio carries on {} with {}",
                    band_name(band),
                    std_name(STD[e])
                ));
                w = maxw;
            }
            (e, w)
        }
    };
    if band == "6g" && eff < 2 {
        return Err(err(format!("{}: 6 GHz needs 802.11ax and {hwhy}", n.name)));
    }
    if band == "2g" && eff == 1 {
        eff = 0;
    }
    // 6 GHz regulatory: every 20 MHz channel of the block must allow an access point to transmit
    if band == "6g" {
        if let Some(c) = caps {
            if n.channel != 0 {
                let block = patronus_config::seg_wifi_chan::block_of(band, n.channel, width);
                let blocked: Vec<i64> = block
                    .iter()
                    .copied()
                    .filter(|x| c.usable(band, *x) != Some(true))
                    .collect();
                if !blocked.is_empty() {
                    return Err(err(six_ghz_regulatory(&n.country, &blocked)));
                }
            } else if !c.ap_band("6g") {
                return Err(err(six_ghz_regulatory(&n.country, &[])));
            }
        }
    }
    let standard = STD[eff].to_string();
    if g.standard == "auto" && caps.is_some() {
        notes.push(format!(
            "running {}: the newest this radio and the installed hostapd support on {}",
            std_name(&standard),
            band_name(band)
        ));
    }
    // 6 GHz discovery
    let mut discovery = None;
    if band == "6g" && g.discovery != "off" {
        let (probe, fils) = caps.map_or((false, false), |c| (c.unsol_probe, c.fils_discovery));
        let pick = match g.discovery.as_str() {
            "probe" if probe => Some("probe"),
            "fils" if fils => Some("fils"),
            "auto" if probe => Some("probe"),
            "auto" if fils => Some("fils"),
            _ => None,
        };
        match pick {
            Some(p) => discovery = Some((p.to_string(), g.discovery_interval)),
            None => {
                let m = "this driver sends neither unsolicited probe responses nor FILS discovery frames: 6 GHz devices find the network by scanning its preferred scanning channel, or through the reduced neighbour report of a 2.4/5 GHz network on the same radio";
                if g.discovery == "auto" {
                    notes.push(m.into());
                } else {
                    warnings.push(format!("discovery {}: {m}", g.discovery));
                }
            }
        }
    }
    let bss_color = (eff >= 2).then(|| {
        if g.bss_color > 0 {
            g.bss_color
        } else {
            auto_color(&n.name)
        }
    });
    // multi-link
    let mut links = Vec::new();
    let asked = g.links();
    if !asked.is_empty() {
        if eff < 3 {
            warnings.push(format!(
                "multi-link (MLO) needs Wi-Fi 7 on every link: running one link ({})",
                std_name(&standard)
            ));
        } else if !h.mld {
            warnings.push("multi-link (MLO): the installed hostapd has no AP MLD support (hostapd 2.11 or newer with CONFIG_IEEE80211BE): running one link".into());
        } else {
            for l in asked {
                let ok = caps.is_none_or(|c| {
                    c.band(&l.band).is_some_and(|b| b.eht)
                        && (l.band != "6g" || c.ap_band("6g"))
                        && c.max_width(&l.band, "be") >= l.width
                });
                if ok {
                    links.push(l);
                } else {
                    warnings.push(format!(
                        "multi-link: this radio cannot add a Wi-Fi 7 link on {} at {} MHz (channel {}): left out",
                        band_name(&l.band),
                        l.width,
                        l.channel
                    ));
                }
            }
        }
    }
    Ok(Plan {
        standard,
        width,
        discovery,
        bss_color,
        links,
        warnings,
        notes,
    })
}

/// The fail-closed message of a 6 GHz block the regulatory domain does not open for an access point.
pub fn six_ghz_regulatory(country: &str, blocked: &[i64]) -> String {
    let which = if blocked.is_empty() {
        "no 6 GHz channel".to_string()
    } else {
        format!(
            "channel{} {}",
            if blocked.len() == 1 { "" } else { "s" },
            blocked
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    format!(
        "6 GHz: the regulatory database for country {country} allows {which} for an access point (marked no-IR or disabled; e.g. wireless-regdb marks US 6 GHz passive-scan, so Linux refuses to start a 6 GHz access point there unless the driver manages its own regulatory domain). The network stays off rather than transmitting where it may not. Pick channels the database opens for {country}, or use 5 GHz."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radio::parse_caps;
    use patronus_config::seg_wifi_chan::ChanSettings;
    use patronus_config::seg_wifi_gen::GenSettings;

    const DE: &str = include_str!("testdata/iw-phy-hwsim-de.txt");
    const WORLD: &str = include_str!("testdata/iw-phy-hwsim-world.txt");
    const WIFI5: &str = include_str!("testdata/iw-phy-wifi5.txt");

    fn net(
        band: &str,
        ch: i64,
        width: i64,
        sec: &str,
        f: impl FnOnce(&mut GenSettings),
    ) -> Network {
        let mut gen = GenSettings::default();
        f(&mut gen);
        Network {
            id: 1,
            name: "home".into(),
            ifname: "wlan0".into(),
            ssid: "s".into(),
            band: band.into(),
            channel: ch,
            chan: ChanSettings {
                width,
                ..Default::default()
            },
            gen,
            country: "DE".into(),
            security: sec.into(),
            segment: "@lan".into(),
            unknown_policy: "reject".into(),
            has_enrol_secret: false,
            enabled: true,
            restart_on_credential_change: true,
        }
    }

    #[test]
    fn auto_climbs_to_the_newest_both_support() {
        let c = parse_caps(DE);
        let p = plan(
            &net("5g", 36, 80, "wpa2", |_| {}),
            Some(&c),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert_eq!((p.standard.as_str(), p.width), ("be", 80));
        assert!(
            p.warnings.is_empty() && p.notes[0].contains("Wi-Fi 7"),
            "{p:?}"
        );
        // hostapd without BE (Debian/Ubuntu builds): Wi-Fi 6, said in the note, no warning for auto
        let ax_only = HostapdCaps {
            be: false,
            mld: false,
            ..HostapdCaps::full()
        };
        let p = plan(&net("5g", 36, 80, "wpa2", |_| {}), Some(&c), &ax_only).unwrap();
        assert_eq!(p.standard, "ax");
        assert!(p.warnings.is_empty());
        // an explicit Wi-Fi 7 on that hostapd names the build option
        let p = plan(
            &net("5g", 36, 80, "wpa2", |g| g.standard = "be".into()),
            Some(&c),
            &ax_only,
        )
        .unwrap();
        assert_eq!(p.standard, "ax");
        assert!(
            p.warnings[0].contains("CONFIG_IEEE80211BE"),
            "{:?}",
            p.warnings
        );
        // a Wi-Fi 5 card: auto runs ac on 5 GHz, n on 2.4 GHz; asked-for ax is narrowed and said
        let c5 = parse_caps(WIFI5);
        assert_eq!(
            plan(
                &net("5g", 36, 80, "wpa2", |_| {}),
                Some(&c5),
                &HostapdCaps::full()
            )
            .unwrap()
            .standard,
            "ac"
        );
        assert_eq!(
            plan(
                &net("2g", 6, 20, "wpa2", |_| {}),
                Some(&c5),
                &HostapdCaps::full()
            )
            .unwrap()
            .standard,
            "n"
        );
        let p = plan(
            &net("5g", 36, 80, "wpa2", |g| g.standard = "ax".into()),
            Some(&c5),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert_eq!(p.standard, "ac");
        assert!(
            p.warnings[0].contains("this radio offers Wi-Fi 5"),
            "{:?}",
            p.warnings
        );
        assert!(p.bss_color.is_none(), "no HE, no colour");
    }

    #[test]
    fn no_radio_information_keeps_the_old_behaviour() {
        let p = plan(
            &net("5g", 36, 80, "wpa2", |_| {}),
            None,
            &HostapdCaps::full(),
        )
        .unwrap();
        assert_eq!((p.standard.as_str(), p.width), ("ac", 80));
        assert_eq!(
            plan(
                &net("2g", 6, 20, "wpa2", |_| {}),
                None,
                &HostapdCaps::full()
            )
            .unwrap()
            .standard,
            "n"
        );
        assert_eq!(
            plan(
                &net("2g", 6, 20, "wpa2", |g| g.standard = "ax".into()),
                None,
                &HostapdCaps::full()
            )
            .unwrap()
            .standard,
            "ax"
        );
    }

    #[test]
    fn six_ghz_fails_closed_where_the_regulatory_domain_says_no() {
        let world = parse_caps(WORLD);
        let e = plan(
            &net("6g", 37, 160, "wpa3", |_| {}),
            Some(&world),
            &HostapdCaps::full(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("regulatory database") && e.contains("stays off"),
            "{e}"
        );
        // DE opens 6 GHz LPI up to 6425 MHz (channel 93): 37 works, 229 is refused by name
        let de = parse_caps(DE);
        let p = plan(
            &net("6g", 37, 320, "wpa3", |_| {}),
            Some(&de),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert_eq!((p.standard.as_str(), p.width), ("be", 320));
        let e = plan(
            &net("6g", 229, 20, "wpa3", |_| {}),
            Some(&de),
            &HostapdCaps::full(),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("channel 229"), "{e}");
        // a 6 GHz network on a hostapd without 802.11ax cannot run at all
        let old = HostapdCaps {
            installed: true,
            ..Default::default()
        };
        assert!(plan(&net("6g", 37, 80, "wpa3", |_| {}), Some(&de), &old).is_err());
        // a radio without 6 GHz says which bands it has
        let e = plan(
            &net("6g", 37, 80, "wpa3", |_| {}),
            Some(&parse_caps(WIFI5)),
            &HostapdCaps::full(),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("no 6 GHz band") && e.contains("5 GHz"), "{e}");
    }

    #[test]
    fn discovery_frames_only_where_the_driver_sends_them() {
        let mut c = parse_caps(DE);
        let p = plan(
            &net("6g", 37, 80, "wpa3", |_| {}),
            Some(&c),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert!(
            p.discovery.is_none() && p.notes.iter().any(|x| x.contains("neither")),
            "{p:?}"
        );
        let p = plan(
            &net("6g", 37, 80, "wpa3", |g| g.discovery = "probe".into()),
            Some(&c),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert!(p.discovery.is_none() && p.warnings[0].contains("discovery probe"));
        c.fils_discovery = true;
        let p = plan(
            &net("6g", 37, 80, "wpa3", |_| {}),
            Some(&c),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert_eq!(p.discovery, Some(("fils".into(), 20)));
        c.unsol_probe = true;
        let p = plan(
            &net("6g", 37, 80, "wpa3", |g| g.discovery_interval = 10),
            Some(&c),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert_eq!(p.discovery, Some(("probe".into(), 10)));
        let p = plan(
            &net("6g", 37, 80, "wpa3", |g| g.discovery = "off".into()),
            Some(&c),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert!(p.discovery.is_none());
        // never on 2.4/5 GHz
        assert!(plan(
            &net("5g", 36, 80, "wpa3", |_| {}),
            Some(&c),
            &HostapdCaps::full()
        )
        .unwrap()
        .discovery
        .is_none());
    }

    #[test]
    fn widths_are_narrowed_to_what_the_card_carries() {
        let c5 = parse_caps(WIFI5);
        let p = plan(
            &net("2g", 6, 40, "wpa2", |_| {}),
            Some(&c5),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert_eq!(p.width, 40);
        let mut c = parse_caps(DE);
        c.bands.iter_mut().for_each(|b| {
            b.eht320 = false;
        });
        let p = plan(
            &net("6g", 37, 320, "wpa3", |_| {}),
            Some(&c),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert_eq!(p.width, 160);
        assert!(
            p.warnings[0].contains("asked for 320 MHz, running 160 MHz"),
            "{:?}",
            p.warnings
        );
    }

    #[test]
    fn bss_colour_is_stable_and_configurable() {
        let c = parse_caps(DE);
        let p = plan(
            &net("5g", 36, 80, "wpa2", |_| {}),
            Some(&c),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert_eq!(p.bss_color, Some(auto_color("home")));
        assert!(
            (1..=63).contains(&auto_color("home")) && auto_color("home") != auto_color("guest")
        );
        let p = plan(
            &net("5g", 36, 80, "wpa2", |g| g.bss_color = 9),
            Some(&c),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert_eq!(p.bss_color, Some(9));
    }

    #[test]
    fn multi_link_degrades_with_a_reason() {
        let c = parse_caps(DE);
        let mlo = |g: &mut GenSettings| g.mlo_links = "6g/37/160".into();
        let p = plan(
            &net("5g", 36, 80, "wpa3", mlo),
            Some(&c),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert_eq!(p.links.len(), 1);
        let no_mld = HostapdCaps {
            mld: false,
            ..HostapdCaps::full()
        };
        let p = plan(&net("5g", 36, 80, "wpa3", mlo), Some(&c), &no_mld).unwrap();
        assert!(p.links.is_empty() && p.warnings[0].contains("AP MLD"));
        let p = plan(
            &net("5g", 36, 80, "wpa3", mlo),
            Some(&parse_caps(WIFI5)),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert!(
            p.links.is_empty() && p.warnings.iter().any(|w| w.contains("multi-link")),
            "{:?}",
            p.warnings
        );
        // a 6 GHz link the regulatory domain blocks is left out by name
        let p = plan(
            &net("5g", 36, 80, "wpa3", mlo),
            Some(&parse_caps(WORLD)),
            &HostapdCaps::full(),
        )
        .unwrap();
        assert!(p.links.is_empty());
    }
}
