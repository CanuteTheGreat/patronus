//! Version comparison for the two ecosystems the exposure view reads: Gentoo
//! (PMS section 3.2: `1.2.3a_rc1_p2-r4`) and semantic versions of crates.io crates.

use std::cmp::Ordering;

// ---------------------------------------------------------------------------
// Gentoo
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct GentooVersion {
    pub raw: String,
    comps: Vec<String>,
    letter: Option<char>,
    suffixes: Vec<(u8, u64)>,
    rev: u64,
}

const SUFFIXES: &[(&str, u8)] = &[("alpha", 0), ("beta", 1), ("pre", 2), ("rc", 3), ("p", 5)];
/// Rank of "no suffix": above alpha..rc, below _p.
const NO_SUFFIX: u8 = 4;

impl GentooVersion {
    pub fn parse(s: &str) -> Option<GentooVersion> {
        let raw = s.trim().to_string();
        let mut rest = raw.as_str();
        let mut rev = 0u64;
        if let Some(i) = rest.rfind("-r") {
            let tail = &rest[i + 2..];
            if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
                rev = tail.parse().ok()?;
                rest = &rest[..i];
            }
        }
        let mut parts = rest.split('_');
        let head = parts.next()?;
        let mut suffixes = Vec::new();
        for p in parts {
            let (name, num) = match p.find(|c: char| c.is_ascii_digit()) {
                Some(i) => (&p[..i], &p[i..]),
                None => (p, ""),
            };
            let rank = SUFFIXES.iter().find(|(n, _)| *n == name)?.1;
            let n = if num.is_empty() { 0 } else { num.parse().ok()? };
            suffixes.push((rank, n));
        }
        let mut head = head;
        let mut letter = None;
        if let Some(c) = head.chars().last() {
            if c.is_ascii_lowercase() {
                letter = Some(c);
                head = &head[..head.len() - 1];
            }
        }
        if head.is_empty() {
            return None;
        }
        let comps: Vec<String> = head.split('.').map(String::from).collect();
        if comps
            .iter()
            .any(|c| c.is_empty() || !c.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        Some(GentooVersion {
            raw,
            comps,
            letter,
            suffixes,
            rev,
        })
    }

    pub fn revision(&self) -> u64 {
        self.rev
    }

    fn cmp_base(&self, o: &GentooVersion) -> Ordering {
        // first component: integer; the others: integer, unless one has a leading zero
        for i in 0..self.comps.len().max(o.comps.len()) {
            let (a, b) = match (self.comps.get(i), o.comps.get(i)) {
                (Some(a), Some(b)) => (a, b),
                (Some(_), None) => return Ordering::Greater,
                (None, Some(_)) => return Ordering::Less,
                (None, None) => break,
            };
            let ord = if i > 0 && (a.starts_with('0') || b.starts_with('0')) {
                a.trim_end_matches('0').cmp(b.trim_end_matches('0'))
            } else {
                let (a, b) = (a.trim_start_matches('0'), b.trim_start_matches('0'));
                a.len().cmp(&b.len()).then_with(|| a.cmp(b))
            };
            if ord != Ordering::Equal {
                return ord;
            }
        }
        self.letter.cmp(&o.letter).then_with(|| {
            for i in 0..self.suffixes.len().max(o.suffixes.len()) {
                let a = self.suffixes.get(i).copied().unwrap_or((NO_SUFFIX, 0));
                let b = o.suffixes.get(i).copied().unwrap_or((NO_SUFFIX, 0));
                if a != b {
                    return a.cmp(&b);
                }
            }
            Ordering::Equal
        })
    }

    pub fn same_base(&self, o: &GentooVersion) -> bool {
        self.cmp_base(o) == Ordering::Equal
    }
}

impl PartialEq for GentooVersion {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == Ordering::Equal
    }
}
impl Eq for GentooVersion {}

impl PartialOrd for GentooVersion {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for GentooVersion {
    fn cmp(&self, o: &Self) -> Ordering {
        self.cmp_base(o).then(self.rev.cmp(&o.rev))
    }
}

/// Split a `/var/db/pkg` directory name (`foo-bar-1.2.3-r1`) into name and version.
pub fn split_pf(pf: &str) -> Option<(String, GentooVersion)> {
    let bytes = pf.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            if let Some(v) = GentooVersion::parse(&pf[i + 1..]) {
                return Some((pf[..i].to_string(), v));
            }
        }
    }
    None
}

/// One range of a GLSA (`lt`, `le`, `gt`, `ge`, `eq`, and the revision forms `rlt`,
/// `rle`, `rgt`, `rge`, which only match the same version with another revision).
pub fn gentoo_range_matches(op: &str, bound: &str, v: &GentooVersion) -> bool {
    let (glob, bound) = match bound.strip_suffix('*') {
        Some(b) if op == "eq" => (true, b),
        _ => (false, bound),
    };
    let Some(b) = GentooVersion::parse(bound) else {
        return false;
    };
    if glob {
        // =1.2* : every version that starts with the bound's components
        return v.raw.starts_with(bound);
    }
    match op {
        "lt" => v < &b,
        "le" => v <= &b,
        "gt" => v > &b,
        "ge" => v >= &b,
        "eq" => v == &b,
        "rlt" => v.same_base(&b) && v.rev < b.rev,
        "rle" => v.same_base(&b) && v.rev <= b.rev,
        "rgt" => v.same_base(&b) && v.rev > b.rev,
        "rge" => v.same_base(&b) && v.rev >= b.rev,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// semver (crates.io)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SemVer {
    pub raw: String,
    nums: [u64; 3],
    pre: Vec<String>,
}

impl SemVer {
    pub fn parse(s: &str) -> Option<SemVer> {
        let raw = s.trim().trim_start_matches('v').to_string();
        let core = raw.split('+').next()?;
        let (nums_s, pre_s) = match core.split_once('-') {
            Some((a, b)) => (a, Some(b)),
            None => (core, None),
        };
        let mut nums = [0u64; 3];
        let mut n = 0;
        for p in nums_s.split('.') {
            if n >= 3 {
                return None;
            }
            nums[n] = p.parse().ok()?;
            n += 1;
        }
        if n == 0 {
            return None;
        }
        let pre = pre_s
            .map(|p| p.split('.').map(String::from).collect())
            .unwrap_or_default();
        Some(SemVer { raw, nums, pre })
    }
}

impl PartialEq for SemVer {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == Ordering::Equal
    }
}
impl Eq for SemVer {}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for SemVer {
    fn cmp(&self, o: &Self) -> Ordering {
        self.nums.cmp(&o.nums).then_with(|| {
            match (self.pre.is_empty(), o.pre.is_empty()) {
                (true, true) => return Ordering::Equal,
                (true, false) => return Ordering::Greater,
                (false, true) => return Ordering::Less,
                _ => {}
            }
            for (a, b) in self.pre.iter().zip(o.pre.iter()) {
                let ord = match (a.parse::<u64>(), b.parse::<u64>()) {
                    (Ok(x), Ok(y)) => x.cmp(&y),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => a.cmp(b),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            self.pre.len().cmp(&o.pre.len())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(s: &str) -> GentooVersion {
        GentooVersion::parse(s).unwrap()
    }

    #[test]
    fn gentoo_ordering_follows_pms() {
        assert!(g("1.2.3") < g("1.2.10"));
        assert!(g("1.0") < g("1.0.1"));
        assert!(g("1") < g("1.0"));
        assert!(g("1.2.3_alpha1") < g("1.2.3_beta"));
        assert!(g("1.2.3_rc1") < g("1.2.3"));
        assert!(g("1.2.3") < g("1.2.3_p1"));
        assert!(g("1.2.3") < g("1.2.3a"));
        assert!(g("1.2.3-r1") > g("1.2.3"));
        assert!(g("1.2.3-r2") > g("1.2.3-r1"));
        assert!(g("1.01") < g("1.1"));
        assert!(g("2.0_pre20230101") < g("2.0"));
        assert!(GentooVersion::parse("not-a-version").is_none());
        assert!(g("3.0.0").cmp(&g("3.0.0")) == Ordering::Equal);
    }

    #[test]
    fn pf_split_finds_the_version() {
        let (n, v) = split_pf("openssl-3.0.13-r2").unwrap();
        assert_eq!(n, "openssl");
        assert_eq!(v.raw, "3.0.13-r2");
        let (n, v) = split_pf("python-exec-2-r3").unwrap();
        assert_eq!(n, "python-exec");
        assert_eq!(v.raw, "2-r3");
        let (n, _) = split_pf("lib-2to3-1.0").unwrap();
        assert_eq!(n, "lib-2to3");
        assert!(split_pf("noversion").is_none());
    }

    #[test]
    fn glsa_ranges() {
        assert!(gentoo_range_matches("lt", "1.2.0", &g("1.1.9")));
        assert!(!gentoo_range_matches("lt", "1.2.0", &g("1.2.0")));
        assert!(gentoo_range_matches("ge", "1.2.0", &g("1.2.0-r1")));
        assert!(gentoo_range_matches("rge", "1.2.0-r2", &g("1.2.0-r3")));
        assert!(!gentoo_range_matches("rge", "1.2.0-r2", &g("1.3.0")));
        assert!(gentoo_range_matches("eq", "1.2*", &g("1.2.9")));
        assert!(!gentoo_range_matches("eq", "1.2*", &g("1.3")));
        assert!(gentoo_range_matches("le", "2", &g("2")));
    }

    #[test]
    fn semver_ordering() {
        let s = |x| SemVer::parse(x).unwrap();
        assert!(s("0.3.23") < s("0.3.24"));
        assert!(s("0.4.0-0") < s("0.4.0"));
        assert!(s("1.0.0-alpha") < s("1.0.0-alpha.1"));
        assert!(s("1.0.0-alpha.2") < s("1.0.0-alpha.10"));
        assert!(s("1.0.0-1") < s("1.0.0-alpha"));
        assert_eq!(s("1.2.3+build").cmp(&s("1.2.3")), Ordering::Equal);
        assert!(s("0.0.0-0") < s("0.0.0"));
        assert!(SemVer::parse("x").is_none());
    }
}
