//! System-account authentication for the web UI (and `patronus applyd`).
//!
//! The web UI signs in the box's own system users; Patronus keeps no account
//! set of its own. Two backends check the password:
//!
//! * **PAM** (full Linux tier): `libpam` is loaded at run time (dlopen, so
//!   nothing links against it and a build/host without PAM still works) and
//!   service `patronus` (`/etc/pam.d/patronus`, installed by the ebuild) runs
//!   `pam_unix`/`pam_faillock`/SSSD/LDAP like any other login. Groups come
//!   from NSS (`getgrouplist`).
//! * **Shadow** (embedded MIPS/OpenWrt-style tier, no PAM): the platform's
//!   own account files (`passwd`, `group`, `shadow` under an etc directory,
//!   default `/etc`) are read directly and the hash is checked in pure Rust
//!   (MD5-crypt `$1$`, SHA-256/512-crypt `$5$`/`$6$`, bcrypt `$2*$`: what
//!   busybox `passwd`/`mkpasswd` and musl `crypt` produce). Locked (`!`,
//!   `*`) and empty passwords and expired accounts never verify. yescrypt
//!   (`$y$`) is not supported here: it fails closed; use PAM on that tier.
//!
//! Reading `/etc/shadow` / running the PAM helpers needs root, and the web
//! UI runs as the unprivileged `patronus` user: it asks the root broker
//! (`patronus applyd`, `op: "auth"`) which calls [`check`]. A web process
//! that is itself root (container image, tests) calls [`check`] directly.

use std::path::{Path, PathBuf};

/// PAM service name (`/etc/pam.d/patronus`).
pub const PAM_SERVICE: &str = "patronus";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    Pam,
    /// passwd/group/shadow files in this directory.
    Shadow(PathBuf),
}

/// A verified system account: numeric uid and the names of all its groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub uid: u32,
    pub groups: Vec<String>,
}

/// `$PATRONUS_AUTH_BACKEND` = `pam` | `shadow` | `auto` (default). `auto`
/// is PAM when `/etc/pam.d/patronus` exists and libpam loads, else the
/// shadow files in `$PATRONUS_AUTH_ETC` (default `/etc`).
pub fn auto_backend() -> Backend {
    let etc = std::env::var_os("PATRONUS_AUTH_ETC")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc"));
    match std::env::var("PATRONUS_AUTH_BACKEND").as_deref() {
        Ok("pam") => Backend::Pam,
        Ok("shadow") => Backend::Shadow(etc),
        _ => {
            if Path::new("/etc/pam.d").join(PAM_SERVICE).exists() && pam::available() {
                Backend::Pam
            } else {
                Backend::Shadow(etc)
            }
        }
    }
}

/// Only names a Linux account can have are ever offered to PAM / looked up.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// uid and groups of a system user (None: no such user).
pub fn lookup(b: &Backend, name: &str) -> Option<Identity> {
    if !valid_name(name) {
        return None;
    }
    match b {
        Backend::Pam => nss_lookup(name),
        Backend::Shadow(etc) => files_lookup(etc, name),
    }
}

fn nss_lookup(name: &str) -> Option<Identity> {
    use nix::unistd::{getgrouplist, Group, User};
    let u = User::from_name(name).ok().flatten()?;
    let c = std::ffi::CString::new(name).ok()?;
    let groups = getgrouplist(&c, u.gid)
        .ok()?
        .into_iter()
        .filter_map(|g| Group::from_gid(g).ok().flatten().map(|g| g.name))
        .collect();
    Some(Identity {
        uid: u.uid.as_raw(),
        groups,
    })
}

fn files_lookup(etc: &Path, name: &str) -> Option<Identity> {
    let passwd = std::fs::read_to_string(etc.join("passwd")).ok()?;
    let (uid, gid) = passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 4 || f[0] != name {
            return None;
        }
        Some((f[2].parse::<u32>().ok()?, f[3].to_string()))
    })?;
    let group = std::fs::read_to_string(etc.join("group")).unwrap_or_default();
    let mut groups = Vec::new();
    for l in group.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 3 {
            continue;
        }
        let member = f.get(3).is_some_and(|m| m.split(',').any(|m| m == name));
        if (member || f[2] == gid) && !groups.iter().any(|g| g == f[0]) {
            groups.push(f[0].to_string());
        }
    }
    Some(Identity { uid, groups })
}

/// Check a password against the backend. Ok(false) = wrong password, unknown
/// or locked account; Err = the mechanism itself is unavailable. Blocking.
pub fn authenticate(b: &Backend, name: &str, password: &str) -> Result<bool, String> {
    if !valid_name(name) {
        return Ok(false);
    }
    match b {
        Backend::Pam => pam::authenticate(name, password),
        Backend::Shadow(etc) => Ok(shadow_verify(etc, name, password)),
    }
}

/// Password check + identity in one step (what applyd runs as root). The
/// password check always runs, for unknown users too, so the cost does not
/// tell which names exist. `Ok(None)`: not signed in.
pub fn check(b: &Backend, name: &str, password: &str) -> Result<Option<Identity>, String> {
    let ok = authenticate(b, name, password)?;
    Ok(if ok { lookup(b, name) } else { None })
}

/// Add (or replace) an account in passwd/group/shadow files under `etc`
/// (created if missing, shadow 0600), password hashed sha512-crypt. This is
/// the account store of the container image, where the web UI is not root:
/// `patronus users add-local-account`. uids start at 1000.
pub fn add_account(
    etc: &Path,
    name: &str,
    password: &str,
    groups: &[String],
) -> Result<(), String> {
    use std::io::Write;
    if !valid_name(name) {
        return Err(format!("invalid account name {name:?}"));
    }
    if password.len() < 12 {
        return Err("the password must have at least 12 characters".into());
    }
    if groups.iter().any(|g| !valid_name(g)) {
        return Err("invalid group name".into());
    }
    std::fs::create_dir_all(etc).map_err(|e| e.to_string())?;
    let hash = pwhash::sha512_crypt::hash(password).map_err(|e| e.to_string())?;
    let read = |f: &str| std::fs::read_to_string(etc.join(f)).unwrap_or_default();
    let write = |f: &str, body: String, mode: u32| -> Result<(), String> {
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = etc.join(format!(".{f}.new"));
        let mut o = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        o.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, etc.join(f)).map_err(|e| e.to_string())
    };
    let passwd = read("passwd");
    let uid = passwd
        .lines()
        .filter_map(|l| l.split(':').nth(2)?.parse::<u32>().ok())
        .max()
        .map_or(1000, |m| (m + 1).max(1000));
    let uid = passwd
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.first() == Some(&name)).then(|| f.get(2)?.parse::<u32>().ok())?
        })
        .unwrap_or(uid);
    let keep = |t: String, name: &str| -> String {
        t.lines()
            .filter(|l| l.split(':').next() != Some(name))
            .map(|l| format!("{l}\n"))
            .collect()
    };
    write(
        "passwd",
        keep(passwd, name) + &format!("{name}:x:{uid}:{uid}::/nonexistent:/sbin/nologin\n"),
        0o644,
    )?;
    write(
        "shadow",
        keep(read("shadow"), name) + &format!("{name}:{hash}:1::::::\n"),
        0o600,
    )?;
    // primary group = the user's own; supplementary groups list the member
    let mut group = keep(read("group"), name) + &format!("{name}:x:{uid}:\n");
    for g in groups {
        let mut found = false;
        group = group
            .lines()
            .map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                if f.first() == Some(&g.as_str()) && f.len() >= 4 {
                    found = true;
                    let mut m: Vec<&str> = f[3]
                        .split(',')
                        .filter(|m| !m.is_empty() && *m != name)
                        .collect();
                    m.push(name);
                    format!("{}:{}:{}:{}\n", f[0], f[1], f[2], m.join(","))
                } else {
                    format!("{l}\n")
                }
            })
            .collect();
        if !found {
            let gid = group
                .lines()
                .filter_map(|l| l.split(':').nth(2)?.parse::<u32>().ok())
                .max()
                .map_or(2000, |m| (m + 1).max(2000));
            group += &format!("{g}:x:{gid}:{name}\n");
        }
    }
    write("group", group, 0o644)
}

/// Non-root accounts in `etc`'s passwd/group files that belong to one of
/// `groups` (as a listed member or by primary gid). The embedded first-run
/// flow asks this to decide whether an administrator exists yet.
pub fn group_members(etc: &Path, groups: &[String]) -> Vec<String> {
    let pw_db = std::fs::read_to_string(etc.join("passwd")).unwrap_or_default();
    let group = std::fs::read_to_string(etc.join("group")).unwrap_or_default();
    let mut gids = Vec::new();
    let mut out: Vec<String> = Vec::new();
    for l in group.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 3 || !groups.iter().any(|g| !g.is_empty() && g == f[0]) {
            continue;
        }
        gids.push(f[2].to_string());
        for m in f.get(3).copied().unwrap_or("").split(',') {
            if !m.is_empty() && !out.iter().any(|o| o == m) {
                out.push(m.to_string());
            }
        }
    }
    for l in pw_db.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() >= 4 && gids.iter().any(|g| g == f[3]) && !out.iter().any(|o| o == f[0]) {
            out.push(f[0].to_string());
        }
    }
    // root never signs in to the web UI by default, and names that are not in
    // passwd are stale group entries
    out.retain(|n| {
        n != "root"
            && pw_db.lines().any(|l| {
                let f: Vec<&str> = l.split(':').collect();
                f.len() >= 3 && f[0] == n && f[2] != "0"
            })
    });
    out
}

fn decoy_hash() -> &'static str {
    static D: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    D.get_or_init(|| pwhash::sha512_crypt::hash("decoy-never-matches").unwrap_or_default())
}

fn days_today() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86400) as i64)
        .unwrap_or(0)
}

/// The shadow entry's hash if the account may sign in at all.
fn usable_hash(etc: &Path, name: &str, today: i64) -> Option<String> {
    let shadow = std::fs::read_to_string(etc.join("shadow")).ok()?;
    let f: Vec<&str> = shadow
        .lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .find(|f| f.len() >= 2 && f[0] == name)?;
    let h = f[1];
    // empty (no password) and locked ('!', '*', '!!', '!$6$..') never verify
    if h.is_empty() || h.starts_with('!') || h.starts_with('*') {
        return None;
    }
    // account expiry (field 8, days since the epoch) and forced change
    if let Some(e) = f.get(7).and_then(|e| e.parse::<i64>().ok()) {
        if e >= 0 && e < today {
            return None;
        }
    }
    Some(h.to_string())
}

fn shadow_verify(etc: &Path, name: &str, password: &str) -> bool {
    let h = usable_hash(etc, name, days_today());
    // unknown/locked accounts cost one decoy verification as well
    let ok = pwhash::unix::verify(password, h.as_deref().unwrap_or_else(|| decoy_hash()));
    ok && h.is_some()
}

mod pam {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_void};

    const PAM_SUCCESS: c_int = 0;
    const PAM_PROMPT_ECHO_OFF: c_int = 1;
    const PAM_PROMPT_ECHO_ON: c_int = 2;
    const PAM_BUF_ERR: c_int = 5;
    const PAM_CONV_ERR: c_int = 19;

    #[repr(C)]
    struct PamMessage {
        msg_style: c_int,
        msg: *const c_char,
    }
    #[repr(C)]
    struct PamResponse {
        resp: *mut c_char,
        resp_retcode: c_int,
    }
    type ConvFn =
        extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int;
    #[repr(C)]
    struct PamConv {
        conv: ConvFn,
        appdata_ptr: *mut c_void,
    }

    type StartFn = unsafe extern "C" fn(
        *const c_char,
        *const c_char,
        *const PamConv,
        *mut *mut c_void,
    ) -> c_int;
    type AuthFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
    type EndFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;

    struct Lib {
        start: StartFn,
        authenticate: AuthFn,
        acct_mgmt: AuthFn,
        end: EndFn,
    }
    // plain function pointers into a library that is never unloaded
    unsafe impl Send for Lib {}
    unsafe impl Sync for Lib {}

    fn lib() -> Option<&'static Lib> {
        static L: std::sync::OnceLock<Option<Lib>> = std::sync::OnceLock::new();
        L.get_or_init(|| unsafe {
            let mut h = std::ptr::null_mut();
            for n in [c"libpam.so.0", c"libpam.so"] {
                h = libc::dlopen(n.as_ptr(), libc::RTLD_NOW);
                if !h.is_null() {
                    break;
                }
            }
            if h.is_null() {
                return None;
            }
            let sym = |n: &std::ffi::CStr| {
                let p = libc::dlsym(h, n.as_ptr());
                (!p.is_null()).then_some(p)
            };
            Some(Lib {
                start: std::mem::transmute::<*mut c_void, StartFn>(sym(c"pam_start")?),
                authenticate: std::mem::transmute::<*mut c_void, AuthFn>(sym(c"pam_authenticate")?),
                acct_mgmt: std::mem::transmute::<*mut c_void, AuthFn>(sym(c"pam_acct_mgmt")?),
                end: std::mem::transmute::<*mut c_void, EndFn>(sym(c"pam_end")?),
            })
        })
        .as_ref()
    }

    pub fn available() -> bool {
        lib().is_some()
    }

    /// Answers every password / visible prompt with the password (malloc'ed:
    /// PAM frees the answers with free()).
    extern "C" fn converse(
        num_msg: c_int,
        msg: *mut *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata: *mut c_void,
    ) -> c_int {
        if num_msg <= 0 || msg.is_null() || resp.is_null() || appdata.is_null() {
            return PAM_CONV_ERR;
        }
        unsafe {
            let pw = appdata as *const c_char;
            let out = libc::calloc(num_msg as usize, std::mem::size_of::<PamResponse>())
                as *mut PamResponse;
            if out.is_null() {
                return PAM_BUF_ERR;
            }
            for i in 0..num_msg as usize {
                let m = *msg.add(i);
                if m.is_null() {
                    continue;
                }
                if matches!((*m).msg_style, PAM_PROMPT_ECHO_OFF | PAM_PROMPT_ECHO_ON) {
                    (*out.add(i)).resp = libc::strdup(pw);
                }
            }
            *resp = out;
        }
        PAM_SUCCESS
    }

    pub fn authenticate(user: &str, password: &str) -> Result<bool, String> {
        let l = lib().ok_or("libpam is not installed")?;
        let service = CString::new(super::PAM_SERVICE).map_err(|e| e.to_string())?;
        let user = CString::new(user).map_err(|e| e.to_string())?;
        let pw = CString::new(password).map_err(|e| e.to_string())?;
        let conv = PamConv {
            conv: converse,
            appdata_ptr: pw.as_ptr() as *mut c_void,
        };
        let mut handle: *mut c_void = std::ptr::null_mut();
        unsafe {
            let rc = (l.start)(service.as_ptr(), user.as_ptr(), &conv, &mut handle);
            if rc != PAM_SUCCESS || handle.is_null() {
                return Err(format!("pam_start failed ({rc})"));
            }
            let mut rc = (l.authenticate)(handle, 0);
            if rc == PAM_SUCCESS {
                rc = (l.acct_mgmt)(handle, 0);
            }
            (l.end)(handle, rc);
            Ok(rc == PAM_SUCCESS)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(deprecated)] // md5-crypt is what busybox boxes have
    fn etc() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let ok = pwhash::sha512_crypt::hash("correct horse battery").unwrap();
        let md5 = pwhash::md5_crypt::hash("busybox-pw").unwrap();
        let bc = pwhash::bcrypt::hash("bcrypt-pw").unwrap();
        std::fs::write(
            d.path().join("passwd"),
            "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\n\
             carol:x:1002:1002::/h:/bin/sh\nlocked:x:1003:1003::/h:/bin/sh\nold:x:1004:1004::/h:/bin/sh\nnopw:x:1005:1005::/h:/bin/sh\n",
        )
        .unwrap();
        std::fs::write(
            d.path().join("group"),
            "root:x:0:\nwheel:x:10:alice\nalice:x:1000:\nbob:x:1001:\nops:x:2000:bob,carol\npatronus-admin:x:2001:carol\n",
        )
        .unwrap();
        std::fs::write(
            d.path().join("shadow"),
            format!(
                "root:{ok}:1::::::\nalice:{ok}:1::::::\nbob:{md5}:1::::::\ncarol:{bc}:1::::::\n\
                 locked:!{ok}:1::::::\nold:{ok}:1:::::1:\nnopw::1::::::\n"
            ),
        )
        .unwrap();
        d
    }

    #[test]
    fn names_are_restricted_to_what_an_account_can_have() {
        assert!(valid_name("alice") && valid_name("a.b-c_d"));
        for bad in ["", "-x", "a b", "a:b", "a/b", "a\nb", &"x".repeat(33)] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn shadow_backend_verifies_sha512_md5_and_bcrypt_hashes() {
        let d = etc();
        let b = Backend::Shadow(d.path().into());
        assert_eq!(authenticate(&b, "alice", "correct horse battery"), Ok(true));
        assert_eq!(authenticate(&b, "alice", "wrong"), Ok(false));
        assert_eq!(authenticate(&b, "bob", "busybox-pw"), Ok(true));
        assert_eq!(authenticate(&b, "carol", "bcrypt-pw"), Ok(true));
        assert_eq!(authenticate(&b, "carol", "bcrypt-pw "), Ok(false));
    }

    #[test]
    fn locked_empty_expired_and_unknown_accounts_never_verify() {
        let d = etc();
        let b = Backend::Shadow(d.path().into());
        for (u, p) in [
            ("locked", "correct horse battery"),
            ("old", "correct horse battery"),
            ("nopw", ""),
            ("nobody-here", "correct horse battery"),
            ("alice;id", "x"),
        ] {
            assert_eq!(authenticate(&b, u, p), Ok(false), "{u}");
        }
    }

    #[test]
    fn identity_has_uid_primary_and_supplementary_groups() {
        let d = etc();
        let b = Backend::Shadow(d.path().into());
        let a = check(&b, "alice", "correct horse battery")
            .unwrap()
            .unwrap();
        assert_eq!(a.uid, 1000);
        assert!(a.groups.contains(&"wheel".to_string()) && a.groups.contains(&"alice".to_string()));
        let c = check(&b, "carol", "bcrypt-pw").unwrap().unwrap();
        assert!(c.groups.contains(&"patronus-admin".to_string()));
        assert!(c.groups.contains(&"ops".to_string()));
        let r = check(&b, "root", "correct horse battery").unwrap().unwrap();
        assert_eq!(r.uid, 0);
        assert_eq!(check(&b, "alice", "nope"), Ok(None));
        assert_eq!(lookup(&b, "ghost"), None);
    }

    #[test]
    fn add_account_writes_files_that_verify_and_map_groups() {
        let d = tempfile::tempdir().unwrap();
        let g = vec!["patronus-admin".to_string()];
        add_account(d.path(), "boss", "Correct-Horse-9", &g).unwrap();
        add_account(d.path(), "viewer", "Another-Pass-77", &[]).unwrap();
        // idempotent: a second add replaces the password and keeps one entry
        add_account(d.path(), "boss", "Second-Pass-4242", &g).unwrap();
        let b = Backend::Shadow(d.path().into());
        assert_eq!(check(&b, "boss", "Correct-Horse-9"), Ok(None));
        let i = check(&b, "boss", "Second-Pass-4242").unwrap().unwrap();
        assert_eq!(i.uid, 1000);
        assert!(i.groups.contains(&"patronus-admin".to_string()));
        let v = check(&b, "viewer", "Another-Pass-77").unwrap().unwrap();
        assert_eq!(v.uid, 1001);
        assert!(!v.groups.contains(&"patronus-admin".to_string()));
        let shadow = std::fs::read_to_string(d.path().join("shadow")).unwrap();
        assert_eq!(shadow.lines().filter(|l| l.starts_with("boss:")).count(), 1);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(d.path().join("shadow"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(add_account(d.path(), "x", "short", &[]).is_err());
        assert!(add_account(d.path(), "a:b", "Correct-Horse-9", &[]).is_err());
    }

    #[test]
    fn missing_account_files_fail_closed() {
        let d = tempfile::tempdir().unwrap();
        let b = Backend::Shadow(d.path().into());
        assert_eq!(check(&b, "alice", "x"), Ok(None));
    }
}
