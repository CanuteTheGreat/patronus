//! Reading syslog FILES for the system log viewer: bounded, from the end.
//!
//! Memory rule (router tier): a request never loads a whole file. Files are read
//! backwards in 64 KiB blocks, stopping at the page limit or the scan budget
//! (`logview.max_scan_bytes`); the live follower reads only the bytes appended
//! since its cursor.
//!
//! A position is `(inode, byte offset)`; the cursor text is `f:<inode>:<offset>`.
//! The inode survives a rename rotation (`messages` -> `messages.0`), so a cursor
//! taken before the rotation still finds its file; a truncating rotation
//! (offset beyond the new length) restarts at 0.

use super::parse::{parse_file_line, Ctx, Entry};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const BLOCK: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pos {
    pub ino: u64,
    pub off: u64,
}

impl Pos {
    pub fn cursor(&self) -> String {
        format!("f:{}:{}", self.ino, self.off)
    }
    pub fn parse(c: &str) -> Option<Pos> {
        let r = c.strip_prefix("f:")?;
        let (a, b) = r.split_once(':')?;
        Some(Pos { ino: a.parse().ok()?, off: b.parse().ok()? })
    }
}

#[derive(Debug, Clone)]
pub struct LogFile {
    pub path: PathBuf,
    pub ino: u64,
    pub len: u64,
}

fn stat(p: &Path) -> Option<LogFile> {
    let m = std::fs::metadata(p).ok()?;
    m.is_file().then(|| LogFile { path: p.to_path_buf(), ino: m.ino(), len: m.len() })
}

/// The active file first, then its rotated files, newest first. Rotated names are
/// `<file>.0` (busybox) and `<file>.1` (logrotate, sysklogd) with higher numbers older;
/// compressed ones (`.gz`) are not read. `active` is used when it exists, else the
/// `fallback` file.
pub fn chain(active: &Path, rotated: u32) -> Vec<LogFile> {
    let mut v = Vec::new();
    if let Some(a) = stat(active) {
        v.push(a);
    }
    let mut rot: Vec<(std::time::SystemTime, LogFile)> = Vec::new();
    for n in 0..=rotated {
        let p = PathBuf::from(format!("{}.{}", active.display(), n));
        if let (Some(f), Ok(m)) = (stat(&p), std::fs::metadata(&p)) {
            rot.push((m.modified().unwrap_or(std::time::UNIX_EPOCH), f));
        }
    }
    rot.sort_by(|a, b| b.0.cmp(&a.0));
    rot.truncate(rotated as usize);
    v.extend(rot.into_iter().map(|(_, f)| f));
    v
}

/// Which file of the configured pair to read: the managed one (priority in every
/// line) when it has data, else the plain one.
pub fn pick_active(managed: &str, plain: &str) -> PathBuf {
    let m = Path::new(managed);
    if std::fs::metadata(m).map(|x| x.len() > 0).unwrap_or(false) {
        return m.to_path_buf();
    }
    PathBuf::from(plain)
}

/// Lines of one file from `end` backwards, with their start offsets.
pub struct RevReader {
    f: File,
    pos: u64,
    carry: Vec<u8>,
    ready: Vec<(u64, Vec<u8>)>,
    pub bytes: u64,
}

impl RevReader {
    pub fn new(path: &Path, end: u64) -> std::io::Result<Self> {
        Ok(Self { f: File::open(path)?, pos: end, carry: Vec::new(), ready: Vec::new(), bytes: 0 })
    }

    pub fn next_line(&mut self) -> std::io::Result<Option<(u64, String)>> {
        loop {
            if let Some((s, l)) = self.ready.pop() {
                return Ok(Some((s, String::from_utf8_lossy(&l).into_owned())));
            }
            if self.pos == 0 {
                return Ok(None);
            }
            let size = BLOCK.min(self.pos);
            self.pos -= size;
            let mut buf = vec![0u8; size as usize];
            self.f.seek(SeekFrom::Start(self.pos))?;
            self.f.read_exact(&mut buf)?;
            self.bytes += size;
            buf.extend_from_slice(&self.carry);
            // `buf` starts at file offset `self.pos`; every segment after the first
            // newline is a whole line, the first one may continue into the next block
            let mut segs: Vec<(u64, Vec<u8>)> = Vec::new();
            let mut off = self.pos;
            for part in buf.split(|b| *b == b'\n') {
                segs.push((off, part.to_vec()));
                off += part.len() as u64 + 1;
            }
            let first = segs.remove(0);
            if self.pos == 0 {
                segs.insert(0, first);
                self.carry.clear();
            } else {
                self.carry = first.1;
            }
            for (s, l) in segs {
                if !l.is_empty() {
                    self.ready.push((s, l));
                }
            }
        }
    }
}

/// One record found going backwards: the parsed entry and the byte range it covers.
pub struct Found {
    pub entry: Entry,
    pub start: Pos,
    pub end: Pos,
}

/// Newest-first iterator over the records of the chain, starting at `from`
/// (None = the end of the active file). Continuation lines (no timestamp) are
/// merged into the record they follow.
pub struct Backwards<'a> {
    files: &'a [LogFile],
    idx: usize,
    rd: Option<RevReader>,
    cur_end: u64,
    pending: Vec<String>,
    pending_end: Option<u64>,
    ctx: Ctx,
    markers: &'a [String],
    pub scanned: u64,
    budget: u64,
    pub exhausted: bool,
    pub over_budget: bool,
}

impl<'a> Backwards<'a> {
    pub fn new(files: &'a [LogFile], from: Option<Pos>, ctx: Ctx, markers: &'a [String], budget: u64) -> Self {
        let (mut idx, mut end) = (0usize, files.first().map(|f| f.len).unwrap_or(0));
        if let Some(p) = from {
            if let Some(i) = files.iter().position(|f| f.ino == p.ino) {
                idx = i;
                end = p.off.min(files[i].len);
            }
        }
        let mut s = Self {
            files,
            idx,
            rd: None,
            cur_end: end,
            pending: Vec::new(),
            pending_end: None,
            ctx,
            markers,
            scanned: 0,
            budget,
            exhausted: files.is_empty(),
            over_budget: false,
        };
        s.open();
        s
    }

    fn open(&mut self) {
        self.rd = self
            .files
            .get(self.idx)
            .and_then(|f| RevReader::new(&f.path, self.cur_end).ok());
        if self.rd.is_none() {
            self.exhausted = true;
        }
    }

    pub fn next_record(&mut self) -> Option<Found> {
        loop {
            if self.exhausted {
                return None;
            }
            let rd = self.rd.as_mut()?;
            match rd.next_line() {
                Ok(Some((start, line))) => {
                    self.scanned += line.len() as u64 + 1;
                    if self.scanned > self.budget {
                        self.over_budget = true;
                        self.exhausted = true;
                        return None;
                    }
                    let ino = self.files[self.idx].ino;
                    match parse_file_line(&line, &self.ctx, self.markers) {
                        None => {
                            if !line.trim().is_empty() {
                                if self.pending.is_empty() {
                                    self.pending_end = Some(start + line.len() as u64 + 1);
                                }
                                self.pending.push(line);
                            }
                        }
                        Some(mut e) => {
                            let mut end = start + line.len() as u64 + 1;
                            if !self.pending.is_empty() {
                                for l in self.pending.drain(..).rev() {
                                    e.message.push('\n');
                                    e.message.push_str(l.trim_end());
                                }
                                end = self.pending_end.take().unwrap_or(end);
                            }
                            return Some(Found { entry: e, start: Pos { ino, off: start }, end: Pos { ino, off: end } });
                        }
                    }
                }
                Ok(None) | Err(_) => {
                    self.pending.clear();
                    self.idx += 1;
                    if self.idx >= self.files.len() {
                        self.exhausted = true;
                        return None;
                    }
                    self.cur_end = self.files[self.idx].len;
                    self.open();
                }
            }
        }
    }
}

/// Records appended after `from` (live mode), oldest first, at most `budget` bytes.
/// Returns the records (with their end positions) and the new position.
pub fn read_after(
    files: &[LogFile],
    from: Pos,
    ctx: &Ctx,
    markers: &[String],
    budget: u64,
) -> (Vec<(Entry, Pos)>, Pos) {
    // oldest first
    let order: Vec<&LogFile> = files.iter().rev().collect();
    let (mut i, mut off) = match order.iter().position(|f| f.ino == from.ino) {
        Some(i) => (i, if from.off > order[i].len { 0 } else { from.off }),
        // the file the cursor named is gone: continue with the active file from its start
        None => (order.len().saturating_sub(1), 0),
    };
    let mut out: Vec<(Entry, Pos)> = Vec::new();
    let mut left = budget;
    let mut pos = Pos { ino: from.ino, off };
    while i < order.len() {
        let f = order[i];
        let newest = i + 1 == order.len();
        let want = f.len.saturating_sub(off).min(left);
        if want > 0 {
            let Ok(mut fh) = File::open(&f.path) else { break };
            if fh.seek(SeekFrom::Start(off)).is_err() {
                break;
            }
            let mut buf = vec![0u8; want as usize];
            let Ok(n) = fh.read(&mut buf) else { break };
            buf.truncate(n);
            // never consume a half-written last line of the live file
            let mut used = buf.len();
            if newest || used as u64 == left {
                if let Some(p) = buf.iter().rposition(|b| *b == b'\n') {
                    used = p + 1;
                } else if newest {
                    used = 0;
                }
            }
            let mut line_off = off;
            for raw in buf[..used].split_inclusive(|b| *b == b'\n') {
                line_off += raw.len() as u64;
                let line = String::from_utf8_lossy(raw);
                match parse_file_line(&line, ctx, markers) {
                    Some(e) => out.push((e, Pos { ino: f.ino, off: line_off })),
                    None => {
                        if !line.trim().is_empty() {
                            if let Some((last, p)) = out.last_mut() {
                                last.message.push('\n');
                                last.message.push_str(line.trim_end());
                                p.off = line_off;
                            }
                        }
                    }
                }
            }
            off += used as u64;
            left = left.saturating_sub(used as u64);
            pos = Pos { ino: f.ino, off };
        } else {
            pos = Pos { ino: f.ino, off };
        }
        if off >= f.len && !newest {
            i += 1;
            off = 0;
            pos = Pos { ino: order[i].ino, off: 0 };
        } else {
            break;
        }
    }
    (out, pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use std::io::Write;

    fn ctx() -> Ctx {
        Ctx { now: Utc.with_ymd_and_hms(2026, 11, 25, 20, 0, 0).unwrap() }
    }
    fn mk() -> Vec<String> {
        vec!["Linux version ".into()]
    }

    fn write(p: &Path, lines: &[&str]) {
        let mut f = File::create(p).unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
    }

    #[test]
    fn reads_backwards_in_blocks_and_never_loads_the_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("messages");
        let mut f = File::create(&p).unwrap();
        for i in 0..5000 {
            writeln!(f, "Nov 25 12:{:02}:{:02} gw daemon.info t[{i}]: line number {i}", (i / 60) % 60, i % 60).unwrap();
        }
        drop(f);
        let files = chain(&p, 0);
        let m = mk();
        let mut b = Backwards::new(&files, None, ctx(), &m, 1 << 30);
        let first = b.next_record().unwrap();
        assert_eq!(first.entry.message, "line number 4999");
        let second = b.next_record().unwrap();
        assert_eq!(second.entry.message, "line number 4998");
        let mut n = 2;
        while b.next_record().is_some() {
            n += 1;
        }
        assert_eq!(n, 5000);
        // a tiny budget stops early and says so
        let mut b = Backwards::new(&files, None, ctx(), &m, 1000);
        let mut n = 0;
        while b.next_record().is_some() {
            n += 1;
        }
        assert!(n < 30 && b.over_budget);
    }

    #[test]
    fn rotated_files_are_followed_busybox_and_logrotate_names() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("messages");
        write(&d.path().join("messages.1"), &["Nov 25 10:00:00 gw daemon.info t: oldest"]);
        std::thread::sleep(std::time::Duration::from_millis(30));
        write(&d.path().join("messages.0"), &["Nov 25 11:00:00 gw daemon.info t: older"]);
        std::thread::sleep(std::time::Duration::from_millis(30));
        write(&p, &["Nov 25 12:00:00 gw daemon.info t: newest"]);
        let files = chain(&p, 3);
        assert_eq!(files.len(), 3);
        let m = mk();
        let mut b = Backwards::new(&files, None, ctx(), &m, 1 << 20);
        let got: Vec<String> = std::iter::from_fn(|| b.next_record()).map(|f| f.entry.message).collect();
        assert_eq!(got, ["newest", "older", "oldest"]);
        assert_eq!(chain(&p, 1).len(), 2);
    }

    #[test]
    fn continuation_lines_join_their_record() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("messages");
        write(&p, &["Nov 25 12:00:00 gw daemon.err t: first", "  more detail", "Nov 25 12:00:01 gw daemon.info t: second"]);
        let files = chain(&p, 0);
        let m = mk();
        let mut b = Backwards::new(&files, None, ctx(), &m, 1 << 20);
        let got: Vec<String> = std::iter::from_fn(|| b.next_record()).map(|f| f.entry.message).collect();
        assert_eq!(got, ["second", "first\nmore detail"]);
    }

    #[test]
    fn cursor_pages_older_records() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("messages");
        write(&p, &["Nov 25 12:00:00 gw daemon.info t: a", "Nov 25 12:00:01 gw daemon.info t: b", "Nov 25 12:00:02 gw daemon.info t: c"]);
        let files = chain(&p, 0);
        let m = mk();
        let mut b = Backwards::new(&files, None, ctx(), &m, 1 << 20);
        let c = b.next_record().unwrap();
        let cur = Pos::parse(&c.start.cursor()).unwrap();
        let mut b = Backwards::new(&files, Some(cur), ctx(), &m, 1 << 20);
        assert_eq!(b.next_record().unwrap().entry.message, "b");
    }

    #[test]
    fn live_follower_gets_only_new_lines_survives_rotation_and_skips_partial() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("messages");
        write(&p, &["Nov 25 12:00:00 gw daemon.info t: a"]);
        let m = mk();
        let files = chain(&p, 2);
        let start = Pos { ino: files[0].ino, off: files[0].len };
        // appended: one whole line and half of another
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        write!(f, "Nov 25 12:00:01 gw daemon.warn t: b\nNov 25 12:00:02 gw daemon.info t: ha").unwrap();
        let files = chain(&p, 2);
        let (got, pos) = read_after(&files, start, &ctx(), &m, 1 << 20);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.message, "b");
        // the rest of the line arrives, then the file is rotated (rename) and a new one starts
        write!(f, "lf\n").unwrap();
        drop(f);
        std::fs::rename(&p, d.path().join("messages.0")).unwrap();
        write(&p, &["Nov 25 12:00:03 gw daemon.err t: c"]);
        let files = chain(&p, 2);
        let (got, pos2) = read_after(&files, pos, &ctx(), &m, 1 << 20);
        let msgs: Vec<&str> = got.iter().map(|g| g.0.message.as_str()).collect();
        assert_eq!(msgs, ["half", "c"]);
        let (none, _) = read_after(&files, pos2, &ctx(), &m, 1 << 20);
        assert!(none.is_empty());
    }

    #[test]
    fn truncation_restarts_at_zero() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("messages");
        write(&p, &["Nov 25 12:00:00 gw daemon.info t: a", "Nov 25 12:00:01 gw daemon.info t: b"]);
        let files = chain(&p, 0);
        let at = Pos { ino: files[0].ino, off: files[0].len };
        write(&p, &["Nov 25 12:00:05 gw daemon.info t: after"]);
        let files = chain(&p, 0);
        let (got, _) = read_after(&files, at, &ctx(), &[], 1 << 20);
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn managed_file_preferred_when_it_has_data() {
        let d = tempfile::tempdir().unwrap();
        let m = d.path().join("system.log");
        let plain = d.path().join("messages");
        assert_eq!(pick_active(m.to_str().unwrap(), plain.to_str().unwrap()), plain);
        write(&m, &["x"]);
        assert_eq!(pick_active(m.to_str().unwrap(), plain.to_str().unwrap()), m);
    }
}
