//! Live host metrics read from /proc and statvfs, shared by the dashboard,
//! status API, system and monitoring pages. Everything here is measured;
//! when a source is missing the caller gets `None`/empty, never a default
//! number that looks like a measurement.

use std::time::Duration;

/// One line of /proc/net/dev.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetDev {
    pub name: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
}

/// Parse /proc/net/dev (loopback excluded).
pub fn parse_net_dev(text: &str) -> Vec<NetDev> {
    text.lines()
        .skip(2)
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let name = name.trim();
            if name == "lo" {
                return None;
            }
            let n: Vec<u64> = rest
                .split_whitespace()
                .map(|v| v.parse().unwrap_or(0))
                .collect();
            if n.len() < 16 {
                return None;
            }
            Some(NetDev {
                name: name.to_string(),
                rx_bytes: n[0],
                rx_packets: n[1],
                rx_errors: n[2],
                tx_bytes: n[8],
                tx_packets: n[9],
                tx_errors: n[10],
            })
        })
        .collect()
}

/// (busy, total) jiffies from the aggregate `cpu` line of /proc/stat.
pub fn parse_proc_stat(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().find(|l| l.starts_with("cpu "))?;
    let v: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .take(8) // user nice system idle iowait irq softirq steal
        .map(|x| x.parse().unwrap_or(0))
        .collect();
    if v.len() < 4 {
        return None;
    }
    let total: u64 = v.iter().sum();
    let idle = v[3] + v.get(4).copied().unwrap_or(0);
    Some((total - idle, total))
}

/// CPU busy share between two /proc/stat readings, in percent.
pub fn cpu_percent(before: (u64, u64), after: (u64, u64)) -> Option<f64> {
    let busy = after.0.checked_sub(before.0)?;
    let total = after.1.checked_sub(before.1)?;
    (total > 0).then(|| busy as f64 * 100.0 / total as f64)
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// A measurement over a short window: CPU use and per-interface rates.
#[derive(Debug, Clone, Default)]
pub struct Sample {
    pub cpu_percent: Option<f64>,
    /// (counters at the end of the window, rx bytes/s, tx bytes/s, packets/s)
    pub interfaces: Vec<(NetDev, u64, u64, u64)>,
}

impl Sample {
    pub fn rx_rate(&self) -> u64 {
        self.interfaces.iter().map(|i| i.1).sum()
    }
    pub fn tx_rate(&self) -> u64 {
        self.interfaces.iter().map(|i| i.2).sum()
    }
    pub fn packet_rate(&self) -> u64 {
        self.interfaces.iter().map(|i| i.3).sum()
    }
    pub fn packets_total(&self) -> u64 {
        self.interfaces
            .iter()
            .map(|i| i.0.rx_packets + i.0.tx_packets)
            .sum()
    }
}

/// Measure CPU and interface throughput over `window`.
pub async fn sample(window: Duration) -> Sample {
    let cpu0 = read("/proc/stat").and_then(|t| parse_proc_stat(&t));
    let net0 = read("/proc/net/dev")
        .map(|t| parse_net_dev(&t))
        .unwrap_or_default();
    tokio::time::sleep(window).await;
    let cpu1 = read("/proc/stat").and_then(|t| parse_proc_stat(&t));
    let net1 = read("/proc/net/dev")
        .map(|t| parse_net_dev(&t))
        .unwrap_or_default();
    let secs = window.as_secs_f64().max(0.001);
    let rate = |a: u64, b: u64| (b.saturating_sub(a) as f64 / secs) as u64;
    Sample {
        cpu_percent: match (cpu0, cpu1) {
            (Some(a), Some(b)) => cpu_percent(a, b),
            _ => None,
        },
        interfaces: net1
            .into_iter()
            .map(|n| {
                let prev = net0.iter().find(|p| p.name == n.name).cloned();
                let p = prev.unwrap_or_else(|| n.clone());
                let rx = rate(p.rx_bytes, n.rx_bytes);
                let tx = rate(p.tx_bytes, n.tx_bytes);
                let pk = rate(p.rx_packets + p.tx_packets, n.rx_packets + n.tx_packets);
                (n, rx, tx, pk)
            })
            .collect(),
    }
}

/// (used percent, total bytes) from /proc/meminfo.
pub fn memory() -> Option<(f64, u64)> {
    parse_meminfo(&read("/proc/meminfo")?)
}

pub fn parse_meminfo(text: &str) -> Option<(f64, u64)> {
    let kb = |key: &str| -> Option<u64> {
        text.lines()
            .find(|l| l.starts_with(key))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()
    };
    let total = kb("MemTotal:")?;
    let avail = kb("MemAvailable:")?;
    (total > 0).then(|| {
        (
            total.saturating_sub(avail) as f64 * 100.0 / total as f64,
            total * 1024,
        )
    })
}

/// (used bytes, total bytes) of the filesystem holding `path`.
pub fn disk(path: &str) -> Option<(u64, u64)> {
    let st = nix::sys::statvfs::statvfs(path).ok()?;
    let frag = st.fragment_size() as u64;
    let total = st.blocks() as u64 * frag;
    let free = st.blocks_free() as u64 * frag;
    (total > 0).then(|| (total.saturating_sub(free), total))
}

pub fn disk_percent(path: &str) -> Option<f64> {
    disk(path).map(|(u, t)| u as f64 * 100.0 / t as f64)
}

/// Seconds since boot.
pub fn uptime_secs() -> Option<u64> {
    read("/proc/uptime")?
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .map(|s| s as u64)
}

pub fn load_average() -> Option<(f64, f64, f64)> {
    let t = read("/proc/loadavg")?;
    let v: Vec<f64> = t
        .split_whitespace()
        .take(3)
        .filter_map(|x| x.parse().ok())
        .collect();
    (v.len() == 3).then(|| (v[0], v[1], v[2]))
}

pub fn hostname() -> String {
    nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .or_else(|| read("/proc/sys/kernel/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_default()
}

pub fn kernel() -> String {
    read("/proc/sys/kernel/osrelease")
        .map(|s| format!("Linux {}", s.trim()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// CPU model and logical CPU count from /proc/cpuinfo.
pub fn cpu_model() -> String {
    let n = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let model = read("/proc/cpuinfo").and_then(|t| {
        t.lines()
            .find(|l| {
                l.starts_with("model name") || l.starts_with("Hardware") || l.starts_with("Model")
            })
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
    });
    match model {
        Some(m) => format!("{m} ({n} logical CPUs)"),
        None => format!("{n} logical CPUs"),
    }
}

/// "3 d 4 h 5 min" (or "42 s").
pub fn format_duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, (secs % 86_400) / 3600, (secs % 3600) / 60);
    if d > 0 {
        format!("{d} d {h} h {m} min")
    } else if h > 0 {
        format!("{h} h {m} min")
    } else if m > 0 {
        format!("{m} min")
    } else {
        format!("{secs} s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_parsers_read_real_counters() {
        let dev = "Inter-|   Receive                                                |  Transmit\n \
face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    \
lo: 100 2 0 0 0 0 0 0 100 2 0 0 0 0 0 0\n  \
eth0: 5000 40 1 0 0 0 0 0 7000 50 2 0 0 0 0 0\n";
        let d = parse_net_dev(dev);
        assert_eq!(d.len(), 1, "loopback is skipped");
        assert_eq!(
            d[0],
            NetDev {
                name: "eth0".into(),
                rx_bytes: 5000,
                rx_packets: 40,
                rx_errors: 1,
                tx_bytes: 7000,
                tx_packets: 50,
                tx_errors: 2
            }
        );
        let a = parse_proc_stat("cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2 3 4\n").unwrap();
        let b = parse_proc_stat("cpu  150 0 150 800 100 0 0 0 0 0\n").unwrap();
        assert_eq!(a, (200, 1000));
        assert_eq!(cpu_percent(a, b), Some(50.0));
        assert_eq!(cpu_percent(a, a), None, "no time passed: no number");
        let (pct, total) =
            parse_meminfo("MemTotal:       1000 kB\nMemFree: 1 kB\nMemAvailable:    250 kB\n")
                .unwrap();
        assert_eq!(total, 1_024_000);
        assert!((pct - 75.0).abs() < 1e-9);
        assert_eq!(format_duration(42), "42 s");
        assert_eq!(format_duration(86_400 + 3600 * 2 + 60 * 3), "1 d 2 h 3 min");
    }

    #[tokio::test]
    async fn the_live_sample_is_measured_here() {
        // Whatever box runs the tests: the root filesystem has a size, the
        // machine has an uptime, a hostname and a CPU reading.
        assert!(disk("/").is_some());
        assert!(uptime_secs().is_some());
        let s = sample(Duration::from_millis(50)).await;
        if let Some(c) = s.cpu_percent {
            assert!((0.0..=100.0).contains(&c));
        }
    }
}
