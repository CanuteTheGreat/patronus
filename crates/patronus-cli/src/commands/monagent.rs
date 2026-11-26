//! `patronus zabbix-item KEY [ARG]`: one Zabbix item, answered from the
//! metrics snapshot the web UI refreshes while the Zabbix agent is on
//! (`patronus_network::monagent`). Runs as the agent's unprivileged account:
//! it opens no database and no socket, it reads one file.

use patronus_network::monagent;
use patronus_network::supervise::NetPaths;

pub fn zabbix_item(key: String, arg: String) -> ! {
    let snap = monagent::base_dir(&NetPaths::default()).join(monagent::SNAPSHOT);
    let loadavg = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let host_only = key.starts_with("host.load");
    let prom = match std::fs::metadata(&snap).and_then(|m| m.modified()) {
        Ok(t) => {
            let age = t.elapsed().map(|d| d.as_secs()).unwrap_or(0);
            if age > monagent::SNAPSHOT_MAX_AGE_SECS && !host_only {
                eprintln!(
                    "the metrics snapshot {} is {age} s old (patronus-web not running?)",
                    snap.display()
                );
                std::process::exit(1);
            }
            std::fs::read_to_string(&snap).unwrap_or_default()
        }
        Err(e) if host_only => {
            let _ = e;
            String::new()
        }
        Err(e) => {
            eprintln!("no metrics snapshot at {}: {e}", snap.display());
            std::process::exit(1);
        }
    };
    match monagent::zabbix_item(&key, &arg, &prom, &loadavg) {
        Ok(v) => {
            println!("{v}");
            std::process::exit(0)
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1)
        }
    }
}
