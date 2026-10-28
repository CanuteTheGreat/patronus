#!/bin/sh
set -e
chmod +x /etc/init.d/patronus-* /usr/libexec/live-install-hook
getent group patronus >/dev/null || groupadd -r patronus
getent passwd patronus >/dev/null || useradd -r -g patronus -d /var/lib/patronus -s /sbin/nologin patronus
mkdir -p /var/lib/patronus /var/log/patronus /etc/patronus/tls /run/patronus
chown -R patronus:patronus /var/lib/patronus /var/log/patronus /etc/patronus/tls
# patronus-web runs as user patronus and must read /etc/patronus/patronus.toml
chgrp patronus /etc/patronus && chmod 0750 /etc/patronus
chgrp patronus /etc/patronus/patronus.toml && chmod 0640 /etc/patronus/patronus.toml
# patronus-firewall = boot-time `patronus apply` (seeds + applies the ruleset); the stock
# nftables service is NOT enabled (patronus owns the ruleset)
for s in patronus-firewall patronus-applyd patronus-web chronyd; do rc-update add $s default >/dev/null 2>&1 || echo "warn: rc-update add $s"; done
# every shipped binary must resolve its libraries on the live system
bad=0; for b in /usr/bin/patronus-cli /usr/bin/patronus-web /usr/bin/patronus-install; do
  if ldd $b | grep -q 'not found'; then echo "MISSING LIBS for $b:"; ldd $b | grep 'not found'; bad=1; fi; done
[ $bad = 0 ]
