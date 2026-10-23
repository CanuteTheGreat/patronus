#!/bin/bash
for p in patronus-web patronus softflowd igmpproxy tayga xl2tpd pppd suricata rsyslogd unbound zebra bgpd ospfd watchfrr dnsmasq patronus-dashboard; do pkill -x $p 2>/dev/null; done
for p in $(pgrep -f 'python3 /t/nl-'); do kill $p 2>/dev/null; done
sleep 1
for n in $(ip netns list | cut -d" " -f1); do ip netns del $n 2>/dev/null; done
rm -rf /var/lib/patronus /run/patronus /etc/netns
rm -f /etc/rsyslog.d/50-patronus.conf /etc/unbound/unbound.conf; rm -f /etc/frr/frr.conf.pre-patronus
rm -f /etc/frr/frr.conf; 
pkill -f '^/usr/bin/suricata -c' 2>/dev/null
