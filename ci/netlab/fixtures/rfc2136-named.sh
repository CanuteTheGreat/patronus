# Real BIND for the RFC 2136 lanes (sourced by lane-j-rfc2136.sh and lane-j-rfc2136-ui.sh).
# Needs KEY / KEY512 (base64 TSIG secrets), ND (work dir), NS_IP (address in the INET namespace).
named_start() {
  # its own address: the netlab INET namespace already runs a stand-in DNS (TCP too) on $NL_DNS
  INET ip addr add "$NS_IP/24" dev inet0 2>/dev/null || true
  rm -rf "$ND"; mkdir -p "$ND"
  cat > "$ND/example.net.zone" <<ZONE
\$TTL 60
@ IN SOA ns.example.net. admin.example.net. 1 60 60 3600 60
@ IN NS ns.example.net.
ns IN A $NS_IP
ZONE
  cat > "$ND/named.conf" <<CONF
options {
  directory "$ND";
  pid-file "$ND/named.pid";
  session-keyfile "$ND/session.key";
  listen-on port 53 { $NS_IP; };
  listen-on-v6 { none; };
  recursion no;
  allow-query { any; };
  dnssec-validation no;
};
key "ddns-key" { algorithm hmac-sha256; secret "$KEY"; };
key "ddns-key512" { algorithm hmac-sha512; secret "$KEY512"; };
zone "example.net" {
  type primary;
  file "$ND/example.net.zone";
  allow-update { key "ddns-key"; key "ddns-key512"; };
};
CONF
  INET named-checkconf "$ND/named.conf" || nl_fail "named.conf"
  INET named -u root -c "$ND/named.conf" || nl_fail "named did not start"
  nl_wait 15 INET dig +short +time=1 +tries=1 @"$NS_IP" ns.example.net A || nl_fail "named does not answer"
}
named_stop() { [ -s "$ND/named.pid" ] && kill "$(cat "$ND/named.pid")" 2>/dev/null || true; }

# answer of the real server for NAME TYPE
dnsq() { INET dig +short +time=2 +tries=1 @"$NS_IP" "$1" "$2" 2>/dev/null | sort | tr '\n' ' ' | sed 's/ $//'; }
dns_is() { [ "$(dnsq "$1" "$2")" = "$3" ]; }
want_dns() { # NAME TYPE VALUE DESC
  nl_wait 40 dns_is "$1" "$2" "$3" || nl_fail "$4: the server answers '$(dnsq "$1" "$2")' for $1 $2, want '$3'"
  nl_ok "$4"
}

