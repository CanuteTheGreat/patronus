#!/usr/bin/env bash
# Lane H: notification channels on the real binaries. Fake ntfy / Telegram /
# Discord / Slack endpoints (one HTTP capture server) and an SMTP server run
# on the internet side of the lab:
#
#  1. each channel type is created through the API (bad input refused);
#     "Send test" delivers a readable message in that service's format
#     (ntfy text + Title/Priority, Telegram sendMessage JSON with the bot
#     token in the path, Discord content, Slack text, an RFC 5322 mail with
#     SMTP AUTH); secrets never come back from the API.
#  2. a real event: the WAN gateway monitor target stops answering ->
#     gateway_down (critical) reaches ntfy (priority urgent) and email;
#     a channel with min_severity=critical gets it, one filtered to other
#     event kinds does not.
#  3. a channel whose server is down records the failure on the channel.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-h-notify.db
rm -f "$DB" "$NL_T/nl-jar" "$NL_T/notify-http.log" "$NL_T/notify-smtp.log"
: > "$NL_T/notify-http.log"; : > "$NL_T/notify-smtp.log"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
j() { nl_json "$NL_OUT" "$1"; }

cat > "$NL_T/nl-notify-http.py" <<'PY'
import http.server, json, sys
LOG = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('content-length', 0))).decode()
        with open(LOG, 'a') as f:
            f.write(json.dumps({'path': self.path, 'headers': dict(self.headers.items()), 'body': body}) + '\n')
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok":true}')
    def log_message(self, *a): pass
http.server.HTTPServer(('0.0.0.0', 9200), H).serve_forever()
PY
cat > "$NL_T/nl-notify-smtp.py" <<'PY'
# minimal SMTP server: EHLO (AUTH PLAIN/LOGIN), MAIL, RCPT, DATA; logs each mail as JSON
import base64, json, socketserver, sys
LOG = sys.argv[1]
class S(socketserver.StreamRequestHandler):
    def w(self, s): self.wfile.write((s + '\r\n').encode()); self.wfile.flush()
    def handle(self):
        m = {'from': None, 'rcpt': [], 'auth': None, 'data': ''}
        self.w('220 nl-smtp ready')
        while True:
            line = self.rfile.readline().decode(errors='replace')
            if not line: return
            cmd = line.strip(); up = cmd.upper()
            if up.startswith('EHLO') or up.startswith('HELO'):
                self.w('250-nl-smtp'); self.w('250-AUTH PLAIN LOGIN'); self.w('250 8BITMIME')
            elif up.startswith('AUTH PLAIN'):
                parts = cmd.split()
                raw = parts[2] if len(parts) > 2 else (self.w('334 ') or self.rfile.readline().decode().strip())
                _, u, p = base64.b64decode(raw).decode().split('\0')
                m['auth'] = [u, p]; self.w('235 ok')
            elif up.startswith('AUTH LOGIN'):
                self.w('334 VXNlcm5hbWU6'); u = base64.b64decode(self.rfile.readline().strip()).decode()
                self.w('334 UGFzc3dvcmQ6'); p = base64.b64decode(self.rfile.readline().strip()).decode()
                m['auth'] = [u, p]; self.w('235 ok')
            elif up.startswith('MAIL FROM'):
                m['from'] = cmd.split(':', 1)[1].strip(); self.w('250 ok')
            elif up.startswith('RCPT TO'):
                m['rcpt'].append(cmd.split(':', 1)[1].strip()); self.w('250 ok')
            elif up == 'DATA':
                self.w('354 go'); data = []
                while True:
                    l = self.rfile.readline().decode(errors='replace')
                    if l in ('.\r\n', '.\n', ''): break
                    data.append(l)
                m['data'] = ''.join(data)
                with open(LOG, 'a') as f: f.write(json.dumps(m) + '\n')
                m = {'from': None, 'rcpt': [], 'auth': m['auth'], 'data': ''}
                self.w('250 queued')
            elif up == 'QUIT':
                self.w('221 bye'); return
            else:
                self.w('250 ok')
class T(socketserver.ThreadingTCPServer): allow_reuse_address = True
T(('0.0.0.0', 2525), S).serve_forever()
PY
nl_bg INET python3 "$NL_T/nl-notify-http.py" "$NL_T/notify-http.log"
nl_bg INET python3 "$NL_T/nl-notify-smtp.py" "$NL_T/notify-smtp.log"
for p in 9200 2525; do
  for _ in $(seq 1 40); do INET sh -c "exec 3<>/dev/tcp/$NL_WWW/$p" 2>/dev/null && break; sleep 0.25; done
done
H="http://$NL_WWW:9200"

echo "=== 1. channels + send test"
add() { nl_api POST /system/hooks "$1"; [ "$NL_CODE" = 201 ] || nl_fail "add channel: $NL_CODE $(cat "$NL_OUT") <- $1"; j 'd["id"]'; }
NTFY=$(add "{\"name\":\"push\",\"channel\":\"ntfy\",\"url\":\"$H/alerts\",\"secret\":\"tk_ntfy_test\"}")
TG=$(add "{\"name\":\"tg\",\"channel\":\"telegram\",\"url\":\"$H\",\"secret\":\"123456:TEST-token\",\"target\":\"-100777\"}")
DC=$(add "{\"name\":\"dc\",\"channel\":\"discord\",\"url\":\"$H/discord\"}")
SL=$(add "{\"name\":\"sl\",\"channel\":\"slack\",\"url\":\"$H/slack\",\"kinds\":\"tunnel_down\"}")
MAIL=$(add "{\"name\":\"mail\",\"channel\":\"email\",\"url\":\"smtp://$NL_WWW:2525\",\"sender\":\"router@example.com\",\"target\":\"admin@example.com, ops@example.net\",\"username\":\"mailer\",\"secret\":\"Mail-Passw0rd\",\"min_severity\":\"critical\"}")
for bad in '{"name":"x","channel":"pager","url":"https://a.example"}' \
           '{"name":"x","channel":"telegram","target":"1"}' \
           '{"name":"x","channel":"email","url":"smtp://m.example","sender":"r@example.com","target":"a@example.com\r\nBcc: z@example.com"}' \
           '{"name":"x","channel":"email","url":"https://m.example","sender":"r@example.com","target":"a@example.com"}' \
           '{"name":"x","channel":"ntfy","url":"https://n.example/t","min_severity":"loud"}'; do
  nl_api POST /system/hooks "$bad"
  [ "$NL_CODE" = 400 ] || nl_fail "bad channel accepted ($NL_CODE): $bad"
done
nl_ok "5 channel types added; 5 bad definitions refused (400)"
nl_api GET /system/hooks
for s in tk_ntfy_test TEST-token Mail-Passw0rd; do grep -F "$s" "$NL_OUT" >/dev/null && nl_fail "secret $s returned by the API"; done
nl_ok "no token or password in GET /system/hooks"
for id in $NTFY $TG $DC $SL $MAIL; do
  nl_api POST "/system/hooks/$id/test" '{}'
  [ "$NL_CODE" = 200 ] || nl_fail "test channel $id: $NL_CODE $(cat "$NL_OUT")"
done
python3 - "$NL_T/notify-http.log" "$NL_T/notify-smtp.log" <<'PY' || nl_fail "test deliveries: $(cat "$NL_T/notify-http.log" "$NL_T/notify-smtp.log")"
import json, sys
http = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
by = {r['path']: r for r in http}
n = by['/alerts']
assert n['headers']['Title'].endswith('INFO: test push'), n
assert n['headers']['Priority'] == 'default' and n['headers']['Authorization'] == 'Bearer tk_ntfy_test', n
assert n['headers']['Content-Type'].startswith('text/plain') and 'this notification channel works' in n['body'], n
t = by['/bot123456:TEST-token/sendMessage']
tb = json.loads(t['body']); assert tb['chat_id'] == '-100777' and 'channel works' in tb['text'], t
assert 'channel works' in json.loads(by['/discord']['body'])['content']
assert 'channel works' in json.loads(by['/slack']['body'])['text']
mails = [json.loads(l) for l in open(sys.argv[2]) if l.strip()]
m = mails[0]
assert m['from'] == '<router@example.com>', m
assert sorted(m['rcpt']) == ['<admin@example.com>', '<ops@example.net>'], m
assert m['auth'] == ['mailer', 'Mail-Passw0rd'], m
assert 'Subject: [' in m['data'] and 'INFO: test mail' in m['data'] and 'To: admin@example.com, ops@example.net' in m['data'], m
PY
nl_ok "send test: ntfy (title/priority/token), Telegram (bot path + chat id), Discord, Slack, email (AUTH, 2 recipients, subject)"

echo "=== 2. a real event fans out by kind and severity"
: > "$NL_T/notify-http.log"; : > "$NL_T/notify-smtp.log"
nl_api POST /routing/gateways "{\"name\":\"WAN_GW\",\"interface\":\"@wan\",\"monitor_ip\":\"$NL_WWW\"}"
[ "$NL_CODE" = 201 ] || nl_fail "add gateway: $NL_CODE $(cat "$NL_OUT")"
sleep 5
ISP nft add table ip nl_icmp
ISP nft "add chain ip nl_icmp f { type filter hook forward priority 0; }"
ISP nft "add rule ip nl_icmp f ip daddr $NL_WWW icmp type echo-request drop"
for _ in $(seq 1 60); do
  M=$(cat "$NL_T/notify-smtp.log"); grep -F gateway "$NL_T/notify-http.log" >/dev/null && [ -n "$M" ] && break; sleep 1
done
sleep 3
python3 - "$NL_T/notify-http.log" "$NL_T/notify-smtp.log" <<'PY' || nl_fail "event fan-out: $(cat "$NL_T/notify-http.log" "$NL_T/notify-smtp.log")"
import json, sys
http = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
paths = [r['path'] for r in http if 'gateway down' in r['body'] or 'gateway_down' in r['body']]
assert '/alerts' in paths and '/discord' in paths, paths
assert '/slack' not in paths, "slack only wants tunnel_down: %r" % paths
n = [r for r in http if r['path'] == '/alerts' and 'gateway down' in r['body']][0]
assert n['headers']['Priority'] == 'urgent' and 'CRITICAL: gateway down WAN_GW' in n['headers']['Title'], n
mails = [json.loads(l) for l in open(sys.argv[2]) if l.strip()]
assert any('CRITICAL: gateway down WAN_GW' in m['data'] for m in mails), mails
PY
nl_ok "gateway_down (critical): ntfy urgent + Discord + email (min critical); Slack (tunnel_down only) skipped"
ISP nft delete table ip nl_icmp
for _ in $(seq 1 60); do grep -F 'gateway up' "$NL_T/notify-http.log" >/dev/null && break; sleep 1; done
sleep 3
python3 - "$NL_T/notify-smtp.log" "$NL_T/notify-http.log" <<'PY' || nl_fail "severity filter: $(cat "$NL_T/notify-smtp.log")"
import json, sys
mails = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
assert not any('gateway up' in m['data'] for m in mails), "info event mailed to a critical-only channel"
assert 'gateway up' in open(sys.argv[2]).read()
PY
nl_ok "gateway_up (info) went to ntfy but not to the critical-only mail channel"

echo "=== 3. a dead server is reported on the channel"
DEAD=$(add "{\"name\":\"dead\",\"channel\":\"ntfy\",\"url\":\"http://$NL_WWW:9299/x\"}")
nl_api POST "/system/hooks/$DEAD/test" '{}'
[ "$NL_CODE" = 502 ] || nl_fail "dead server test: $NL_CODE $(cat "$NL_OUT")"
nl_api GET /system/hooks
case "$(j '[h["last_result"] for h in d if h["name"]=="dead"][0]')" in test:*) ;; *) nl_fail "failure not recorded: $(cat "$NL_OUT")" ;; esac
nl_ok "unreachable channel: 502 on test and the error is shown on the channel"

nl_web_stop
nl_down
echo "lane-h-notify: all checks passed"
