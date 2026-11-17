#!/bin/sh
# Host test of ci/embedded-common/accounts-sync (busybox-style sh, no root needed): fresh unit, upgraded unit with the
# account already there, a password the user changed, uid conflict, damaged account dir, idempotence.
D=$(cd "$(dirname "$0")/.." && pwd); S=$D/accounts-sync
W=$(mktemp -d "${TMPDIR:-/tmp}/accsync.XXXX"); trap 'rm -rf "$W"' EXIT
pass=0; failn=0
ok() { pass=$((pass+1)); echo "PASS: accounts-sync: $1"; }
no() { failn=$((failn+1)); echo "FAIL: accounts-sync: $1"; }
chk() { name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else no "$name"; fi; }

HASH='$6$saltsalt$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz01'
mkacc() { # dir
  a=$1/accounts.d/ron; mkdir -p "$a"
  echo 'ron:x:65535:65535:Ron:/data/home/ron:/bin/sh' > "$a/passwd"
  echo "ron:$HASH:20400:0:99999:7:::" > "$a/shadow"
  printf 'ron:x:65535:\npatronus-admin:x:65536:\n' > "$a/group"
  echo patronus-admin > "$a/member-of"
  echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest ron@test' > "$a/authorized_keys"
}
mkunit() { # name -> sets E (etc) and R (root)
  U=$W/$1; E=$U/etc; R=$U/root; mkdir -p "$E/patronus" "$R"
  printf 'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n' > "$E/passwd"
  printf 'root:!:1::::::\n' > "$E/shadow"; chmod 600 "$E/shadow"
  printf 'root:x:0:\nshadow:x:42:\n' > "$E/group"; printf '/bin/sh\n' > "$E/shells"
  mkacc "$U"
}
run() { ACCOUNTS_SRC=$U/accounts.d ACCOUNTS_ETC=$E ACCOUNTS_ROOT=$R sh "$S"; }

# 1. fresh unit
mkunit fresh; out=$(run); rc=$?
chk "fresh unit: exit 0" test $rc = 0
chk "fresh unit: passwd line added" grep -qx 'ron:x:65535:65535:Ron:/data/home/ron:/bin/sh' "$E/passwd"
chk "fresh unit: shadow hash set" grep -q "^ron:$(printf '%s' "$HASH" | sed 's/[$]/\\$/g'):" "$E/shadow"
chk "fresh unit: shadow stays 0600" test "$(stat -c %a "$E/shadow")" = 600
chk "fresh unit: primary and admin groups created" sh -c "grep -qx 'ron:x:65535:' $E/group && grep -qx 'patronus-admin:x:65536:ron' $E/group"
chk "fresh unit: root untouched" grep -qx 'root:!:1::::::' "$E/shadow"
chk "fresh unit: key installed with strict modes" sh -c "test \"\$(stat -c %a $R/data/home/ron/.ssh)\" = 700 && test \"\$(stat -c %a $R/data/home/ron/.ssh/authorized_keys)\" = 600 && grep -q ron@test $R/data/home/ron/.ssh/authorized_keys"
chk "fresh unit: reports what it did" sh -c "echo '$out' | grep -q 'ron: passwd line added'"

# 2. second run changes nothing and says nothing
cp "$E/passwd" "$W/p1"; cp "$E/group" "$W/g1"; cp "$E/shadow" "$W/s1"
out=$(run)
chk "second run: silent" test -z "$out"
chk "second run: files unchanged" sh -c "cmp -s $W/p1 $E/passwd && cmp -s $W/g1 $E/group && cmp -s $W/s1 $E/shadow"

# 3. upgraded unit: account made earlier by the first-run page (nologin, member of patronus-admin, same hash, no state file)
mkunit old
echo 'ron:x:65535:65535::/nonexistent:/sbin/nologin' >> "$E/passwd"; echo "ron:$HASH:20300::::::" >> "$E/shadow"
printf 'ron:x:65535:\npatronus-admin:x:65536:ron,other\n' >> "$E/group"
out=$(run)
chk "upgraded unit: shell and home corrected" grep -qx 'ron:x:65535:65535:Ron:/data/home/ron:/bin/sh' "$E/passwd"
chk "upgraded unit: no duplicate account line" test "$(grep -c '^ron:' "$E/passwd")" = 1
chk "upgraded unit: existing group members kept, no duplicate" sh -c "grep -qx 'patronus-admin:x:65536:ron,other' $E/group && test \$(grep -c '^patronus-admin:' $E/group) = 1"
chk "upgraded unit: shadow line is the package's" grep -qx "ron:$HASH:20400:0:99999:7:::" "$E/shadow"

# 4. a password changed on the box is not undone by a later boot
mkunit chg; run >/dev/null
sed -i "s#^ron:[^:]*:#ron:\$6\$user\$changedbyuser:#" "$E/shadow"
out=$(run)
chk "changed password: kept" grep -q '^ron:\$6\$user\$changedbyuser:' "$E/shadow"
chk "changed password: says so" sh -c "echo '$out' | grep -q 'password was changed on the box, kept'"
# ... and a new package hash replaces the one the package itself set last time
mkunit rot; run >/dev/null
NEW='$6$other$ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ'
echo "ron:$NEW:20500:0:99999:7:::" > "$U/accounts.d/ron/shadow"; run >/dev/null
chk "rotated package hash: applied when the user never changed it" grep -q "^ron:$(printf '%s' "$NEW" | sed 's/[$]/\\$/g'):" "$E/shadow"

# 5. locked account of the same name gets the package password
mkunit lock; echo 'ron:x:65535:65535::/h:/bin/sh' >> "$E/passwd"; echo 'ron:!:1::::::' >> "$E/shadow"; run >/dev/null
chk "locked account: hash applied" grep -q "^ron:\\\$6\\\$saltsalt" "$E/shadow"

# 6. uid belongs to someone else: skipped, nothing overwritten, non-zero exit
mkunit clash; echo 'bob:x:65535:65535::/h:/bin/sh' >> "$E/passwd"; out=$(run); rc=$?
chk "uid conflict: refused" test $rc != 0
chk "uid conflict: other account intact, ron not added" sh -c "grep -qx 'bob:x:65535:65535::/h:/bin/sh' $E/passwd && ! grep -q '^ron:' $E/passwd"

# 7. damaged account directory: skipped
mkunit bad; echo 'mallory:x:0:0::/root:/bin/sh' > "$U/accounts.d/ron/passwd"; out=$(run); rc=$?
chk "passwd line for another name: refused" sh -c "test $rc != 0 && ! grep -q '^mallory:' $E/passwd && ! grep -q '^ron:' $E/passwd"

# 8. no accounts directory: no-op
mkunit none; rm -rf "$U/accounts.d"; cp "$E/passwd" "$W/pn"; out=$(run); rc=$?
chk "no accounts.d: no-op" sh -c "test $rc = 0 && test -z '$out' && cmp -s $W/pn $E/passwd"

# 9. shell that /etc/shells lacks is added (dropbear refuses others)
mkunit shell; sed -i 's#/bin/sh$#/bin/ash#' "$U/accounts.d/ron/passwd"; run >/dev/null
chk "login shell registered in /etc/shells" grep -qx /bin/ash "$E/shells"

echo "accounts-sync tests: $pass passed, $failn failed"
[ "$failn" = 0 ]
