#!/bin/sh
# build.sh <out-dir>: fetch GL's U-Boot sources at the pinned commit (gl-src.pin, sha256-checked), take their hush parser and
# the test/echo/run commands verbatim, and link them with ubsim.c into <out-dir>/ubsim. Needs curl (or wget) and cc.
# The GL sources are GPL-2.0; they are downloaded at test time and never committed here.
set -eu
H=$(cd "$(dirname "$0")" && pwd); O=${1:?usage: build.sh <out-dir>}; mkdir -p "$O/src" "$O/include/linux"
. "$H/gl-src.pin"
get() { u="https://raw.githubusercontent.com/gl-inet/uboot-for-qca95xx/$GL_COMMIT/$1"
  if [ -n "${GL_SRC_DIR:-}" ] && [ -f "$GL_SRC_DIR/$1" ]; then cp "$GL_SRC_DIR/$1" "$O/src/${1##*/}"
  elif command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 -o "$O/src/${1##*/}" "$u"; else wget -q -O "$O/src/${1##*/}" "$u"; fi
  echo "$2  $O/src/${1##*/}" | sha256sum -c - >/dev/null || { echo "build.sh: $1 does not match the pinned sha256" >&2; exit 1; }; }
get src/common/hush.c "$GL_HUSH_C"; get src/common/command.c "$GL_COMMAND_C"; get src/common/main.c "$GL_MAIN_C"; get src/include/hush.h "$GL_HUSH_H"
cp "$O/src/hush.h" "$O/include/hush.h"; cp "$H/include/common.h" "$H/include/command.h" "$O/include/"
printf '#include <stdlib.h>\n' > "$O/include/malloc.h"; printf '#include <ctype.h>\n' > "$O/include/linux/ctype.h"
# the functions, verbatim: from their definition line to the first closing brace in column 0
fn() { awk -v s="$2" 'index($0, s)==1 {p=1} p {print} p && /^}/ {exit}' "$1"; }
{ echo '#include <common.h>'; echo '#include <command.h>'; echo '#include <hush.h>'
  fn "$O/src/command.c" 'do_echo ('; echo; fn "$O/src/command.c" 'do_test ('; echo; fn "$O/src/main.c" 'int do_run ('; } > "$O/src/glcmds.c"
sed -i 's/^do_echo (/int do_echo (/; s/^do_test (/int do_test (/' "$O/src/glcmds.c"
grep -q '^int do_test' "$O/src/glcmds.c" && grep -q '^int do_echo' "$O/src/glcmds.c" && grep -q '^int do_run' "$O/src/glcmds.c" || { echo "build.sh: could not extract do_test/do_echo/do_run" >&2; exit 1; }
${CC:-cc} -O0 -g -w -std=gnu89 -fcommon -I"$O/include" -o "$O/ubsim" "$H/ubsim.c" "$O/src/hush.c" "$O/src/glcmds.c"
echo "$O/ubsim"
