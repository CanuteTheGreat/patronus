#!/usr/bin/env python3
"""Keep docs/THREAT-MODEL.md honest.

Checks, with no network and no build:
  * every `path/to/file` reference in backticks names a file or directory that exists in the repo;
  * every `path::test_name` reference names a fn that exists in that file;
  * every threat row (a table row whose first cell is T<number>) cites at least one existing test/CI file in its last
    column, or says UNTESTED;
  * the document says plainly that it is not an independent review, and keeps the open item for one.
Exit 1 with a list of problems.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "THREAT-MODEL.md"
FILE_RE = re.compile(r"^[\w./-]+\.(rs|sh|py|yml|yaml|md|toml|conf|json|txt|gpg|asc)$")
TICK = re.compile(r"`([^`]+)`")

problems = []
text = DOC.read_text()

for tok in sorted(set(TICK.findall(text))):
    path, _, fn = tok.partition("::")
    if not ("/" in path and FILE_RE.match(path)):
        continue
    # a bare crate-relative or doc-relative reference: try the repo root, then docs/
    cand = [ROOT / path, ROOT / "docs" / path]
    f = next((c for c in cand if c.exists()), None)
    if f is None:
        problems.append(f"missing file: {path}")
        continue
    if fn and not re.search(r"\bfn\s+%s\b|def\s+%s\b" % (re.escape(fn), re.escape(fn)), f.read_text(errors="replace")):
        problems.append(f"no fn {fn} in {path}")

# bare docs links like [SECURITY.md](../SECURITY.md)
for m in re.finditer(r"\]\((\.\./[^)#]+|[A-Za-z0-9_.-]+\.md)(#[^)]*)?\)", text):
    t = m.group(1)
    if not ((DOC.parent / t).resolve().exists()):
        problems.append(f"broken link: {t}")

rows = 0
for line in text.splitlines():
    if not re.match(r"\|\s*T\d+\s*\|", line):
        continue
    rows += 1
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    last = cells[-1]
    refs = [t for t in TICK.findall(last) if "/" in t.split("::")[0]]
    if "UNTESTED" not in last and not refs:
        problems.append(f"{cells[0]}: no test cited and not marked UNTESTED")
if rows < 30:
    problems.append(f"only {rows} threat rows found (expected the full table)")

low = text.lower()
if "not an independent review" not in low:
    problems.append("the document must say plainly that it is not an independent review")
if not re.search(r"\|\s*R1\s*\|.*independent review", text, re.I):
    problems.append("open item R1 (independent review) is missing")

if problems:
    print("THREAT-MODEL.md problems:")
    for p in problems:
        print("  -", p)
    sys.exit(1)
print(f"THREAT-MODEL.md ok: {rows} threat rows, references resolve")
