#!/usr/bin/env python3
"""mutate.py <src.toml> <dst.toml> 'old=>new'...: copy a profile with literal replacements (each 'old' must exist)."""
import sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()
for pair in sys.argv[3:]:
    a, b = pair.split("=>", 1)
    assert a in s, "pattern not in profile: " + a
    s = s.replace(a, b)
open(dst, "w").write(s)
