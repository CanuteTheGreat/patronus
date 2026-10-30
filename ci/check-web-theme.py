#!/usr/bin/env python3
"""Owner rule 2026-10-30: the Patronus web UI follows the device's light/dark setting by default.

Static guard for crates/patronus-web/templates (the rendered, both-scheme contrast scan lives in
the real-render proof is in the commit message and ~/.hermes/state/dark-mode-review/patronus-web):
  * every full page (<!DOCTYPE html>) pulls in theme_head.html (color-scheme, theme-color per scheme,
    the tokens, the no-flash script) and nothing re-pins one scheme (no body.dark-mode, no theme-color
    without a media query other than the override the head script writes);
  * theme_head.html declares both palettes and the text/background pairs the pages use are >= 4.5:1 in both;
  * the light-only literals that used to be scattered through the pages stay out (use the tokens).
"""
import pathlib, re, sys

root = pathlib.Path(__file__).resolve().parent.parent / "crates" / "patronus-web" / "templates"
head = (root / "theme_head.html").read_text()
bad = []
if 'name="color-scheme" content="light dark"' not in head:
    bad.append("theme_head.html: color-scheme meta must be 'light dark'")
for s in ("light", "dark"):
    if not re.search(r'name="theme-color"[^>]*media="\(prefers-color-scheme: %s\)"' % s, head):
        bad.append(f"theme_head.html: theme-color for {s} missing")
if "@media (prefers-color-scheme: dark)" not in head:
    bad.append("theme_head.html: no prefers-color-scheme: dark palette")
if re.search(r"color-scheme:\s*(dark|light)\s*;", head.split(':root[data-theme="dark"]')[0]):
    bad.append("theme_head.html: :root pins color-scheme (must be 'light dark')")

for f in sorted(root.glob("*.html")):
    t = f.read_text()
    if f.name == "theme_head.html":
        continue
    if "<!DOCTYPE html>" in t and 'include "theme_head.html"' not in t:
        bad.append(f"{f.name}: full page without {{% include \"theme_head.html\" %}}")
    if "dark-mode" in t:
        bad.append(f"{f.name}: body.dark-mode class (the palette is prefers-color-scheme + data-theme)")
    # light-only literals that mean 'a light surface/border/ink' and must be tokens now
    for lit in ("#f8f9fa", "#f3f4f6", "#fcfcfc", "#e5e7eb", "#d1d5db", "#ddd", "#fff3cd", "#f8d7da",
                "#d4edda", "#fee2e2", "#dcfce7", "#fef3c7", "#eff6ff", "#6b7280", "#374151"):
        for m in re.finditer(re.escape(lit) + r"\b", t, re.I):
            bad.append(f"{f.name}: hard-coded {lit} (use the theme tokens)")
            break


def block(name_re):
    m = re.search(name_re, head, re.S)
    return m.group(1) if m else ""


def tokens(b):
    return {k: v.strip() for k, v in re.findall(r"(--[\w-]+):\s*(#[0-9a-fA-F]{6})", b)}


light = tokens(block(r"^\s*:root \{(.*?)\n    \}\n    @media", ) or head.split("@media")[0])
dm = re.search(r"@media \(prefers-color-scheme: dark\) \{\s*:root:not\(\[data-theme=\"light\"\]\) \{(.*?)\n        \}", head, re.S)
dark = {**light, **(tokens(dm.group(1)) if dm else {})}
if not dm:
    bad.append("theme_head.html: dark palette block not found")


def rgb(h):
    return tuple(int(h[i:i + 2], 16) for i in (1, 3, 5))


def lum(c):
    f = lambda x: (x / 255 / 12.92) if x / 255 <= 0.03928 else ((x / 255 + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2])


def ratio(a, b):
    hi, lo = sorted((lum(rgb(a)), lum(rgb(b))), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


PAIRS = [("--text", "--bg"), ("--text", "--card-bg"), ("--text-muted", "--bg"), ("--text-muted", "--card-bg"),
         ("--primary", "--bg"), ("--primary", "--card-bg"), ("--accent", "--card-bg"), ("--ink", "--card-bg"),
         ("--ink-2", "--card-bg"), ("--muted", "--card-bg"), ("--muted", "--surface-2"), ("--ink", "--surface-2"),
         ("--ok-fg", "--ok-bg"), ("--bad-fg", "--bad-bg"), ("--warn-fg", "--warn-bg"), ("--info-fg", "--info-bg"),
         ("--note-fg", "--note-bg"), ("--wnote-fg", "--wnote-bg"), ("--quar-fg", "--quar-bg"),
         ("--bad-fg", "--row-bad"), ("--ink", "--surface-3"), ("--success", "--card-bg"), ("--danger", "--card-bg"),
         ("--warning", "--card-bg"), ("--info", "--card-bg")]
for name, pal in (("light", light), ("dark", dark)):
    for fg, bg in PAIRS:
        if fg not in pal or bg not in pal:
            bad.append(f"{name}: token {fg} or {bg} missing")
            continue
        r = ratio(pal[fg], pal[bg])
        if r < 4.5:
            bad.append(f"{name}: {fg} on {bg} = {r:.2f}:1 (< 4.5)")
    for solid in ("--primary-solid", "--b-primary", "--b-secondary", "--b-success", "--b-info", "--b-danger", "--b-blue"):
        if solid in pal and ratio("#ffffff", pal[solid]) < 4.5:
            bad.append(f"{name}: white on {solid} = {ratio('#ffffff', pal[solid]):.2f}:1 (< 4.5)")
if bad:
    print("check-web-theme: FAIL\n" + "\n".join(bad))
    sys.exit(1)
print("check-web-theme: OK (full pages include theme_head, both palettes >= 4.5:1)")
