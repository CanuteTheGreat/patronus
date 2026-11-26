#!/usr/bin/env python3
"""Owner rule 2026-10-30: the Patronus web UI follows the device's light/dark setting by default.

Static guard for crates/patronus-web/templates. Since the shared ui-kit adoption the palette is
ui-kit/tokens.css (light + dark) overlaid by the Patronus theme layer theme/patronus.css (brand accent and
the legacy token names the pages still use, mapped onto kit tokens with var()). This check:
  * every full page (<!DOCTYPE html>) pulls in theme_head.html (color-scheme, theme-color per scheme,
    the kit + theme stylesheets, the no-flash script) and nothing re-pins one scheme (no body.dark-mode);
  * theme_head.html loads tokens.css, components.css and patronus.css (in that order) and declares no palette of
    its own;
  * the resolved light and dark palettes keep every text/background pair the pages use >= 4.5:1, and white
    text on every solid fill >= 4.5:1;
  * the light-only literals that used to be scattered through the pages stay out (use the tokens).
"""
import pathlib, re, sys

web = pathlib.Path(__file__).resolve().parent.parent / "crates" / "patronus-web"
root = web / "templates"
head = (root / "theme_head.html").read_text()
bad = []
if 'name="color-scheme" content="light dark"' not in head:
    bad.append("theme_head.html: color-scheme meta must be 'light dark'")
for s in ("light", "dark"):
    if not re.search(r'name="theme-color"[^>]*media="\(prefers-color-scheme: %s\)"' % s, head):
        bad.append(f"theme_head.html: theme-color for {s} missing")
if "localStorage.getItem('patronus-theme')" not in head:
    bad.append("theme_head.html: no-flash script (patronus-theme) missing")
order = [head.find(f'href="/ui-kit/{f}') for f in ("tokens.css", "components.css", "patronus.css")]
if min(order) < 0 or order != sorted(order):
    bad.append("theme_head.html: must link /ui-kit/tokens.css, components.css, patronus.css in that order")
if re.search(r"--[\w-]+\s*:\s*#[0-9a-fA-F]{3,6}", head):
    bad.append("theme_head.html: declares colour tokens itself (they live in ui-kit + theme/patronus.css)")
if re.search(r":root\s*{[^}]*color-scheme:\s*(dark|light)\s*;", head):
    bad.append("theme_head.html: :root pins color-scheme (must be 'light dark')")

for f in sorted(root.glob("*.html")):
    t = f.read_text()
    if f.name == "theme_head.html":
        continue
    if "<!DOCTYPE html>" in t and 'include "theme_head.html"' not in t:
        bad.append(f"{f.name}: full page without {{% include \"theme_head.html\" %}}")
    if "dark-mode" in t:
        bad.append(f"{f.name}: body.dark-mode class (the palette is prefers-color-scheme + data-theme)")
    for lit in ("#f8f9fa", "#f3f4f6", "#fcfcfc", "#e5e7eb", "#d1d5db", "#ddd", "#fff3cd", "#f8d7da",
                "#d4edda", "#fee2e2", "#dcfce7", "#fef3c7", "#eff6ff", "#6b7280", "#374151"):
        for m in re.finditer(re.escape(lit) + r"\b", t, re.I):
            bad.append(f"{f.name}: hard-coded {lit} (use the theme tokens)")
            break


def strip(s):
    return re.sub(r"/\*.*?\*/", "", s, flags=re.S)


def decls(body):
    return {k: v.strip() for k, v in re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", body)}


def palettes(src):
    """(light, dark) declarations of one stylesheet: plain :root blocks, and the dark blocks
    (@media dark :root:not([data-theme=light]) and :root[data-theme=dark]; both must agree)."""
    src = strip(src)
    light, dark_m, dark_a = {}, {}, {}
    for m in re.finditer(r"@media \(prefers-color-scheme: dark\)\s*{\s*:root:not\(\[data-theme=\"light\"\]\)\s*{(.*?)}\s*}", src, re.S):
        dark_m.update(decls(m.group(1)))
    rest = re.sub(r"@media[^{]*{(?:[^{}]*{[^{}]*})*\s*}", "", src, flags=re.S)
    for m in re.finditer(r"(?:^|})\s*:root\s*{(.*?)}", rest, re.S):
        light.update(decls(m.group(1)))
    for m in re.finditer(r":root\[data-theme=\"dark\"\]\s*{(.*?)}", rest, re.S):
        dark_a.update(decls(m.group(1)))
    for k in set(dark_m) ^ set(dark_a):
        bad.append(f"dark token {k} set in only one of the @media / [data-theme=dark] blocks")
    for k in set(dark_m) & set(dark_a):
        if dark_m[k] != dark_a[k]:
            bad.append(f"dark token {k}: @media {dark_m[k]} != [data-theme=dark] {dark_a[k]}")
    return light, dark_m


light, dark = {}, {}
for sheet in (web / "ui-kit" / "tokens.css", web / "theme" / "patronus.css"):
    l, d = palettes(sheet.read_text())
    light.update(l)
    dark.update(l)
    dark.update(d)


def resolve(pal, name, depth=0):
    v = pal.get(name)
    if v is None or depth > 8:
        return None
    m = re.fullmatch(r"var\((--[\w-]+)\)", v)
    if m:
        return resolve(pal, m.group(1), depth + 1)
    return v if re.fullmatch(r"#[0-9a-fA-F]{6}", v) else None


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
         ("--bad-fg", "--row-bad"), ("--success", "--card-bg"), ("--danger", "--card-bg"),
         ("--warning", "--card-bg"), ("--info", "--card-bg"),
         # kit tokens as the migrated pages use them
         ("--c-ink", "--c-canvas"), ("--c-ink", "--c-surface"), ("--c-ink", "--c-sunken"),
         ("--c-muted", "--c-surface"), ("--c-muted", "--c-canvas"), ("--c-muted", "--c-sunken"),
         ("--c-accent", "--c-surface"), ("--c-accent", "--c-canvas"), ("--c-accent", "--c-accent-subtle"),
         ("--c-ok", "--c-ok-bg"), ("--c-warn", "--c-warn-bg"), ("--c-crit", "--c-crit-bg"), ("--c-info", "--c-info-bg"),
         ("--c-ok", "--c-surface"), ("--c-warn", "--c-surface"), ("--c-crit", "--c-surface"), ("--c-info", "--c-surface"),
         ("--c-chrome-ink", "--c-chrome"), ("--c-chrome-muted", "--c-chrome"), ("--c-brand", "--c-surface")]
SOLIDS = ("--primary-solid", "--b-primary", "--b-secondary", "--b-success", "--b-info", "--b-danger", "--b-blue",
          "--c-accent-solid", "--c-accent-hover", "--c-ok-solid", "--c-crit-solid", "--c-info-solid", "--c-warn-solid",
          "--c-neutral-solid")
for name, pal in (("light", light), ("dark", dark)):
    for fg, bg in PAIRS:
        a, b = resolve(pal, fg), resolve(pal, bg)
        if a is None or b is None:
            bad.append(f"{name}: token {fg} or {bg} missing / not a #rrggbb colour")
            continue
        r = ratio(a, b)
        if r < 4.5:
            bad.append(f"{name}: {fg} ({a}) on {bg} ({b}) = {r:.2f}:1 (< 4.5)")
    for solid in SOLIDS:
        c = resolve(pal, solid)
        if c is None:
            bad.append(f"{name}: solid {solid} missing")
        elif ratio("#ffffff", c) < 4.5:
            bad.append(f"{name}: white on {solid} ({c}) = {ratio('#ffffff', c):.2f}:1 (< 4.5)")
if bad:
    print("check-web-theme: FAIL\n" + "\n".join(bad))
    sys.exit(1)
print(f"check-web-theme: OK (full pages include theme_head, kit + Patronus theme, {len(PAIRS)} pairs >= 4.5:1 light+dark)")
