#!/usr/bin/env python3
"""i18n gate for patronus-web (run by the claims step of rust-ci).

1. Catalogs: every language file in crates/patronus-web/i18n/ has exactly the keys of en.ftl and
   the same $variables per key (a translator cannot drop or rename a placeholder); no duplicate keys.
2. Use: every key a template or Rust file uses exists in en.ftl; every en.ftl key is used somewhere
   (err-*, crumb-* and wait-* are looked up by text / page / number at run time).
3. No new hard-coded text: visible text in templates and literal API error messages in Rust may
   not grow past ci/i18n-baseline.json (a file missing from it has a baseline of 0). New code uses
   `{{ "key"|t }}` / `i18n::api_error`. A line marked `i18n-ok` (Rust `// i18n-ok`, template
   `{# i18n-ok #}` on the same line) is not counted: product names, protocol keywords, test data.
   `--update` rewrites the baseline (it may only go down in review).
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WEB = ROOT / "crates" / "patronus-web"
I18N = WEB / "i18n"
BASELINE = ROOT / "ci" / "i18n-baseline.json"
RUNTIME_KEYS = ("err-", "crumb-", "wait-")
ALWAYS_USED = {"lang-name"}

bad = []


def parse_catalog(path):
    """id -> (value text, set of $variables); continuation lines belong to the previous id."""
    out, order = {}, []
    cur = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(.*)$", raw)
        if m:
            cur = m.group(1)
            if cur in out:
                bad.append(f"{path.name}: duplicate key {cur}")
            out[cur] = m.group(2)
            order.append(cur)
        elif cur and raw.startswith((" ", "\t")):
            out[cur] += "\n" + raw
        else:
            cur = None
    return {k: (v, set(re.findall(r"\$([A-Za-z_]\w*)", v))) for k, v in out.items()}


def check_catalogs():
    en = parse_catalog(I18N / "en.ftl")
    for f in sorted(I18N.glob("*.ftl")):
        if f.name == "en.ftl":
            continue
        c = parse_catalog(f)
        for k in sorted(set(en) - set(c)):
            bad.append(f"{f.name}: missing key {k} (add its translation)")
        for k in sorted(set(c) - set(en)):
            bad.append(f"{f.name}: key {k} is not in en.ftl")
        for k in sorted(set(en) & set(c)):
            if en[k][1] != c[k][1]:
                bad.append(f"{f.name}: {k} uses variables {sorted(c[k][1])}, en.ftl has {sorted(en[k][1])}")
            if not c[k][0].strip():
                bad.append(f"{f.name}: {k} is empty")
    return en


def sources():
    for p in sorted((WEB / "src").rglob("*.rs")):
        yield p
    for p in sorted((WEB / "templates").glob("*.html")):
        yield p


def check_use(en):
    used = set()
    pats = [
        r'"([a-z][a-z0-9-]*)"\s*\|\s*t(?:_with)?\b',
        r"\btr\(\s*'([a-z][a-z0-9-]*)'",
        r'\b(?:tr|tr_with|tr_num|tr_in)\(\s*(?:[^,"()]+,\s*)?"([a-z][a-z0-9-]*)"',
        r'\bapi_error\(\s*[^,]+,\s*"([a-z][a-z0-9-]*)"',
        r'data-i18n="([a-z][a-z0-9-]*)"',
    ]
    for p in sources():
        if p.name == "i18n.rs":
            continue
        t = p.read_text(encoding="utf-8")
        if p.suffix == ".rs":
            t = "\n".join(l for l in t.splitlines() if not l.lstrip().startswith("//"))
        for pat in pats:
            for m in re.finditer(pat, t):
                used.add((m.group(1), p.name))
    keys_used = {k for k, _ in used}
    for k, f in sorted(used):
        if k not in en and not k.startswith(RUNTIME_KEYS):
            bad.append(f"{f}: uses key {k}, which en.ftl does not have")
    for k in en:
        if k in ALWAYS_USED or k.startswith(RUNTIME_KEYS):
            continue
        if k not in keys_used:
            bad.append(f"en.ftl: key {k} is not used by any template or Rust file (remove it or use it)")
    # js_catalog serves every js-* key to the pages: those only need to be used by a script
    return en


# ---- hard-coded text counters ----

BRAND = re.compile(r"^(- )?(Patronus( Firewall| @PATRONUS_VERSION@)?|OpenAPI|JSON)( - Patronus( Firewall)?)?$")


def visible_strings(text):
    lines_ok = {i for i, l in enumerate(text.splitlines()) if "i18n-ok" in l}
    t = re.sub(r"\{#.*?#\}", lambda m: " " * len(m.group(0)), text, flags=re.S)
    t = re.sub(r"<!--.*?-->", "", t, flags=re.S)
    t = re.sub(r"<(script|style)\b.*?</\1>", "", t, flags=re.S | re.I)
    t = re.sub(r"\{%.*?%\}", "", t, flags=re.S)
    t = re.sub(r"\{\{.*?\}\}", "\u0001", t, flags=re.S)
    found = []
    for m in re.finditer(r'\b(?:title|placeholder|aria-label|alt)="([^"\u0001]*)"', t):
        v = m.group(1).strip()
        if re.search(r"[A-Za-z]{2}", v) and not BRAND.match(v):
            found.append(v)
    for chunk in re.split(r"<[^>]*>", t):
        v = re.sub(r"&[a-z#0-9]+;", " ", chunk)
        v = re.sub(r"\s+", " ", v.replace("\u0001", " ")).strip()
        if re.search(r"[A-Za-z]{2}", v) and not BRAND.match(v):
            found.append(v)
    if lines_ok:
        # drop strings that sit on an i18n-ok line of the original
        orig = text.splitlines()
        marked = " ".join(orig[i] for i in lines_ok)
        found = [f for f in found if f not in marked]
    return found


LIT_ERR = [
    re.compile(r'"error"\s*:\s*"(?=[^"]*[A-Za-z]{3})'),
    re.compile(r'\b(?:error|bad_request|bad|err_msg)\(\s*(?:StatusCode::[A-Z_]+\s*,\s*)?"(?=[^"]*[A-Za-z]{3})'),
]


def rust_literals(text):
    cut = text.find("#[cfg(test)]")
    body = text if cut < 0 else text[:cut]
    n = 0
    for line in body.splitlines():
        if "i18n-ok" in line or line.lstrip().startswith("//"):
            continue
        for rx in LIT_ERR:
            n += len(rx.findall(line))
    return n


def counts():
    tpl, rs = {}, {}
    for p in sorted((WEB / "templates").glob("*.html")):
        tpl[p.name] = len(visible_strings(p.read_text(encoding="utf-8")))
    for p in sorted((WEB / "src").rglob("*.rs")):
        if p.name == "i18n.rs" or p.name.endswith("_tests.rs"):
            continue
        n = rust_literals(p.read_text(encoding="utf-8"))
        if n:
            rs[str(p.relative_to(WEB / "src"))] = n
    return {"templates": {k: v for k, v in tpl.items() if v}, "rust": rs}


def check_baseline(update):
    cur = counts()
    if update:
        BASELINE.write_text(json.dumps(cur, indent=1, sort_keys=True) + "\n")
        print(f"wrote {BASELINE.relative_to(ROOT)}")
        return
    base = json.loads(BASELINE.read_text()) if BASELINE.exists() else {"templates": {}, "rust": {}}
    for kind, what in (("templates", "hard-coded visible text"), ("rust", "literal API error messages")):
        for f, n in sorted(cur[kind].items()):
            allowed = base.get(kind, {}).get(f, 0)
            if n > allowed:
                bad.append(
                    f"{f}: {n} {what}, baseline {allowed}: new text goes into i18n/en.ftl "
                    + ('(`{{ "key"|t }}`)' if kind == "templates" else "(i18n::api_error)")
                )
    # fully converted files may not regress even if the baseline file is stale
    for f in ("base.html", "login.html", "api_docs.html"):
        if cur["templates"].get(f, 0):
            bad.append(f"{f}: converted to the catalog, but {cur['templates'][f]} text(s) are hard-coded again")


def main():
    en = check_catalogs()
    check_use(en)
    check_baseline("--update" in sys.argv)
    if bad:
        print("check-i18n: FAIL")
        for b in bad:
            print("  -", b)
        return 1
    langs = sorted(p.stem for p in I18N.glob("*.ftl"))
    print(f"check-i18n: ok ({len(en)} keys, languages: {', '.join(langs)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
