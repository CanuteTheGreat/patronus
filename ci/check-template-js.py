#!/usr/bin/env python3
"""check-template-js.py: every inline <script> block of the web UI templates must parse as JavaScript.

The templates are rendered by askama, so `{% ... %}` tags are replaced by a neutral `true` (expression context) or
removed (statement lines) and `{{ ... }}` by a string literal before `node --check`. A syntax error anywhere in a page's
script stops the whole page (found 2026-11-18: an unbalanced parenthesis left the Wi-Fi page at "Loading..." for a day).
Usage: ci/check-template-js.py [TEMPLATE_DIR]   (default crates/patronus-web/templates); needs node on PATH.
"""
import os, re, subprocess, sys, tempfile

root = sys.argv[1] if len(sys.argv) > 1 else "crates/patronus-web/templates"
script_re = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S | re.I)
bad = 0
checked = 0
for dirpath, _, files in os.walk(root):
    for name in sorted(files):
        if not name.endswith(".html"):
            continue
        path = os.path.join(dirpath, name)
        text = open(path, encoding="utf-8").read()
        for i, m in enumerate(script_re.finditer(text)):
            js = m.group(1)
            if not js.strip():
                continue
            # an askama if/else used as a value: "{% if x %}a{% else %}b{% endif %}" -> a
            js = re.sub(r"\{%\s*if[^%]*%\}(.*?)\{%\s*else\s*%\}.*?\{%\s*endif\s*%\}", r"\1", js, flags=re.S)
            js = re.sub(r"\{%.*?%\}", "", js, flags=re.S)
            js = re.sub(r"\{\{.*?\}\}", '"x"', js, flags=re.S)
            line0 = text[: m.start(1)].count("\n")
            with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
                f.write("\n" * line0 + js)
                tmp = f.name
            r = subprocess.run(["node", "--check", tmp], capture_output=True, text=True)
            os.unlink(tmp)
            checked += 1
            if r.returncode != 0:
                bad += 1
                msg = r.stderr.replace(tmp, path).strip().splitlines()
                print(f"check-template-js: {path} script {i + 1}:")
                for l in msg[:6]:
                    print("    " + l)
if checked == 0:
    print("check-template-js: no inline scripts found under " + root)
    sys.exit(1)
print(f"check-template-js: {checked} inline script(s), {bad} with a syntax error")

# <input pattern="..."> is compiled by browsers with the `v` (unicodeSets) flag: there an unescaped `-` at the edge of a
# class ("[a-z0-9_-]") or other class syntax characters are errors, the browser logs a console error and silently skips
# the check (found 2026-11-25 by the UX crawl on the System page's host name field). Compile every pattern the same way.
pattern_re = re.compile(r'\bpattern="([^"]*)"')
pats = []
for dirpath, _, files in os.walk(root):
    for name in sorted(files):
        if name.endswith(".html"):
            path = os.path.join(dirpath, name)
            text = open(path, encoding="utf-8").read()
            for m in pattern_re.finditer(text):
                p = m.group(1)
                if "{{" in p or "{%" in p:
                    continue
                p = p.replace("&quot;", '"').replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
                pats.append((f"{path}:{text[: m.start()].count(chr(10)) + 1}", p))
js = "const P=" + __import__("json").dumps(pats) + ";let b=0;for(const [w,p] of P){try{new RegExp('^(?:'+p+')$','v')}catch(e){b++;console.log('check-template-js: '+w+': pattern '+JSON.stringify(p)+' is invalid with the v flag: '+e.message)}}process.exit(b?1:0)"
r = subprocess.run(["node", "-e", js], capture_output=True, text=True)
print(r.stdout.strip() or f"check-template-js: {len(pats)} input pattern(s) compile with the v flag")
if r.returncode != 0:
    bad += 1
sys.exit(1 if bad else 0)
