#!/usr/bin/env node
// CI regression gate (owner rule: every UI follows the device light/dark setting by default, live).
// Static checks over the source, plus -- when ../static exists -- the built output.
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const errors = []
const fail = (m) => errors.push(m)

const html = readFileSync(join(root, 'index.html'), 'utf8')
if (!/<meta\s+name="color-scheme"\s+content="light dark"/.test(html)) fail('index.html: <meta name="color-scheme" content="light dark"> missing')
for (const scheme of ['light', 'dark']) {
  if (!new RegExp(`<meta\\s+name="theme-color"[^>]*media="\\(prefers-color-scheme: ${scheme}\\)"`).test(html)) {
    fail(`index.html: theme-color meta for prefers-color-scheme: ${scheme} missing`)
  }
}

const tw = readFileSync(join(root, 'tailwind.config.js'), 'utf8')
if (!/darkMode:\s*'media'/.test(tw)) fail("tailwind.config.js: darkMode must be 'media' (follow the system live, no JS/flash)")

const walk = (d) => readdirSync(d).flatMap((f) => {
  const p = join(d, f)
  return statSync(p).isDirectory() ? walk(p) : [p]
})
const src = walk(join(root, 'src')).filter((f) => /\.(tsx?|css)$/.test(f))
const forced = /setDefaultNightMode|classList\.(add|toggle)\(\s*['"]dark['"]|data-theme|localStorage\.\w+\(\s*['"]theme['"]|color-scheme:\s*(dark|light)\s*;/
// Light surfaces/inks that must have a dark: counterpart in the same class string.
const needDark = [
  [/(?<![\w:-])bg-white(?![\w-])/, /dark:bg-/],
  [/(?<![\w:-])bg-gray-(50|100)(?![\w-])/, /dark:bg-/],
  [/(?<![\w:-])text-gray-(500|600|700|800|900)(?![\w-])/, /dark:text-/],
  [/(?<![\w:-])border-gray-(200|300)(?![\w-])/, /dark:border-/],
]
for (const f of src) {
  const t = readFileSync(f, 'utf8')
  const rel = f.slice(root.length + 1)
  if (forced.test(t)) fail(`${rel}: forces a theme (class/data-theme/localStorage/color-scheme literal)`)
  if (!f.endsWith('.tsx')) continue
  // every string literal / template that looks like a class list
  for (const m of t.matchAll(/(["'`])((?:(?!\1)[^\n])*?(?:bg|text|border)-[a-z]+-?\d*(?:(?!\1)[^\n])*)\1/g)) {
    const s = m[2]
    for (const [light, dark] of needDark) {
      if (light.test(s) && !dark.test(s)) {
        // alert/badge strings that carry their own dark variant elsewhere in the same file are not exempt: be strict
        fail(`${rel}: "${s.slice(0, 80)}" has a light-only colour without a dark: variant`)
        break
      }
    }
  }
}

const dist = join(root, '..', 'static', 'assets')
if (existsSync(dist)) {
  const css = readdirSync(dist).filter((f) => f.endsWith('.css')).map((f) => readFileSync(join(dist, f), 'utf8')).join('\n')
  if (!css.includes('prefers-color-scheme:dark') && !css.includes('prefers-color-scheme: dark')) fail('built CSS has no prefers-color-scheme: dark rules')
}

if (errors.length) {
  console.error(errors.map((e) => 'THEME CHECK: ' + e).join('\n'))
  process.exit(1)
}
console.log('theme check ok')
