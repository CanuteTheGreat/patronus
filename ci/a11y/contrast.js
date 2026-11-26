(() => {
  const dark = matchMedia('(prefers-color-scheme: dark)').matches;
  const parse = c => { const m = c.match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(/[ ,\/]+/).filter(Boolean).map(Number); return {r:p[0],g:p[1],b:p[2],a:p.length>3?p[3]:1}; };
  const over = (f,b) => ({r:f.r*f.a+b.r*(1-f.a),g:f.g*f.a+b.g*(1-f.a),b:f.b*f.a+b.b*(1-f.a),a:1});
  const lin = v => { v/=255; return v<=0.03928? v/12.92 : Math.pow((v+0.055)/1.055,2.4); };
  const L = c => 0.2126*lin(c.r)+0.7152*lin(c.g)+0.0722*lin(c.b);
  const ratio = (a,b) => { const x=L(a),y=L(b); return (Math.max(x,y)+0.05)/(Math.min(x,y)+0.05); };
  const canvas = dark ? {r:18,g:18,b:18,a:1} : {r:255,g:255,b:255,a:1};
  function bgOf(el) {
    const chain = []; let skip = false;
    for (let e = el; e; e = e.parentElement) {
      const cs = getComputedStyle(e);
      if (cs.backgroundImage && cs.backgroundImage !== 'none' && /gradient|url/.test(cs.backgroundImage)) { skip = true; break; }
      const c = parse(cs.backgroundColor); if (c && c.a > 0) { chain.push(c); if (c.a >= 1) break; }
    }
    if (skip) return null;
    let base = canvas; for (let i = chain.length - 1; i >= 0; i--) base = over(chain[i], base);
    return base;
  }
  const bad = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const seen = new Set(); let n = 0;
  while (walker.nextNode()) {
    const t = walker.currentNode; if (!t.nodeValue.trim()) continue;
    const el = t.parentElement; if (!el || seen.has(el)) continue; seen.add(el);
    if (['SCRIPT','STYLE','NOSCRIPT','OPTION'].includes(el.tagName)) continue;
    const r = el.getBoundingClientRect(); const cs = getComputedStyle(el);
    if (r.width < 1 || r.height < 1 || cs.visibility === 'hidden' || cs.display === 'none' || parseFloat(cs.opacity) === 0) continue;
    const fgc = parse(cs.color); const bg = bgOf(el); if (!fgc || !bg) continue;
    const fg = over(fgc, bg); n++;
    const size = parseFloat(cs.fontSize), bold = parseInt(cs.fontWeight) >= 700;
    const need = (size >= 24 || (size >= 18.66 && bold)) ? 3 : 4.5;
    const cr = ratio(fg, bg);
    if (cr < need) bad.push({txt: t.nodeValue.trim().slice(0, 40), cr: +cr.toFixed(2), need, fg: cs.color, bg: `rgb(${Math.round(bg.r)},${Math.round(bg.g)},${Math.round(bg.b)})`, tag: el.tagName + '.' + (el.className && el.className.baseVal === undefined ? el.className : '')});
  }
  return {dark, checked: n, bad};
})()
