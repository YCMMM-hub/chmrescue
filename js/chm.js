// CHMRescue core: open a CHM, render pages safely, search, export. Everything is local.
import { CHMReader } from '../vendor/chmkit/index.mjs';

export const MIME = { png: 'image/png', gif: 'image/gif', jpg: 'image/jpeg', jpeg: 'image/jpeg', bmp: 'image/bmp', svg: 'image/svg+xml', ico: 'image/x-icon', webp: 'image/webp', woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf', otf: 'font/otf' };
export const isHtmlPath = p => /\.html?$/i.test(p);
const extOf = p => (p.match(/\.([A-Za-z0-9]+)$/) || [, ''])[1].toLowerCase();

export class ChmError extends Error { constructor(code, detail) { super(code); this.code = code; this.detail = detail || ''; } }

// ---------- open ----------
export async function openChm(file) {
  let reader;
  try {
    reader = await CHMReader.open(file, { maxFileSize: 256 * 1024 * 1024, maxCacheBytes: 128 * 1024 * 1024 });
  } catch (e) {
    const m = String((e && e.message) || e);
    if (/duplicate|重复|dupl/i.test(m)) throw new ChmError('duplicate', m);
    if (/encrypt|加密/i.test(m)) throw new ChmError('encrypted', m);
    if (/ITSF|signature|magic|not a CHM|invalid|header|签名|格式/i.test(m)) throw new ChmError('notchm', m);
    throw new ChmError('open', m);
  }
  return new Archive(reader, file.name || 'manual.chm');
}

export class Archive {
  constructor(reader, name) {
    this.reader = reader; this.name = name;
    this.files = reader.listFiles('**/*');
    this.lower = new Map(); for (const f of this.files) this.lower.set(f.toLowerCase(), f);
    this.htmlFiles = this.files.filter(isHtmlPath);
    let toc = []; try { toc = reader.getTOC() || []; } catch { toc = []; }
    this.toc = toc;
    this.titles = new Map(); this.order = [];
    const seen = new Set();
    const walk = items => { for (const it of items) {
      const p = it.local ? this.find(it.local.split('#')[0]) : null;
      if (p && !seen.has(p)) { seen.add(p); this.order.push(p); this.titles.set(p, it.name); }
      if (it.children) walk(it.children);
    } };
    walk(toc);
    if (!this.order.length) this.order = [...this.htmlFiles].sort();
    this.title = (reader.getMetadata() || {}).title || name.replace(/\.chm$/i, '');
    this.cache = new Map(); this.cacheBytes = 0;
  }
  close() { try { this.reader.close(); } catch {} this.cache.clear(); }
  find(p) {
    if (!p) return null; let q = p; try { q = decodeURIComponent(p); } catch {}
    if (!q.startsWith('/')) q = '/' + q;
    if (this.files.includes(q)) return q;
    return this.lower.get(q.toLowerCase()) || this.lower.get(p.toLowerCase()) || null;
  }
  home() { const d = this.reader.getDefaultPage && this.reader.getDefaultPage(); return (d && this.find(d)) || this.order[0] || this.htmlFiles[0] || null; }
  titleOf(p) { return this.titles.get(p) || p.split('/').pop(); }
  bytes(p) { return this.reader.readFile(p); }
  html(p) { return this.reader.readHTML(p); }
  // resolve a link found in page `from`; returns {path, frag, external, href}
  resolve(href, from) {
    if (!href) return null;
    let h = href.trim();
    if (/^(javascript|data|vbscript):/i.test(h)) return { external: true };
    const mk = h.match(/^(?:mk:@MSITStore:|ms-its:)[^:]*::(.*)$/i); if (mk) h = mk[1];
    else if (/^[a-z][a-z0-9+.-]*:/i.test(h)) return { external: true };
    const hash = h.indexOf('#'); const frag = hash >= 0 ? h.slice(hash + 1) : ''; const rel = hash >= 0 ? h.slice(0, hash) : h;
    if (!rel) return { path: from, frag };
    let abs;
    try { abs = new URL(rel.startsWith('/') ? rel : rel, 'chm://x' + from).pathname; } catch { return { external: true }; }
    return { path: this.find(abs), frag, tried: abs };
  }
  dataUri(p) {
    if (this.cache.has(p)) return this.cache.get(p);
    let b; try { b = this.bytes(p); } catch { return null; }
    let bin = ''; for (let i = 0; i < b.length; i += 0x8000) bin += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
    const uri = 'data:' + (MIME[extOf(p)] || 'application/octet-stream') + ';base64,' + btoa(bin);
    if (this.cacheBytes > 48e6) { this.cache.clear(); this.cacheBytes = 0; }
    this.cache.set(p, uri); this.cacheBytes += uri.length; return uri;
  }
  cssText(p) {
    let css; try { css = this.reader.readCSS(p); } catch { return ''; }
    return this.fixCss(css, p);
  }
  fixCss(css, from) {
    css = css.replace(/@import[^;]*;?/gi, '');
    return css.replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, u) => {
      if (/^data:/i.test(u)) return m;
      const r = this.resolve(u, from); if (!r || r.external || !r.path) return 'none';
      const d = this.dataUri(r.path); return d ? 'url("' + d + '")' : 'none';
    });
  }
}

export const VIEW_CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:";

// Rename on* attributes inside tags (bounded, linear): parsing them in an extension page would make Chrome log a CSP violation for each one.
const defuseHandlers = h => { // linear scan: rename on* attributes inside tags
  h = String(h); let out = '', i = 0;
  for (;;) {
    const lt = h.indexOf('<', i); if (lt < 0) { out += h.slice(i); break; }
    const gt = h.indexOf('>', lt); if (gt < 0) { out += h.slice(i); break; }
    const tag = h.slice(lt, gt + 1);
    out += h.slice(i, lt) + (/^<[a-z]/i.test(tag) ? tag.replace(/([\s\/])on(?=[a-z]+\s*=)/gi, '$1data-chm-removed-on') : tag);
    i = gt + 1;
  }
  return out;
};
// Make a CHM page safe to show: no scripts, no frames, no network, internal links marked with data-chm.
// opts.print: strip stylesheets, rewrite internal links to in-document anchors via opts.anchor(path) -> id|null.
export function preparePage(archive, path, opts = {}) {
  const raw = archive.html(path);
  // Defuse inline handlers in the source text first: parsing them in an extension page would make Chrome log a CSP violation for each one.
  const defused = defuseHandlers(raw);
  const doc = new DOMParser().parseFromString(defused, 'text/html');
  doc.querySelectorAll('script,noscript,iframe,frame,frameset,object,embed,applet,base,meta[http-equiv],link:not([rel~="stylesheet"]),audio,video,source,track').forEach(n => n.remove());
  // Keep what is inside <form> (many manuals wrap the whole page in one): unwrap it and make controls inert.
  doc.querySelectorAll('form').forEach(f => { while (f.firstChild) f.parentNode.insertBefore(f.firstChild, f); f.remove(); });
  doc.querySelectorAll('input,select,textarea,button').forEach(c => c.setAttribute('disabled', ''));
  if (opts.print) doc.querySelectorAll('style,link[rel~="stylesheet"]').forEach(n => n.remove());
  else {
    doc.querySelectorAll('link[rel~="stylesheet"]').forEach(l => {
      const r = archive.resolve(l.getAttribute('href'), path);
      const s = doc.createElement('style');
      s.textContent = r && r.path ? archive.cssText(r.path) : '';
      l.replaceWith(s);
    });
    doc.querySelectorAll('style').forEach(s => { s.textContent = archive.fixCss(s.textContent, path); });
  }
  for (const el of doc.querySelectorAll('*')) {
    for (const a of [...el.attributes]) {
      const n = a.name.toLowerCase();
      if (n.startsWith('on') || n.startsWith('data-chm-removed') || n === 'srcset' || n === 'ping' || n === 'formaction' || n === 'action' || (n !== 'href' && n.endsWith('href'))) el.removeAttribute(a.name);
      else if (n === 'style' && !opts.print) el.setAttribute('style', archive.fixCss(a.value, path));
      else if (n === 'style') el.setAttribute('style', a.value.replace(/url\([^)]*\)/gi, 'none'));
    }
  }
  doc.querySelectorAll('img,input[type="image"]').forEach(im => {
    const r = archive.resolve(im.getAttribute('src'), path);
    const d = r && !r.external && r.path ? archive.dataUri(r.path) : null;
    if (d) im.setAttribute('src', d); else im.removeAttribute('src');
  });
  doc.querySelectorAll('[background]').forEach(el => {
    const r = archive.resolve(el.getAttribute('background'), path);
    const d = r && !r.external && r.path ? archive.dataUri(r.path) : null;
    if (d && !opts.print) el.setAttribute('background', d); else el.removeAttribute('background');
  });
  doc.querySelectorAll('a[href],area[href]').forEach(a => {
    const href = a.getAttribute('href');
    const r = archive.resolve(href, path);
    a.removeAttribute('target');
    if (!r || r.external) { a.removeAttribute('href'); a.classList.add('chm-ext'); return; }
    if (!r.path) { a.removeAttribute('href'); a.classList.add('chm-dead'); return; }
    if (opts.print) {
      const id = opts.anchor ? opts.anchor(r.path) : null;
      if (id) a.setAttribute('href', '#' + id + (r.frag ? '' : '')); else a.removeAttribute('href');
      return;
    }
    if (r.path === path && r.frag) { a.setAttribute('href', '#' + r.frag); return; }
    a.setAttribute('data-chm', r.path + (r.frag ? '#' + r.frag : '')); a.setAttribute('href', '#');
  });
  const title = (doc.title || '').trim();
  if (opts.print) return { title, body: doc.body ? doc.body.innerHTML : '' };
  const meta = doc.createElement('meta'); meta.setAttribute('http-equiv', 'Content-Security-Policy'); meta.setAttribute('content', VIEW_CSP);
  doc.head.prepend(meta);
  const base = doc.createElement('style'); base.textContent = 'a.chm-ext,a.chm-dead{cursor:not-allowed}img{max-width:100%;height:auto}';
  doc.head.append(base);
  return { title, html: '<!doctype html>' + doc.documentElement.outerHTML };
}

// ---------- search ----------
export function searchArchive(archive, query, max = 100) {
  const q = query.trim(); if (!q) return [];
  const res = archive.reader.search(q, { maxResults: max, maxMatchesPerFile: 1, contextLength: 50 });
  return res.filter(r => isHtmlPath(r.path)).map(r => ({ path: r.path, title: archive.titleOf(r.path), context: (r.matches[0] && r.matches[0].context) || '' }));
}

// ---------- text / markdown ----------
const SKIP = new Set(['SCRIPT', 'STYLE', 'HEAD', 'NOSCRIPT']);
const noHandlers = defuseHandlers;
export function htmlToText(html) {
  const doc = new DOMParser().parseFromString(noHandlers(html), 'text/html');
  doc.querySelectorAll('script,style,noscript').forEach(n => n.remove());
  const t = (doc.body ? doc.body.innerText || doc.body.textContent : '') || '';
  return t.replace(/ /g, ' ').replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim() + '\n';
}
export function htmlToMarkdown(html, linkMap) {
  const doc = new DOMParser().parseFromString(noHandlers(html), 'text/html');
  const out = [];
  const inline = n => {
    if (n.nodeType === 3) return n.nodeValue.replace(/\s+/g, ' ');
    if (n.nodeType !== 1 || SKIP.has(n.tagName)) return '';
    const kids = () => [...n.childNodes].map(inline).join('');
    switch (n.tagName) {
      case 'B': case 'STRONG': { const k = kids().trim(); return k ? '**' + k + '**' : ''; }
      case 'I': case 'EM': { const k = kids().trim(); return k ? '*' + k + '*' : ''; }
      case 'CODE': case 'TT': case 'KBD': case 'SAMP': { const k = n.textContent; return k.trim() ? '`' + k.replace(/`/g, "'") + '`' : ''; }
      case 'BR': return '  \n';
      case 'IMG': return n.getAttribute('alt') ? '[image: ' + n.getAttribute('alt') + ']' : '[image]';
      case 'A': { const k = kids().trim(); const h = n.getAttribute('href') || ''; if (!k) return ''; const m = linkMap && linkMap(h); return m ? '[' + k + '](' + m + ')' : k; }
      default: return kids();
    }
  };
  const block = (n, depth = 0) => {
    if (n.nodeType === 3) { const t = n.nodeValue.replace(/\s+/g, ' ').trim(); if (t) out.push(t + '\n'); return; }
    if (n.nodeType !== 1 || SKIP.has(n.tagName)) return;
    const tag = n.tagName;
    if (/^H[1-6]$/.test(tag)) { const t = inline(n).trim(); if (t) out.push('#'.repeat(+tag[1]) + ' ' + t + '\n'); return; }
    if (tag === 'PRE') { out.push('```\n' + n.textContent.replace(/\n+$/, '') + '\n```\n'); return; }
    if (tag === 'UL' || tag === 'OL') {
      let i = 1; for (const li of n.children) { if (li.tagName !== 'LI') continue;
        const sub = [...li.children].filter(c => /^(UL|OL)$/.test(c.tagName));
        const txt = [...li.childNodes].filter(c => !sub.includes(c)).map(inline).join('').trim();
        out.push('  '.repeat(depth) + (tag === 'OL' ? (i++) + '. ' : '- ') + txt); sub.forEach(s => block(s, depth + 1)); }
      out.push(''); return;
    }
    if (tag === 'TABLE') {
      const rows = [...n.querySelectorAll('tr')].map(tr => [...tr.children].filter(c => /^(TD|TH)$/.test(c.tagName)).map(c => inline(c).trim().replace(/\|/g, '\\|').replace(/\n/g, ' ')));
      if (rows.length) { const w = Math.max(...rows.map(r => r.length)); const pad = r => '| ' + [...r, ...Array(w - r.length).fill('')].join(' | ') + ' |';
        out.push(pad(rows[0])); out.push('|' + ' --- |'.repeat(w)); rows.slice(1).forEach(r => out.push(pad(r))); out.push(''); }
      return;
    }
    if (tag === 'BLOCKQUOTE') { const t = inline(n).trim(); if (t) out.push('> ' + t.replace(/\n/g, '\n> ') + '\n'); return; }
    if (tag === 'P' || tag === 'LI' || tag === 'DT' || tag === 'DD' || tag === 'CAPTION') { const t = inline(n).trim(); if (t) out.push(t + '\n'); return; }
    if (tag === 'HR') { out.push('---\n'); return; }
    const hasBlock = [...n.children].some(c => /^(DIV|P|H[1-6]|UL|OL|PRE|TABLE|BLOCKQUOTE|DL|SECTION|ARTICLE|CENTER|FORM|BODY|HR|FONT)$/.test(c.tagName));
    if (hasBlock || !n.children.length && tag !== 'DIV') { [...n.childNodes].forEach(c => block(c, depth)); return; }
    if (hasBlock) { [...n.childNodes].forEach(c => block(c, depth)); return; }
    const t = inline(n).trim(); if (t) out.push(t + '\n');
  };
  if (doc.body) [...doc.body.childNodes].forEach(c => block(c));
  return out.join('\n').replace(/\n{3,}/g, '\n\n').trim() + '\n';
}

// ---------- ZIP export ----------
function safePath(p) { return p.replace(/^\/+/, '').replace(/\\/g, '/').split('/').filter(s => s && s !== '.' && s !== '..').map(s => s.replace(/[<>:"|?*\u0000-\u001f]/g, '_')).join('/'); }
const tick = () => new Promise(r => setTimeout(r, 0));

// Streams into a Blob so large manuals do not need one giant array. onProgress(done,total).
// Layout: <root>/html/<original tree>, <root>/markdown/*.md, <root>/text/*.txt, <root>/README.txt, <root>/contents.md
export async function exportZip(fflate, archives, { onProgress, signal } = {}) {
  const parts = []; let failure = null;
  const zip = new fflate.Zip((err, chunk, final) => { if (err) { failure = err; return; } parts.push(chunk); });
  const addFile = (name, data, compress) => {
    const f = compress ? new fflate.ZipDeflate(name, { level: 6 }) : new fflate.ZipPassThrough(name);
    zip.add(f); f.push(data, true);
  };
  const enc = new TextEncoder();
  const total = archives.reduce((n, a) => n + a.files.length + a.htmlFiles.length * 2, 0); let done = 0;
  const taken = new Set(); const warnings = [];
  for (const a of archives) {
    let root = safePath(a.name.replace(/\.chm$/i, '')) || 'manual';
    for (let n = 2; taken.has(root.toLowerCase()); n++) root = root + '-' + n;
    taken.add(root.toLowerCase());
    const mdNames = new Set(); const txtNames = new Set(); const names = new Set();
    let nHtml = 0, nOther = 0, nFail = 0;
    const mdPath = new Map();
    for (const p of a.htmlFiles) mdPath.set(p, 'markdown/' + safePath(p).replace(/\.html?$/i, '') + '.md');
    for (const p of a.files) {
      if (signal && signal.aborted) throw new Error('cancelled');
      let name = safePath(p); if (!name) continue;
      let key = 'html/' + name.toLowerCase(); if (names.has(key)) { name = name.replace(/(\.[^./]*)?$/, '-dup$1'); key = 'html/' + name.toLowerCase(); } names.add(key);
      try {
        const bytes = a.bytes(p);
        addFile(root + '/html/' + name, bytes, isHtmlPath(p) || /\.(css|js|txt|xml|hhc|hhk)$/i.test(p));
        if (isHtmlPath(p)) {
          nHtml++;
          const html = a.html(p);
          const linkMap = h => { const r = a.resolve(h, p); if (!r || r.external || !r.path || !isHtmlPath(r.path)) return null;
            const target = mdPath.get(r.path); if (!target) return null;
            const from = mdPath.get(p).split('/'); const to = target.split('/'); from.pop(); while (from.length && to.length > 1 && from[0] === to[0]) { from.shift(); to.shift(); }
            return '../'.repeat(from.length).replace(/^$/, '') + to.join('/') ; };
          const md = htmlToMarkdown(html, linkMap);
          addFile(root + '/' + mdPath.get(p), enc.encode(md), true);
          addFile(root + '/text/' + safePath(p).replace(/\.html?$/i, '') + '.txt', enc.encode(htmlToText(html)), true);
          done += 2;
        } else nOther++;
      } catch (e) { nFail++; warnings.push(p + ': ' + (e && e.message || e)); }
      if (++done % 25 === 0) { if (onProgress) onProgress(done, total); await tick(); }
    }
    const toc = [];
    const walk = (items, d) => { for (const it of items) { const r = it.local && a.find(it.local.split('#')[0]); const link = r && mdPath.get(r);
      toc.push('  '.repeat(d) + '- ' + (link ? '[' + it.name + '](' + link + ')' : it.name)); if (it.children) walk(it.children, d + 1); } };
    walk(a.toc, 0);
    addFile(root + '/contents.md', enc.encode('# ' + a.title + '\n\n' + (toc.join('\n') || '(no table of contents in this file)') + '\n'), true);
    addFile(root + '/README.txt', enc.encode(
      'Exported with CHMRescue from "' + a.name + '". Nothing was uploaded: the conversion ran on your computer.\n\n' +
      'html/      the original files of the manual, same folder structure (open the main page in a browser; scripts inside old CHM pages may not run)\n' +
      'markdown/  each page converted to Markdown (simple conversion: headings, lists, code blocks, tables, links; images are noted, not embedded)\n' +
      'text/      each page as plain text\n' +
      'contents.md  table of contents with links to the Markdown pages\n\n' +
      'HTML pages: ' + nHtml + ' | other files: ' + nOther + ' | failed: ' + nFail + '\n' + (warnings.length ? '\nProblems:\n' + warnings.slice(0, 50).join('\n') + '\n' : '')), true);
  }
  zip.end();
  await tick();
  if (failure) throw failure;
  return { blob: new Blob(parts, { type: 'application/zip' }), warnings };
}

// ---------- single printable document ----------
export const PAGES_PER_PART = 400;
export function documentParts(archive) {
  const o = archive.order; const parts = [];
  for (let i = 0; i < o.length; i += PAGES_PER_PART) parts.push({ from: i, to: Math.min(o.length, i + PAGES_PER_PART) });
  return parts;
}
const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
export const PRINT_CSS = `
@page{margin:18mm 16mm}
body{font:11pt/1.45 system-ui,-apple-system,"Segoe UI",Roboto,Arial,"Noto Sans CJK SC","Hiragino Sans GB","PingFang SC","Microsoft YaHei",sans-serif;color:#111;margin:0}
h1,h2,h3,h4{break-after:avoid}
pre,code,tt,kbd,samp{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:9.5pt}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f4;padding:6px;break-inside:avoid-page}
table{border-collapse:collapse;max-width:100%}td,th{border:1px solid #bbb;padding:3px 6px;vertical-align:top}
img{max-width:100%;height:auto}
.cover{break-after:page;padding-top:30vh;text-align:center}.cover h1{font-size:28pt}.cover p{color:#555}
.toc{break-after:page}.toc ol{list-style:none;padding-left:0}.toc li{margin:2px 0}.toc a{color:#111;text-decoration:none}
section.chm-page{break-before:page}section.chm-page>h2.pg{font-size:15pt;border-bottom:1px solid #999;padding-bottom:4px;margin-top:0}
a{color:#0b4f8a}`;
// Returns {html, count, skipped}. Pages are taken in table-of-contents order.
export function buildPrintDocument(archive, part, lang = 'en', onProgress) {
  const paths = archive.order.slice(part.from, part.to);
  const ids = new Map(paths.map((p, i) => [p, 'p' + (part.from + i)]));
  const sections = []; let skipped = 0;
  paths.forEach((p, i) => {
    try {
      const r = preparePage(archive, p, { print: true, anchor: q => ids.get(q) || null });
      sections.push('<section class="chm-page" id="' + ids.get(p) + '"><h2 class="pg">' + esc(archive.titleOf(p)) + '</h2>' + r.body + '</section>');
    } catch { skipped++; }
    if (onProgress && i % 20 === 0) onProgress(i + 1, paths.length);
  });
  const L = lang === 'fr' ? { toc: 'Table des matières', gen: 'Document assemblé par CHMRescue sur votre ordinateur — aucun envoi.', part: 'Partie', of: 'pages' } : { toc: 'Contents', gen: 'Assembled by CHMRescue on your computer — nothing uploaded.', part: 'Part', of: 'pages' };
  const toc = paths.map(p => '<li><a href="#' + ids.get(p) + '">' + esc(archive.titleOf(p)) + '</a></li>').join('');
  const range = archive.order.length > PAGES_PER_PART ? '<p>' + L.part + ' ' + (part.from / PAGES_PER_PART + 1) + ' — ' + L.of + ' ' + (part.from + 1) + '–' + part.to + ' / ' + archive.order.length + '</p>' : '';
  const html = '<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="' + VIEW_CSP + '"><title>' + esc(archive.title) + '</title><style>' + PRINT_CSS + '</style></head><body>' +
    '<div class="cover"><h1>' + esc(archive.title) + '</h1>' + range + '<p>' + L.gen + '</p></div>' +
    '<nav class="toc"><h1>' + L.toc + '</h1><ol>' + toc + '</ol></nav>' + sections.join('') + '</body></html>';
  return { html, count: sections.length, skipped };
}
