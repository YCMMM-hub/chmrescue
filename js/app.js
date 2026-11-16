// CHMRescue UI. Local only: no network request is ever made from this code.
import { openChm, preparePage, searchArchive, exportZip, documentParts, buildPrintDocument, ChmError, PAGES_PER_PART } from './chm.js';
import { CONFIG, hasLicense, activate } from './license.js';
import { t, LANG, applyStatic } from './i18n.js';

const $ = s => document.querySelector(s);
applyStatic();
const drop = $('#drop'), pick = $('#pick');
const summary = $('#summary'), licenseState = $('#license-state');
const viewer = $('#viewer'), tocEl = $('#toc'), frame = $('#page'), pageTitle = $('#page-title');
const paywall = $('#paywall'), exportModal = $('#export-modal');
let archives = [], current = null, currentPath = null, history = [], hIndex = -1;

// payment link: empty => no buy button, nothing can be purchased
function setPriceUi() {
  document.querySelectorAll('.price-copy').forEach(e => e.textContent = CONFIG.price);
  document.querySelectorAll('.buy-link').forEach(a => { if (CONFIG.PAYMENT_LINK) { a.href = CONFIG.PAYMENT_LINK; a.hidden = false; } else { a.hidden = true; a.removeAttribute('href'); } });
  document.querySelectorAll('.no-link').forEach(e => e.hidden = !!CONFIG.PAYMENT_LINK);
}
setPriceUi();
const say = (msg, err = false) => { summary.textContent = msg; summary.classList.toggle('err', err); };

// ---------- opening ----------
async function handle(fileList) {
  const files = [...fileList].filter(f => /\.chm$/i.test(f.name));
  if (!files.length) return say(t('pick'), true);
  const licensed = await hasLicense();
  say(t('opening'));
  archives.forEach(a => a.close()); archives = []; current = null;
  const errors = []; const t0 = performance.now();
  const useFiles = licensed ? files : files.slice(0, 1);
  for (const f of useFiles) {
    try { archives.push(await openChm(f)); }
    catch (e) { errors.push(f.name + ' — ' + t(e instanceof ChmError ? 'err_' + e.code : 'err_open')); }
  }
  if (!archives.length) { viewer.hidden = true; return say(errors.join(' | '), true); }
  select(0);
  const a = archives[0];
  let msg = t('opened', a.name, a.order.length, Math.round(performance.now() - t0));
  if (files[0].size > 100 * 1024 * 1024) msg += ' ' + t('big', Math.round(files[0].size / 1048576));
  if (!licensed && files.length > 1) { msg += ' ' + t('batch_needs_pass', files.length); openPaywall(); }
  if (errors.length) msg += ' ⚠ ' + errors.join(' | ');
  say(msg, !!errors.length && archives.length === 0);
  renderSwitcher();
}
function renderSwitcher() {
  const sel = $('#switch'); sel.innerHTML = ''; sel.hidden = archives.length < 2;
  archives.forEach((a, i) => { const o = document.createElement('option'); o.value = i; o.textContent = a.name; sel.append(o); });
}
$('#switch').addEventListener('change', e => select(+e.target.value));

function select(i) {
  current = archives[i]; viewer.hidden = false; history = []; hIndex = -1;
  $('#search-results').hidden = true; $('#q').value = ''; tocEl.hidden = false;
  renderToc();
  const home = current.home();
  if (!home) { frame.srcdoc = ''; pageTitle.textContent = ''; return say(t('no_page'), true); }
  show(home, '', 'replace');
}

// ---------- table of contents ----------
function renderToc() {
  tocEl.innerHTML = '';
  const build = (items, parent) => {
    const ul = document.createElement('ul');
    for (const it of items) {
      const li = document.createElement('li');
      const target = it.local ? current.find(it.local.split('#')[0]) : null;
      const kids = it.children && it.children.length;
      const label = document.createElement(target ? 'button' : 'span'); label.textContent = it.name || '…'; label.className = target ? 'toc-link' : 'toc-head';
      if (target) { label.type = 'button'; label.dataset.path = target + (it.local.includes('#') ? '#' + it.local.split('#')[1] : ''); }
      if (kids) { const d = document.createElement('details'); const s = document.createElement('summary'); s.append(label); d.append(s); d.append(build(it.children)); li.append(d); }
      else li.append(label);
      ul.append(li);
    }
    return ul;
  };
  if (current.toc.length) tocEl.append(build(current.toc));
  else { const ul = document.createElement('ul'); for (const p of current.order) { const li = document.createElement('li'); const b = document.createElement('button'); b.type = 'button'; b.className = 'toc-link'; b.textContent = current.titleOf(p); b.dataset.path = p; li.append(b); ul.append(li); } tocEl.append(ul); }
}
tocEl.addEventListener('click', e => { const b = e.target.closest('.toc-link'); if (b) { const [p, f] = b.dataset.path.split('#'); show(p, f || ''); } });

// ---------- page display ----------
function show(path, frag, mode = 'push') {
  if (!current) return;
  let r;
  try { r = preparePage(current, path); } catch { return say(t('page_fail'), true); }
  currentPath = path;
  if (mode === 'push') { history = history.slice(0, hIndex + 1); history.push({ path, frag }); hIndex = history.length - 1; }
  else if (mode === 'replace') { history = [{ path, frag }]; hIndex = 0; }
  pageTitle.textContent = current.titleOf(path);
  $('#prev-page').disabled = !(current.order.indexOf(path) > 0); $('#next-page').disabled = !(current.order.indexOf(path) >= 0 && current.order.indexOf(path) < current.order.length - 1);
  $('#back').disabled = hIndex <= 0; $('#fwd').disabled = hIndex >= history.length - 1;
  frame.onload = () => {
    const d = frame.contentDocument; if (!d) return;
    d.addEventListener('click', ev => {
      const a = ev.target.closest && ev.target.closest('a[data-chm]'); if (!a) { const z = ev.target.closest && ev.target.closest('a.chm-ext'); if (z) ev.preventDefault(); return; }
      ev.preventDefault(); const [p, f] = a.getAttribute('data-chm').split('#'); show(p, f || '');
    });
    if (frag) { try { const el = d.getElementById(frag) || d.getElementsByName(frag)[0]; if (el) el.scrollIntoView(); } catch {} }
    else d.documentElement.scrollTop = 0;
  };
  frame.srcdoc = r.html;
}
function step(delta) { if (!current) return; const i = current.order.indexOf(currentPath) + delta; if (i >= 0 && i < current.order.length) show(current.order[i], ''); }
$('#prev-page').addEventListener('click', () => step(-1));
$('#next-page').addEventListener('click', () => step(1));
$('#back').addEventListener('click', () => { if (hIndex > 0) { hIndex--; show(history[hIndex].path, history[hIndex].frag, 'nav'); } });
$('#fwd').addEventListener('click', () => { if (hIndex < history.length - 1) { hIndex++; show(history[hIndex].path, history[hIndex].frag, 'nav'); } });

// ---------- search ----------
$('#search').addEventListener('submit', e => {
  e.preventDefault(); if (!current) return;
  const out = $('#search-results'); out.hidden = false; delete out.dataset.count; out.textContent = t('search_busy');
  setTimeout(() => {
    const t0 = performance.now(); let res = [];
    try { res = searchArchive(current, $('#q').value, 100); } catch { res = []; }
    out.innerHTML = '';
    const head = document.createElement('p'); head.className = 'muted'; head.textContent = res.length ? t('search_n', res.length) + ' (' + Math.round(performance.now() - t0) + ' ms)' : t('search_none'); out.append(head);
    const ul = document.createElement('ul'); ul.className = 'results';
    for (const r of res) { const li = document.createElement('li'); const b = document.createElement('button'); b.type = 'button'; b.className = 'toc-link'; b.dataset.path = r.path; b.textContent = r.title; const s = document.createElement('small'); s.textContent = r.context.replace(/\s+/g, ' '); li.append(b, s); ul.append(li); }
    out.append(ul);
    out.dataset.count = res.length;
  }, 20);
});
$('#search-results').addEventListener('click', e => { const b = e.target.closest('.toc-link'); if (b) show(b.dataset.path, ''); });
$('#clear-search').addEventListener('click', () => { $('#search-results').hidden = true; $('#q').value = ''; });

// ---------- drop / pick ----------
pick.addEventListener('change', e => { handle(e.target.files); e.target.value = ''; });
['dragover', 'dragenter'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', e => handle(e.dataTransfer.files));

// ---------- export (paid) ----------
async function needPass() { if (await hasLicense()) return false; openPaywall(); return true; }
$('#open-export').addEventListener('click', async () => { if (!current) return; if (await needPass()) return; openExport(); });
function openExport() {
  exportModal.hidden = false; $('#export-msg').textContent = '';
  const sel = $('#doc-part'); sel.innerHTML = '';
  const parts = documentParts(current);
  parts.forEach((p, i) => { const o = document.createElement('option'); o.value = i; o.textContent = parts.length === 1 ? t('all_label', current.order.length) : t('part_label', i + 1, p.from + 1, p.to, current.order.length); sel.append(o); });
  $('#zip-all').hidden = archives.length < 2;
}
$('#close-export').addEventListener('click', () => { exportModal.hidden = true; $('#print-frame').hidden = true; $('#print-btn').hidden = true; });
const download = (blob, name) => { const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = name; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 60000); };
async function runZip(list, name) {
  if (await needPass()) return; const msg = $('#export-msg');
  try {
    const r = await exportZip(window.fflate, list, { onProgress: (d, n) => { msg.textContent = t('zip_busy', d, n); } });
    download(r.blob, name); msg.textContent = t('zip_done', list.length, (r.blob.size / 1048576).toFixed(1));
    if (r.warnings.length) msg.textContent += ' ⚠ ' + r.warnings.length;
  } catch (e) { msg.textContent = '⚠ ' + (e && e.message || e); }
}
$('#zip-one').addEventListener('click', () => runZip([current], current.name.replace(/\.chm$/i, '') + '.zip'));
$('#zip-all').addEventListener('click', () => runZip(archives, 'chm-export.zip'));
let printHtml = '';
$('#make-doc').addEventListener('click', async () => {
  if (await needPass()) return; const msg = $('#export-msg');
  const part = documentParts(current)[+$('#doc-part').value || 0];
  await new Promise(r => setTimeout(r, 20));
  const r = buildPrintDocument(current, part, LANG, (d, n) => { msg.textContent = t('doc_busy', d, n); });
  printHtml = r.html; $('#print-frame').hidden = false; $('#print-frame').srcdoc = r.html; $('#print-btn').hidden = false; $('#save-html').hidden = false;
  msg.textContent = t('doc_done', r.count, r.skipped);
  exportModal.dataset.docCount = r.count; exportModal.dataset.docSkipped = r.skipped; exportModal.dataset.docBytes = r.html.length;
});
$('#print-btn').addEventListener('click', () => { const w = $('#print-frame').contentWindow; if (w) { w.focus(); w.print(); } });
$('#save-html').addEventListener('click', () => download(new Blob([printHtml], { type: 'text/html' }), (current.name.replace(/\.chm$/i, '') || 'manual') + '.html'));
window.__chmrescue = { get printHtml() { return printHtml; } };

// ---------- paywall ----------
function openPaywall() { paywall.hidden = false; }
$('#close-paywall').addEventListener('click', () => paywall.hidden = true);
$('#have-code').addEventListener('click', () => { openPaywall(); $('#code').focus(); });
$('#activate').addEventListener('submit', async e => {
  e.preventDefault();
  if (await activate($('#code').value)) { paywall.hidden = true; $('#code-msg').textContent = ''; licenseState.textContent = t('pass_active'); }
  else { $('#code-msg').textContent = t('code_bad'); }
});
hasLicense().then(ok => { if (ok) licenseState.textContent = t('pass_active'); });
