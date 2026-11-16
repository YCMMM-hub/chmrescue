// Minimal EN/FR strings. Language follows the browser; the page can be forced with ?lang=fr.
const fr = /^fr/i.test((new URLSearchParams(location.search).get('lang')) || navigator.language || '');
export const LANG = fr ? 'fr' : 'en';
const S = {
  en: {
    pick: 'Please choose a .chm file.',
    opening: 'Opening…',
    opened: (n, p, ms) => `${n} — ${p} pages — opened in ${ms} ms. Nothing left your device.`,
    err_duplicate: 'This CHM has duplicate directory entries (some Free Pascal manuals do). CHMRescue cannot open it yet.',
    err_encrypted: 'This CHM looks encrypted or protected. CHMRescue cannot open it.',
    err_notchm: 'This file does not look like a valid CHM (Compiled HTML Help) file.',
    err_open: 'This CHM could not be opened. It may be damaged or use a feature CHMRescue does not support yet.',
    batch_needs_pass: n => `${n} files — the Export Pass lets you export them all at once. The first one is open for reading.`,
    no_page: 'This manual has no readable HTML page.',
    page_fail: 'This page could not be displayed.',
    search_none: 'No result.',
    search_busy: 'Searching…',
    search_n: n => `${n} page${n > 1 ? 's' : ''} found`,
    big: mb => `Large file (${mb} MB): opening may take a few seconds.`,
    zip_busy: (d, t) => `Building the ZIP… ${Math.min(100, Math.round(d * 100 / t))}%`,
    zip_done: (n, mb) => `ZIP ready: ${n} manual${n > 1 ? 's' : ''}, ${mb} MB.`,
    doc_busy: (d, t) => `Assembling pages… ${d}/${t}`,
    doc_done: (n, s) => `Document ready: ${n} pages${s ? ', ' + s + ' skipped' : ''}. Use “Print / Save as PDF”, then choose “Save as PDF” as the printer.`,
    pass_active: '✓ Export Pass active.',
    code_bad: 'That code was not recognised.',
    no_link: 'The payment link is not available yet.',
    part_label: (i, a, b, t) => `Part ${i}: pages ${a}–${b} of ${t}`,
    all_label: n => `All ${n} pages`,
  },
  fr: {
    pick: 'Choisissez un fichier .chm.',
    opening: 'Ouverture…',
    opened: (n, p, ms) => `${n} — ${p} pages — ouvert en ${ms} ms. Rien n’a quitté votre appareil.`,
    err_duplicate: 'Ce CHM contient des entrées de répertoire en double (c’est le cas de certains manuels Free Pascal). CHMRescue ne sait pas encore l’ouvrir.',
    err_encrypted: 'Ce CHM semble chiffré ou protégé. CHMRescue ne peut pas l’ouvrir.',
    err_notchm: 'Ce fichier ne ressemble pas à un fichier CHM (aide HTML compilée) valide.',
    err_open: 'Ce CHM n’a pas pu être ouvert. Il est peut-être endommagé ou utilise une fonction que CHMRescue ne gère pas encore.',
    batch_needs_pass: n => `${n} fichiers — le Pass export permet de tous les exporter d’un coup. Le premier est ouvert en lecture.`,
    no_page: 'Ce manuel ne contient aucune page HTML lisible.',
    page_fail: 'Cette page n’a pas pu être affichée.',
    search_none: 'Aucun résultat.',
    search_busy: 'Recherche…',
    search_n: n => `${n} page${n > 1 ? 's' : ''} trouvée${n > 1 ? 's' : ''}`,
    big: mb => `Gros fichier (${mb} Mo) : l’ouverture peut prendre quelques secondes.`,
    zip_busy: (d, t) => `Création du ZIP… ${Math.min(100, Math.round(d * 100 / t))} %`,
    zip_done: (n, mb) => `ZIP prêt : ${n} manuel${n > 1 ? 's' : ''}, ${mb} Mo.`,
    doc_busy: (d, t) => `Assemblage des pages… ${d}/${t}`,
    doc_done: (n, s) => `Document prêt : ${n} pages${s ? ', ' + s + ' ignorées' : ''}. Cliquez sur « Imprimer / Enregistrer en PDF », puis choisissez « Enregistrer au format PDF ».`,
    pass_active: '✓ Pass export actif.',
    code_bad: 'Ce code n’est pas reconnu.',
    no_link: 'Le lien de paiement n’est pas encore disponible.',
    part_label: (i, a, b, t) => `Partie ${i} : pages ${a}–${b} sur ${t}`,
    all_label: n => `Les ${n} pages`,
  },
};
export const t = (k, ...a) => { const v = S[LANG][k] ?? S.en[k]; return typeof v === 'function' ? v(...a) : v; };
// Static text: elements with data-fr="..." switch to French when LANG is fr.
export function applyStatic() {
  document.documentElement.lang = LANG;
  if (LANG !== 'fr') return;
  document.querySelectorAll('[data-fr]').forEach(el => { el.textContent = el.getAttribute('data-fr'); });
  document.querySelectorAll('[data-fr-ph]').forEach(el => el.setAttribute('placeholder', el.getAttribute('data-fr-ph')));
}
