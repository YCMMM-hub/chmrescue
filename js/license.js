// "Export Pass" licence. The activation code is shown by the payment page after purchase;
// the app stores only the SHA-256 of valid codes. PAYMENT_LINK is the Stripe payment link of the CHMRescue Export Pass (checked at build).
export const CONFIG = {
  PAYMENT_LINK: 'https://buy.stripe.com/8x214m6nF59tbHG9vD4AU05',
  // SHA-256 hashes of valid activation codes (the code itself is never in this file).
  codeHashes: ['ca80e1d7d761abf3d32af47cf0150f0923c10a68bdc7f871adae726ba1b9d8a9'],
  price: '€9',
};
const KEY = 'chmrescue.license';

export async function sha256Hex(text) {
  const data = new TextEncoder().encode(text.trim().toUpperCase());
  const buf = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
export async function isValidCode(code) { if (!code || !code.trim()) return false; return CONFIG.codeHashes.includes(await sha256Hex(code)); }
export function loadLicense() { try { return localStorage.getItem(KEY) || ''; } catch { return ''; } }
export async function hasLicense() { return isValidCode(loadLicense()); }
export async function activate(code) { if (!(await isValidCode(code))) return false; try { localStorage.setItem(KEY, code.trim().toUpperCase()); } catch {} return true; }
