// Cookieless analytics (GoatCounter), website only.
const GOATCOUNTER = 'https://chmrescue.goatcounter.com/count';
if (GOATCOUNTER && location.protocol === 'https:') {
  window.goatcounter = { no_onload: false, endpoint: GOATCOUNTER };
  const s = document.createElement('script');
  s.async = true; s.src = 'https://gc.zgo.at/count.js'; s.setAttribute('data-goatcounter', GOATCOUNTER);
  document.head.appendChild(s);
}
