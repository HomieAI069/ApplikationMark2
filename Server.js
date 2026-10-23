import express from 'express';
import dns from 'node:dns/promises';
import net from 'node:net';

const app = express();
app.use(express.json({ limit: '10kb' }));
app.use(express.static('public'));
const PASS = process.env.APP_PASSWORD || '';
const hits = new Map();

function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
  }
  const l = ip.toLowerCase();
  return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') || l.startsWith('::ffff:');
}
async function safeUrl(u) {
  const url = new URL(u);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Nur http/https erlaubt');
  const addrs = await dns.lookup(url.hostname, { all: true });
  if (!addrs.length || addrs.some(a => isPrivate(a.address))) throw new Error('Adresse nicht erlaubt');
  return url;
}

app.post('/api/scan', async (req, res) => {
  try {
    if (PASS && req.get('x-pass') !== PASS) return res.status(401).json({ error: 'Falsches Passwort' });
    const ip = req.ip, now = Date.now();
    const list = (hits.get(ip) || []).filter(t => now - t < 3600e3);
    if (list.length >= 30) return res.status(429).json({ error: 'Zu viele Scans, bitte später erneut' });
    hits.set(ip, [...list, now]);

    let input = String(req.body.url || '').trim();
    if (!/^https?:\/\//i.test(input)) input = 'https://' + input;
    let url = await safeUrl(input), r;
    const first = url.protocol;
    for (let i = 0; i < 5; i++) {
      r = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(10000),
        headers: { 'user-agent': 'ConsentScan/1.0 (+DSGVO-Check)', accept: 'text/html' } });
      const loc = r.headers.get('location');
      if (r.status >= 300 && r.status < 400 && loc) url = await safeUrl(new URL(loc, url).href); else break;
    }
    const html = (await r.text()).slice(0, 2_000_000);
    const extras = [];
    const cookies = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
    if (first === 'http:' && url.protocol === 'http:')
      extras.push({ s: 'er', t: 'Seite nicht per HTTPS erreichbar', d: 'Die Seite wird unverschlüsselt ausgeliefert.', x: 'SSL-Zertifikat einrichten und HTTP auf HTTPS umleiten.' });
    if (cookies.length) {
      const names = cookies.map(c => c.split('=')[0]).join(', ');
      extras.push({ s: 'er', t: 'Cookies werden schon beim ersten Aufruf gesetzt', d: 'Gefunden: ' + names + '. Nicht notwendige Cookies dürfen erst nach Einwilligung gesetzt werden.', x: 'Prüfen, welche Cookies technisch notwendig sind. Alle anderen erst nach Zustimmung setzen.' });
    }
    if (url.protocol === 'https:' && !r.headers.get('strict-transport-security'))
      extras.push({ s: 'wa', t: 'HSTS-Header fehlt', d: 'Browser werden nicht angewiesen, immer HTTPS zu nutzen.', x: 'Header setzen: Strict-Transport-Security: max-age=31536000; includeSubDomains' });
    res.json({ html, extras, finalUrl: url.href, status: r.status });
  } catch (e) {
    res.status(400).json({ error: 'Abruf fehlgeschlagen: ' + (e.cause?.code || e.message) });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('ConsentScan läuft'));
