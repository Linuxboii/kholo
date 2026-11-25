// Encoders and decoders. Pure functions over strings; nothing leaves the page.

const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });

export function b64enc(s, urlSafe = false) {
  let bin = '';
  for (const b of te.encode(s)) bin += String.fromCharCode(b);
  const out = btoa(bin);
  return urlSafe ? out.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : out;
}

export function b64bytes(s) {
  let t = s.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(t)) throw new Error('Not valid Base64.');
  t += '='.repeat((4 - (t.length % 4)) % 4);
  return Uint8Array.from(atob(t), (c) => c.charCodeAt(0));
}

export const b64dec = (s) => td.decode(b64bytes(s));

export function jwt(token, now = Date.now()) {
  const parts = token.trim().split('.');
  if (parts.length !== 3) throw new Error('A JWT has three parts separated by dots.');
  const header = JSON.parse(b64dec(parts[0]));
  const payload = JSON.parse(b64dec(parts[1]));
  const times = {};
  for (const k of ['iat', 'nbf', 'exp']) if (typeof payload[k] === 'number') times[k] = new Date(payload[k] * 1000).toISOString();
  return {
    header,
    payload,
    times,
    expired: typeof payload.exp === 'number' ? payload.exp * 1000 < now : null,
    signature: parts[2],
  };
}

export async function hash(s, algo = 'SHA-256') {
  const buf = await crypto.subtle.digest(algo, te.encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function ts(input) {
  const n = Number(String(input).trim());
  if (!Number.isFinite(n)) throw new Error('Not a number.');
  const ms = Math.abs(n) >= 1e11 ? n : n * 1000;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) throw new Error('Out of range.');
  return { iso: d.toISOString(), local: d.toLocaleString(), seconds: Math.floor(ms / 1000), ms };
}

export const json = (s, indent = 2) => JSON.stringify(JSON.parse(s), null, indent || undefined);

export const html = {
  enc: (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'),
  dec: (s) => s.replace(/&(#x[0-9a-f]+|#\d+|lt|gt|quot|apos|amp|nbsp);/gi, (m, e) => {
    const k = e.toLowerCase();
    if (k[0] === '#') return String.fromCodePoint(k[1] === 'x' ? parseInt(k.slice(2), 16) : parseInt(k.slice(1), 10));
    return { lt: '<', gt: '>', quot: '"', apos: "'", amp: '&', nbsp: ' ' }[k];
  }),
};

export const hex = {
  enc: (s) => [...te.encode(s)].map((b) => b.toString(16).padStart(2, '0')).join(''),
  dec: (s) => {
    const t = s.replace(/0x|[\s:,-]/gi, '');
    if (!/^([0-9a-f]{2})*$/i.test(t)) throw new Error('Not valid hex.');
    return td.decode(Uint8Array.from(t.match(/../g) || [], (h) => parseInt(h, 16)));
  },
};

export const url = {
  enc: (s) => encodeURIComponent(s),
  dec: (s) => decodeURIComponent(s.replace(/\+/g, ' ')),
};

/** Best guess at what was pasted. */
export function detect(s) {
  const t = s.trim();
  if (!t) return 'empty';
  if (/^eyJ[\w-]*\.[\w-]*\.[\w-]*$/.test(t)) return 'jwt';
  if (/^-?\d{9,13}$/.test(t)) return 'timestamp';
  if (/^[[{]/.test(t)) { try { JSON.parse(t); return 'json'; } catch { /* fall through */ } }
  if (/%[0-9a-f]{2}/i.test(t)) return 'url';
  if (t.length >= 8 && t.length % 4 !== 1 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(t)) {
    try { const d = b64dec(t); if (/^[\P{C}\s]*$/u.test(d)) return 'base64'; } catch { /* not text */ }
  }
  if (/^(0x)?([0-9a-f]{2}[\s:]?)+$/i.test(t) && t.replace(/0x|[\s:]/gi, '').length >= 4) return 'hex';
  if (/&(#x?[0-9a-f]+|lt|gt|amp|quot);/i.test(t)) return 'html';
  return 'text';
}
