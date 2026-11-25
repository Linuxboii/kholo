import { b64enc, b64dec, jwt, hash, detect, ts, json, html, hex, url } from './lib.js';
import { $, copy } from './ui.js';

const OPS = {
  auto: ['Auto', null],
  jwt: ['JWT decode', (s) => {
    const d = jwt(s);
    const note = d.expired === null ? 'No expiry claim' : d.expired ? 'Expired' : 'Not expired';
    return { out: `// Header\n${JSON.stringify(d.header, null, 2)}\n\n// Payload\n${JSON.stringify(d.payload, null, 2)}${Object.keys(d.times).length ? `\n\n// Times (UTC)\n${Object.entries(d.times).map(([k, v]) => `${k}: ${v}`).join('\n')}` : ''}`, note: `${note}. Signature not verified.` };
  }],
  b64d: ['Base64 decode', (s) => ({ out: b64dec(s) })],
  b64e: ['Base64 encode', (s) => ({ out: b64enc(s) })],
  b64u: ['Base64 URL-safe', (s) => ({ out: b64enc(s, true) })],
  urld: ['URL decode', (s) => ({ out: url.dec(s) })],
  urle: ['URL encode', (s) => ({ out: url.enc(s) })],
  ts: ['Timestamp', (s) => { const t = ts(s); return { out: `UTC:    ${t.iso}\nLocal:  ${t.local}\nSeconds: ${t.seconds}\nMillis:  ${t.ms}` }; }],
  jsonp: ['JSON pretty', (s) => ({ out: json(s, 2) })],
  jsonm: ['JSON minify', (s) => ({ out: json(s, 0) })],
  hexd: ['Hex to text', (s) => ({ out: hex.dec(s) })],
  hexe: ['Text to hex', (s) => ({ out: hex.enc(s) })],
  htmld: ['HTML decode', (s) => ({ out: html.dec(s) })],
  htmle: ['HTML encode', (s) => ({ out: html.enc(s) })],
  hash: ['Hashes', async (s) => {
    const rows = [];
    for (const a of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) rows.push(`${a.padEnd(8)} ${await hash(s, a)}`);
    return { out: rows.join('\n'), note: 'Hashes of the exact input, including spaces' };
  }],
};
const AUTO = { jwt: 'jwt', timestamp: 'ts', json: 'jsonp', url: 'urld', base64: 'b64d', hex: 'hexd', html: 'htmld', text: 'hash' };
const NAMES = { jwt: 'JWT', timestamp: 'Unix timestamp', json: 'JSON', url: 'URL-encoded', base64: 'Base64', hex: 'Hex', html: 'HTML entities', text: 'Plain text', empty: 'Waiting for input' };

let op = 'auto';
let run = 0;

const ops = $('#ops');
for (const [k, [label]] of Object.entries(OPS)) {
  const b = document.createElement('button');
  b.type = 'button';
  b.textContent = label;
  b.dataset.op = k;
  b.setAttribute('aria-pressed', k === op);
  b.onclick = () => { op = k; for (const x of ops.children) x.setAttribute('aria-pressed', x.dataset.op === op); go(); };
  ops.append(b);
}

async function go() {
  const my = ++run;
  const s = $('#in').value;
  const kind = detect(s);
  $('#kind').textContent = NAMES[kind];
  const err = $('#err');
  if (kind === 'empty') { $('#out').textContent = ''; $('#note').textContent = ''; err.textContent = ''; return; }
  const key = op === 'auto' ? AUTO[kind] : op;
  try {
    const r = await OPS[key][1](s);
    if (my !== run) return;
    $('#out').textContent = r.out;
    $('#note').textContent = (op === 'auto' ? OPS[key][0] + '. ' : '') + (r.note || '');
    err.textContent = '';
  } catch (e) {
    if (my !== run) return;
    $('#out').textContent = '';
    $('#note').textContent = '';
    err.textContent = `${OPS[key][0]} failed: ${e.message || 'input is not in that format'}`;
  }
}

$('#in').addEventListener('input', go);
$('#copy').onclick = () => copy($('#out').textContent, 'Output copied');
$('#chain').onclick = () => { $('#in').value = $('#out').textContent; go(); };
$('#uuid').onclick = () => { $('#in').value = crypto.randomUUID(); op = 'auto'; for (const x of ops.children) x.setAttribute('aria-pressed', x.dataset.op === 'auto'); go(); };
go();
