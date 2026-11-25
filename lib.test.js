import { test } from 'node:test';
import assert from 'node:assert/strict';
import { b64enc, b64dec, jwt, hash, detect, ts, json, html, hex } from './lib.js';

test('base64 round-trips UTF-8 and handles URL-safe input', () => {
  assert.equal(b64enc('héllo ✓'), 'aMOpbGxvIOKckw==');
  assert.equal(b64dec('aMOpbGxvIOKckw=='), 'héllo ✓');
  assert.equal(b64dec('aMOpbGxvIOKckw'), 'héllo ✓');
  assert.equal(b64enc('??>', true), 'Pz8-');
  assert.equal(b64dec('Pz8-'), '??>');
});

test('jwt decodes header, payload and times without verifying', () => {
  const t = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0MjYyMn0.sig';
  const d = jwt(t, Date.UTC(2026, 0, 1));
  assert.equal(d.header.alg, 'HS256');
  assert.equal(d.payload.sub, '1234567890');
  assert.equal(d.expired, true);
  assert.equal(d.times.iat, '2018-01-18T01:30:22.000Z');
});

test('jwt rejects malformed tokens', () => {
  assert.throws(() => jwt('abc.def'));
});

test('sha-256 of empty string', async () => {
  assert.equal(await hash('', 'SHA-256'), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('detect recognises common inputs', () => {
  assert.equal(detect('eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.x'), 'jwt');
  assert.equal(detect('1764000000'), 'timestamp');
  assert.equal(detect('{"a":1}'), 'json');
  assert.equal(detect('hello%20world'), 'url');
  assert.equal(detect('aGVsbG8gd29ybGQ='), 'base64');
  assert.equal(detect('just words here'), 'text');
});

test('timestamp converts seconds and milliseconds', () => {
  assert.equal(ts('1764000000').iso, '2025-11-24T16:00:00.000Z');
  assert.equal(ts('1764000000000').iso, '2025-11-24T16:00:00.000Z');
});

test('json pretty and minify', () => {
  assert.equal(json('{"a":[1,2]}', 2), '{\n  "a": [\n    1,\n    2\n  ]\n}');
  assert.equal(json('{ "a" : 1 }', 0), '{"a":1}');
});

test('html entities and hex', () => {
  assert.equal(html.enc('<a href="x">&</a>'), '&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;');
  assert.equal(html.dec('&lt;b&gt; &amp;amp; &#39; &#x41;'), '<b> &amp; \' A');
  assert.equal(hex.enc('Hi'), '4869');
  assert.equal(hex.dec('48 69'), 'Hi');
});
