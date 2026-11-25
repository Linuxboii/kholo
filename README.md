# Kholo

Decode JWT, Base64, URL, hex and timestamps offline.

**Live:** https://kholo.avlokai.com

**For:** Developers and security folks who should not paste production tokens into random websites.

## What it does

- Auto-detects JWT, Base64, URL encoding, hex, HTML entities, JSON and Unix timestamps
- JWT header and payload with readable iat, nbf and exp, plus expiry status
- SHA-1, SHA-256, SHA-384 and SHA-512 via Web Crypto
- Encode as well as decode; chain output back to input
- UUID v4 generator

JWT signatures are displayed, not verified. Everything runs on the page.

## Demand

Semrush estimates base64decode.org, a single-purpose Base64 decoder, at roughly 7.7 to 9.7 million visits a month.

- [Semrush: base64decode.org](https://www.semrush.com/website/base64decode.org/overview/)

These figures measure demand for the task, from existing tools. They are third-party estimates or company claims, not usage of this tool.

## Privacy

Everything runs in your browser. There is no backend, no analytics and no account. Nothing you enter is uploaded.

## Run locally

No build step and no runtime dependencies. Serve the folder with any static server:

```
npx serve .
```

## Tests

The logic lives in `lib.js` as pure functions, tested with the Node test runner (Node 20+):

```
npm test
```

## Files

- `index.html` page and styles
- `app.js` wiring between the page and the logic
- `lib.js` pure logic, no DOM
- `lib.test.js` tests
- `base.css`, `ui.js` shared look and small DOM helpers

## Licence

MIT. Made by [Sushanth Kasturi](https://sushanth.avlokai.com).
