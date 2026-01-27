# web-threat-detector

Lightweight local detector for suspicious HTML/JS patterns.

Quick start

1. Install dependencies (already present in this workspace):

```bash
npm install
```

2. Start the server:

```bash
npm start
```

3. Use the API:

POST /analyze JSON body: `{ "url": "https://example.com" }` or `{ "html": "<html>...</html>" }`

The response returns `findings` and a `risk.score` from 0-100.
