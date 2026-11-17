# 🛡️ Web Threat Detector

Web Threat Detector is a lightweight, local security tool that scans HTML and JavaScript content to identify suspicious patterns, malicious scripts, and potential web threats.
It is designed for developers, security learners, and researchers who want a fast way to analyze webpages or raw HTML safely.

# 🚀 Features

🔍 Detects suspicious HTML & JavaScript patterns

⚠️ Assigns a risk score (0–100)

🌐 Analyze by URL or raw HTML

⚡ Fast, lightweight, and runs locally

🔒 No data is sent to third-party servers

📦 Simple REST API interface

# Quick start

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
