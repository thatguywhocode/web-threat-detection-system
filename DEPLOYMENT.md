# SecuNexis — Render Production Deployment Guide

This guide provides end-to-end instructions for deploying the **SecuNexis Web Threat Detection & Security Analysis Platform** to **Render** as a unified full-stack Web Service.

---

## 1. Architecture Overview

SecuNexis is deployed as **ONE Render Web Service** combining the static cybersecurity dashboard frontend and the Node.js Express threat detection backend:

- **Frontend**: High-performance Vanilla HTML5, CSS3, and JavaScript, served directly from the `/frontend` directory using absolute filesystem resolution.
- **Backend**: Node.js & Express engine running on `0.0.0.0:${PORT}` (`process.env.PORT || 3000`).
- **Detection Analyzers**: Cheerio DOM Inspector, JavaScript Heuristic Engine, VirusTotal v3 Threat Intelligence Feed.
- **Database**: MongoDB Atlas for persistent SOC SecurityEvent stream and audit logs, with an automatic resilient in-memory fallback.
- **Security Controls**: Integrated SSRF protection, private IP blocking, cloud metadata defense, rate limiting, and security headers.

```
                           +---------------------------+
                           |  Render Cloud Load Balancer|
                           +-------------+-------------+
                                         |
                                         v
                         +---------------+---------------+
                         |     Render Web Service        |
                         |   (Node.js / Express Server)  |
                         |        Host: 0.0.0.0          |
                         +---------------+---------------+
                                         |
               +-------------------------+-------------------------+
               |                                                   |
               v                                                   v
      [Static Frontend Assets]                            [REST API Endpoints]
     - GET / (Dashboard HTML)                            - POST /scan
     - GET /style.css                                    - GET  /api/soc/events
     - GET /script.js                                    - GET  /api/soc/events/stats
     - Static UI components                              - GET  /api/soc/events/:id
                                                         - GET  /health (Monitoring)
               |                                                   |
               +-------------------------+-------------------------+
                                         |
                                         v
                   +---------------------+---------------------+
                   |                                           |
                   v                                           v
       [MongoDB Atlas Cluster]                     [VirusTotal v3 API]
     (Persistent Security Events)              (Global URL Reputation)
```

---

## 2. Prerequisites

1. **GitHub Account & Repository**:
   - Repository: `https://github.com/thatguywhocode/web-threat-detection-system`
2. **Render Account**:
   - Register at [render.com](https://render.com).
3. **MongoDB Atlas Account** (Free tier supported):
   - Register at [mongodb.com/atlas](https://www.mongodb.com/atlas).
4. **VirusTotal Account** (Free tier supported):
   - Register at [virustotal.com](https://www.virustotal.com).

---

## 3. External Services Setup

### 3.1. MongoDB Atlas Configuration

1. Log in to [MongoDB Atlas](https://cloud.mongodb.com).
2. Create a **Shared (Free M0)** cluster in your preferred region.
3. **Network Access**:
   - In the left sidebar under **Security**, click **Network Access**.
   - Click **Add IP Address**.
   - Select **Allow Access from Anywhere** (`0.0.0.0/0`).
   - *Reason*: Render services use dynamic outbound IP addresses from a large cloud pool; `0.0.0.0/0` is required for connection continuity.
4. **Database Access**:
   - Under **Security**, click **Database Access**.
   - Click **Add New Database User**.
   - Choose **Password** authentication.
   - Enter a username (e.g., `secunexis_admin`) and a strong password.
   - Assign the built-in role **Read and write to any database**.
5. **Get Connection String**:
   - Go to **Database Deployments** > click **Connect**.
   - Select **Drivers** (Node.js).
   - Copy the connection string (format):
     ```
     mongodb+srv://secunexis_admin:<password>@cluster0.xxxxx.mongodb.net/secunexis?retryWrites=true&w=majority
     ```
   - Replace `<password>` with your database user password.

### 3.2. VirusTotal API Key Configuration

1. Log in to [VirusTotal](https://www.virustotal.com).
2. Click your user avatar in the top-right corner and select **API key**.
3. Copy your 64-character API key.
4. Note: Free VirusTotal API keys have a rate limit of 4 requests/minute and 500 requests/day, which is fully supported by the detection engine.

---

## 4. Step-by-Step Render Deployment

### Step 1: Create a New Web Service
1. Log in to your [Render Dashboard](https://dashboard.render.com).
2. Click the **New +** button in the top navigation bar and select **Web Service**.
3. Connect your GitHub account if not already connected.
4. Search for and select the repository: `thatguywhocode/web-threat-detection-system`.

### Step 2: Configure Service Parameters
Configure the service with the exact values below:

| Field | Value | Notes |
| :--- | :--- | :--- |
| **Name** | `secunexis` *(or your preferred app name)* | Becomes your default URL: `https://<name>.onrender.com` |
| **Region** | Choose nearest region (e.g., *Frankfurt*, *Oregon*, *Singapore*) | Lower latency to your target users |
| **Branch** | `main` | Production branch to build from |
| **Root Directory** | *(Leave blank)* | Uses repository root directory |
| **Runtime** | `Node` | Standard Node.js environment |
| **Build Command** | `npm install` | Installs all production dependencies |
| **Start Command** | `npm start` | Runs `node src/server.js` |
| **Instance Type** | `Free` *(or Starter+)* | Compatible with Free tier (512MB RAM) |

### Step 3: Configure Environment Variables
Scroll down to the **Environment Variables** section and add:

| Key | Value | Description |
| :--- | :--- | :--- |
| `NODE_ENV` | `production` | Enables production optimizations and security rules |
| `PORT` | `3000` | *Optional*: Render sets this automatically; Express listens on `0.0.0.0` |
| `MONGODB_URI` | `mongodb+srv://...` | MongoDB Atlas connection string from Step 3.1 |
| `VIRUSTOTAL_API_KEY` | `your_64_char_vt_api_key` | VirusTotal v3 API key from Step 3.2 |

> [!IMPORTANT]
> Never commit real credentials to `.env` in Git. All production secrets must be set exclusively in the Render Dashboard Environment Variables section.

### Step 4: Configure Health Check Path
1. Under **Advanced** settings, find the **Health Check Path** field.
2. Enter `/health`.
3. Render will poll `GET /health` during deployment to verify container readiness before directing live traffic.

### Step 5: Deploy
1. Click **Create Web Service**.
2. Render will clone the repository, run `npm install`, start `node src/server.js`, and verify the health check.
3. Once the build log displays `SecuNexis Web Threat Detection Platform running on http://0.0.0.0:...` and the health check responds `200 OK`, the status turns green: **Live**.
4. Your application is live at `https://<your-service-name>.onrender.com`.

---

## 5. Production Verification Checklist

Run through these 15 verification steps on your deployed Render URL (`https://<app>.onrender.com`):

| # | Test Check | Procedure | Expected Result |
| :-: | :--- | :--- | :--- |
| **1** | **Root Dashboard Access** | Open `https://<app>.onrender.com/` in browser | Loads dark-navy SecuNexis SOC dashboard with all charts, metrics, and navigation. |
| **2** | **Frontend Asset Loading** | Inspect DevTools Network tab | `style.css` and `script.js` load with `200 OK` from same origin without 404 errors. |
| **3** | **Health Check Monitoring** | Navigate to `/health` and `/api/health` | `/health` returns `200 OK`, `/api/health` returns `{"status":"ok",...}`. |
| **4** | **Safe URL Scanning** | Scan `https://github.com` or `https://google.com` | Verdict: **SAFE**, Risk Score: **0/100**, Severity: **LOW**. |
| **5** | **Suspicious URL Scanning** | Scan sample with obscured iframe or heavy obfuscation | Verdict: **SUSPICIOUS**, Risk Score: **20-69/100**, Severity: **LOW/MEDIUM**. |
| **6** | **Malicious Sample Handling** | Scan sample with hidden credential harvesting form | Verdict: **MALICIOUS**, Risk Score: **70-100/100**, Severity: **HIGH**. |
| **7** | **Raw HTML Analysis** | Switch to HTML mode, paste HTML snippet, click Scan | Full heuristic inspection executes; result displays with structured findings. |
| **8** | **Empty & Invalid Input** | Submit empty string or invalid domain | Displays alert: *"Provide either 'html' or 'url' in request body"* or *"Invalid URL format"*. |
| **9** | **VirusTotal Available State** | Scan live domain with `VIRUSTOTAL_API_KEY` configured | VirusTotal section displays engine breakdown (e.g. `90/90 engines checked`) and clean status. |
| **10** | **VirusTotal Unavailable Fallback** | Scan without API key | Returns clean fallback: *"Reputation check unavailable. No reputation conclusion can be drawn."* Score remains strictly based on static heuristics. |
| **11** | **Risk Score Calculation** | Inspect result score breakdown | Composite risk score strictly equals sum of scored threat points capped at 100. |
| **12** | **Historical Scan Restoration** | Click any scan in Recent History or Timeline | Re-populates scanner and restores complete verdict, gauge, evidence table, and remediation. |
| **13** | **Report Downloads** | Click *Download TXT Report* and *Download PDF* | TXT generates clean audit text; PDF generates formatted executive report. |
| **14** | **SOC Event Retrieval** | Inspect Threat Activity Timeline on Dashboard | Chronologically indexes completed scans from `GET /api/soc/events`. Refresh and pagination work. |
| **15** | **SSRF Defense** | Submit `http://127.0.0.1:8080` or `http://169.254.169.254` | Returns HTTP 400 with *"Target resolves to restricted private IP space (SSRF protection)"*. |

---

## 6. Security & Defense Hardening Overview

SecuNexis includes enterprise-grade defensive controls active out of the box:

### SSRF Protection
- **Protocol Whitelisting**: Strictly restricts protocols to `http:` and `https:`.
- **Private IP Blocking**: Automatically blocks requests to `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `0.0.0.0/8`, and CGNAT `100.64.0.0/10`.
- **Cloud Metadata Defense**: Blocks `169.254.169.254`, `metadata.google.internal`, and `instance-data` to prevent credential exfiltration from cloud hosting environments.
- **Redirect Defense**: Inspects all redirect hops (`beforeRedirect`) to block open-redirect pivots into internal networks.

### Request & Resource Limits
- **HTTP Timeout**: Capped at `8,000 ms` to prevent slowloris Denial of Service.
- **Response Size Limits**: `maxContentLength` and `maxBodyLength` restricted to `5 MB` to prevent memory exhaustion from zip-bombs or multi-gigabyte files.
- **Maximum Redirects**: Capped at `5` hops to prevent infinite redirect loops.

### Rate Limiting & HTTP Security Headers
- **Rate Limiting**: Sliding window limiter restricts IP traffic to 60 scan requests/minute, setting `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers.
- **Security Headers**:
  - `X-Content-Type-Options: nosniff` (Prevents MIME sniffing attacks)
  - `X-Frame-Options: DENY` (Clickjacking defense)
  - `X-XSS-Protection: 1; mode=block` (Browser XSS filter enforcement)
  - `Referrer-Policy: strict-origin-when-cross-origin` (Protects sensitive path disclosure)

---

## 7. Local Development Workflow

The codebase remains 100% backward-compatible with local development:

```bash
# 1. Install dependencies
npm install

# 2. Configure local environment (optional)
cp .env.example .env

# 3. Run regression and SOC event test suites
npm test

# 4. Start local development server
npm start
# Server listens on http://0.0.0.0:3000
# Open http://localhost:3000 in your browser
```

---

## 8. Troubleshooting

### Render Service Fails to Start
- **Symptom**: Build succeeds, but service fails health check.
- **Cause**: Application not binding to `0.0.0.0` or wrong port.
- **Fix**: Verify `src/server.js` uses `const PORT = process.env.PORT || 3000;` and `app.listen(PORT, "0.0.0.0", ...)`.

### MongoDB Connection Warning
- **Symptom**: Server logs `MongoDB Atlas unavailable; falling back to in-memory SOC event store`.
- **Cause**: Incorrect `MONGODB_URI` or MongoDB Atlas Network Access is not set to `0.0.0.0/0`.
- **Fix**: In MongoDB Atlas, go to **Network Access** > verify `0.0.0.0/0` is active. Ensure your user password in the connection string has special characters properly URL-encoded.

### Free Tier Inactivity (Spin-down)
- **Symptom**: The first request after 15 minutes of inactivity takes 30-50 seconds.
- **Explanation**: Render Free Web Services spin down when idle. The service automatically spins up on the next incoming HTTP request. For 24/7 instant response, upgrade the service to Render's *Starter* plan (\$7/mo) or use a free monitoring uptime checker (e.g. UptimeRobot) pinging `https://<app>.onrender.com/health` every 10 minutes.

---

## 9. Phase 2.5 Production Security & Hardening (Render)

Before exposing the SOC Operations Console publicly on Render, configure the following production security environment variables in **Render Dashboard &rarr; Environment**:

| Variable | Recommended Value | Purpose |
| :--- | :--- | :--- |
| `NODE_ENV` | `production` | Enables `Secure` cookies, HSTS header, and suppresses detailed error responses. |
| `MONGODB_URI` | `mongodb+srv://...` | Required for persistent users, sessions, events, alerts, incidents, and immutable audit logs across Render restarts. |
| `REQUIRE_MONGODB` | `true` | Fails closed on startup if MongoDB Atlas is unreachable (prevents silent fallback to ephemeral memory in production). |
| `INITIAL_ADMIN_USERNAME` | *(your admin username)* | Provisions the initial `ADMIN` account on first boot (only if 0 users exist). Remove after initial bootstrap. |
| `INITIAL_ADMIN_EMAIL` | *(your admin email)* | Primary admin email for first-boot provisioning. |
| `INITIAL_ADMIN_PASSWORD` | *(strong 14+ char secret)* | Meets complexity rules (upper, lower, digit, symbol). **Never commit to Git.** Remove after bootstrap. |
| `BCRYPT_ROUNDS` | `12` | Password hashing cost factor (minimum 10 enforced). |
| `SESSION_TTL_MS` | `28800000` | Session expiration duration (8 hours). |
| `COOKIE_SAMESITE` | `Strict` | Hardens `secunexis_sid` HttpOnly cookie against CSRF. |
| `ALLOWED_ORIGINS` | `https://<your-app>.onrender.com` | Explicit CORS origin allowlist with `credentials: true`. |

### Post-Deployment Security Checks
1. Verify `GET /api/soc/events`, `GET /api/soc/alerts`, `GET /api/soc/incidents`, `GET /api/soc/audit`, and `GET /api/auth/users` all return `401 Unauthorized` without a session cookie.
2. Sign in via the Login Gate, confirm `Set-Cookie` contains `HttpOnly`, `Secure`, and `SameSite=Strict`.
3. Provision separate `ANALYST` and `VIEWER` accounts in **Users & RBAC**, and verify `VIEWER` receives `403 Forbidden` on alert/incident mutations.
4. Click **Verify Hash Chain** in **Audit Trail** to confirm SHA-256 chain integrity.
5. Remove `INITIAL_ADMIN_PASSWORD` from Render Environment Variables after confirming the primary `ADMIN` user is persisted in MongoDB Atlas.

