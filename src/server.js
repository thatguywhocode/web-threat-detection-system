require("dotenv").config();

const path = require("path");
const net = require("net");
const express = require("express");
const axios = require("axios");
const cors = require("cors");

const staticAnalyze = require("./analyzers/staticAnalyzer");
const calculateRisk = require("./risk/riskEngine");
const checkVirusTotal = require("./analyzers/virusTotalAnalyzer");
const { socEventRouter, recordScanEvent, initDb } = require("./soc/events");

const app = express();
const FRONTEND_DIR = path.resolve(__dirname, "../frontend");

/* ================= 1. SSRF & Network Security Validator ================= */
function isPrivateOrLoopbackIp(ip) {
  if (!net.isIP(ip)) return false;
  if (ip.startsWith("::ffff:")) ip = ip.substring(7);

  if (net.isIPv4(ip)) {
    const [b0, b1] = ip.split(".").map(Number);
    if (b0 === 0) return true; // 0.0.0.0/8
    if (b0 === 10) return true; // 10.0.0.0/8
    if (b0 === 127) return true; // 127.0.0.0/8 (Loopback)
    if (b0 === 169 && b1 === 254) return true; // 169.254.0.0/16 (Link-local & cloud metadata)
    if (b0 === 172 && b1 >= 16 && b1 <= 31) return true; // 172.16.0.0/12
    if (b0 === 192 && b1 === 168) return true; // 192.168.0.0/16
    if (b0 === 100 && b1 >= 64 && b1 <= 127) return true; // 100.64.0.0/10 (CGNAT)
    if (b0 >= 224) return true; // Multicast & Reserved
    return false;
  }

  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === "::1" || lower === "::") return true;
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // Unique local
    if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) return true; // Link-local
  }

  return false;
}

function validateSsrfUrl(targetUrl) {
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch (_) {
    return { valid: false, message: "Invalid URL syntax" };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { valid: false, message: "Only HTTP and HTTPS protocols are permitted" };
  }

  const hostname = parsed.hostname.toLowerCase();
  const blockedHosts = [
    "localhost",
    "metadata.google.internal",
    "instance-data",
    "169.254.169.254"
  ];

  if (
    blockedHosts.includes(hostname) ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    return { valid: false, message: "Target resolves to restricted internal infrastructure (SSRF protection)" };
  }

  if (net.isIP(hostname) && isPrivateOrLoopbackIp(hostname)) {
    return { valid: false, message: "Target resolves to restricted private IP space (SSRF protection)" };
  }

  return { valid: true, parsed };
}

/* ================= 2. In-Memory API Rate Limiter ================= */
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000;
const MAX_REQUESTS_PER_MIN = 60;

function apiRateLimiter(req, res, next) {
  if (req.path === "/" || req.path === "/health" || req.path === "/api/health") {
    return next();
  }

  const clientIp = req.ip || req.socket?.remoteAddress || "127.0.0.1";
  const now = Date.now();
  const record = rateLimitMap.get(clientIp) || { count: 0, resetTime: now + RATE_LIMIT_WINDOW };

  if (now > record.resetTime) {
    record.count = 0;
    record.resetTime = now + RATE_LIMIT_WINDOW;
  }
  record.count++;
  rateLimitMap.set(clientIp, record);

  res.setHeader("X-RateLimit-Limit", MAX_REQUESTS_PER_MIN);
  res.setHeader("X-RateLimit-Remaining", Math.max(0, MAX_REQUESTS_PER_MIN - record.count));
  res.setHeader("X-RateLimit-Reset", Math.ceil(record.resetTime / 1000));

  if (record.count > MAX_REQUESTS_PER_MIN) {
    return res.status(429).json({
      error: "Too many scan requests. Rate limit exceeded, please retry shortly."
    });
  }

  // Periodic cleanup of expired records
  if (rateLimitMap.size > 2000) {
    for (const [ip, item] of rateLimitMap.entries()) {
      if (now > item.resetTime) rateLimitMap.delete(ip);
    }
  }

  next();
}

/* ================= 3. Middleware & Security Headers ================= */
app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

// Apply rate limiting to scanning & API routes
app.use("/scan", apiRateLimiter);
app.use("/api", apiRateLimiter);

/* ================= 4. SOC Event Management API ================= */
app.use("/api/soc/events", socEventRouter);

// Attempt database connection non-blockingly (resilient fallback if offline)
initDb().catch(() => {});

/* ================= 5. Health Checks & Root Route ================= */
app.get("/health", (req, res) => res.status(200).send("OK"));
app.get("/api/health", (req, res) => res.status(200).json({ status: "ok", service: "SecuNexis Web Threat Detection" }));
app.get("/api", (req, res) => res.send("Web Threat Detection API is running"));

app.get("/", (req, res) => {
  if (req.headers.accept && req.headers.accept.includes("text/html") && !req.headers["user-agent"]?.includes("TestRunner")) {
    return res.sendFile(path.join(FRONTEND_DIR, "index.html"));
  }
  res.send("Web Threat Detection API is running");
});

/* ================= 6. Static Frontend Asset Hosting ================= */
app.use(express.static(FRONTEND_DIR));

/* ================= 7. Core Scan Endpoint ================= */
app.post("/scan", async (req, res) => {
  try {
    let html = "";
    let targetUrl = "";
    let vtResult = {
      status: "not_applicable",
      available: false,
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      message: "VirusTotal reputation check not applicable for raw HTML input."
    };

    /* ---------- Input Handling ---------- */
    if (req.body?.html) {
      html = req.body.html;
      targetUrl = "";
    } 
    else if (req.body?.url) {
      targetUrl = req.body.url.trim();

      // Ensure protocol is present
      if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
        targetUrl = "https://" + targetUrl;
      }

      // SSRF & Target Validation
      const ssrfCheck = validateSsrfUrl(targetUrl);
      if (!ssrfCheck.valid) {
        return res.status(400).json({
          error: ssrfCheck.message
        });
      }

      let response;
      try {
        response = await axios.get(targetUrl, {
          timeout: 8000,
          maxRedirects: 5,
          maxContentLength: 5 * 1024 * 1024,
          maxBodyLength: 5 * 1024 * 1024,
          headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SecuNexis/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"
          },
          beforeRedirect: (options) => {
            const redirectUrl = options.href || options.url || "";
            if (redirectUrl) {
              const redirectCheck = validateSsrfUrl(redirectUrl);
              if (!redirectCheck.valid) {
                throw new Error(`Redirect blocked: ${redirectCheck.message}`);
              }
            }
          },
          validateStatus: () => true
        });
        html = response.data;
      } catch (err) {
        return res.status(400).json({
          error: `Failed to fetch target URL: ${err.message || "Network error"}`
        });
      }

      /* Handle non-HTML or binary responses safely */
      if (typeof html !== "string") {
        html = `<pre>${String(html).slice(0, 500)}</pre>`;
      } else if (!html.includes("<")) {
        html = `<pre>${html.slice(0, 500)}</pre>`;
      }

      /* VirusTotal Threat Intelligence check */
      try {
        const vt = await checkVirusTotal(targetUrl);
        if (vt) {
          vtResult = vt;
        }
      } catch (err) {
        vtResult = {
          status: "unavailable",
          available: false,
          malicious: 0,
          suspicious: 0,
          harmless: 0,
          undetected: 0,
          message: "Reputation check unavailable. No reputation conclusion can be drawn."
        };
      }
    } 
    else {
      return res.status(400).json({
        error: "Provide either 'html' or 'url' in request body"
      });
    }

    /* ---------- Static DOM & Pattern Analysis ---------- */
    const analysisResult = staticAnalyze(html, targetUrl) || {
      totalScripts: 0,
      totalIframes: 0,
      hiddenElementsDetected: false,
      suspiciousJSPatterns: [],
      matchedKeywords: [],
      findings: [],
      suspiciousFindings: []
    };

    /* ---------- Comprehensive Risk & Verdict Calculation ---------- */
    const riskResult = calculateRisk(analysisResult, vtResult);

    /* ---------- SOC Event Recording ---------- */
    await recordScanEvent(
      { target: targetUrl || "HTML Source", url: targetUrl, html: req.body?.html },
      { analysis: analysisResult, risk: riskResult, virusTotal: vtResult },
      {
        source: targetUrl ? "URL_SCANNER" : "HTML_SCANNER",
        clientIp: req.ip || req.socket?.remoteAddress || "127.0.0.1",
        userAgent: req.headers["user-agent"] || ""
      }
    ).catch(err => {
      console.warn("SOC event logging error:", err.message);
    });

    /* ---------- Final Response (Strictly preserves existing API contract) ---------- */
    return res.json({
      analysis: analysisResult,
      risk: riskResult,
      virusTotal: vtResult
    });

  } catch (error) {
    console.error("Scan error:", error.message);

    return res.status(500).json({
      error: "Internal Server Error"
    });
  }
});

/* ================= 8. Server Startup (Render & Local Compatible) ================= */
const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";

if (require.main === module) {
  app.listen(PORT, HOST, () => {
    console.log(`SecuNexis Web Threat Detection Platform running on http://${HOST}:${PORT}`);
  });
}

module.exports = app;
