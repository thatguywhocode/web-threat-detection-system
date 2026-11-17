require("dotenv").config();

const path = require("path");
const net = require("net");
const dns = require("dns");
const http = require("http");
const https = require("https");
const express = require("express");
const axios = require("axios");
const cors = require("cors");

const staticAnalyze = require("./analyzers/staticAnalyzer");
const calculateRisk = require("./risk/riskEngine");
const checkVirusTotal = require("./analyzers/virusTotalAnalyzer");
const {
  socEventRouter,
  recordScanEvent,
  initDb,
  disconnectDb,
  isMongoConnected,
  getDbHealth,
  alertRouter,
  incidentRouter,
  authRouter,
  auditRouter,
  generateAlertFromEvent,
  correlateAlertToIncident,
  nosqlInjectionGuard,
  securityHeadersMiddleware,
  attachAuthContext,
  bootstrapInitialAdminFromEnv
} = require("./soc");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
const FRONTEND_DIR = path.resolve(__dirname, "../frontend");

/* ================= 1. SSRF & Network Security Validator ================= */
function isPrivateOrLoopbackIp(rawIp) {
  if (typeof rawIp !== "string") return false;
  let ip = rawIp.trim().replace(/^\[|\]$/g, "").toLowerCase();
  if (!net.isIP(ip)) return false;

  // Handle IPv4-mapped IPv6 in dotted form (::ffff:127.0.0.1) or hex form (::ffff:7f00:1)
  if (ip.startsWith("::ffff:")) {
    const mapped = ip.substring(7);
    if (net.isIPv4(mapped)) {
      ip = mapped;
    } else if (/^[0-9a-f]{1,4}:[0-9a-f]{1,4}$/.test(mapped)) {
      const [hi, lo] = mapped.split(":").map(part => parseInt(part, 16));
      ip = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
    }
  }

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
    if (ip === "::1" || ip === "::") return true;
    if (ip.startsWith("fc") || ip.startsWith("fd")) return true; // Unique local
    if (ip.startsWith("fe8") || ip.startsWith("fe9") || ip.startsWith("fea") || ip.startsWith("feb")) return true; // Link-local
    if (ip.startsWith("ff")) return true; // Multicast
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

  // Strip IPv6 square brackets so net.isIP detects [::1] and [::ffff:169.254.169.254]
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
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

/**
 * Custom DNS lookup enforcing SSRF checks on EVERY resolved IP address at socket-connect time
 * (blocks DNS rebinding, nip.io/internal A/AAAA records, and malicious redirect targets).
 */
function ssrfSafeLookup(hostname, options, callback) {
  const cb = typeof options === "function" ? options : callback;
  const opts = typeof options === "object" && options !== null ? options : {};

  dns.lookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
    if (err) return cb(err);
    if (!Array.isArray(addresses) || addresses.length === 0) {
      return cb(new Error("Target hostname did not resolve to any IP address"));
    }

    for (const entry of addresses) {
      if (isPrivateOrLoopbackIp(entry.address)) {
        return cb(new Error("Target resolves to restricted private IP space (SSRF protection)"));
      }
    }

    if (opts.all) {
      return cb(null, addresses);
    }
    return cb(null, addresses[0].address, addresses[0].family);
  });
}

const ssrfHttpAgent = new http.Agent({ lookup: ssrfSafeLookup });
const ssrfHttpsAgent = new https.Agent({ lookup: ssrfSafeLookup });

/* ================= 2. In-Memory API Rate Limiter ================= */
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000;
const MAX_REQUESTS_PER_MIN = 60;

function apiRateLimiter(req, res, next) {
  const rawPath = (req.originalUrl || req.url || "").split("?")[0];
  if (rawPath === "/" || rawPath === "/health" || rawPath === "/api/health") {
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

/* ================= 3. Middleware & Production Security Hardening ================= */
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(o => o.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const host = req.headers.host;
  const proto = req.headers["x-forwarded-proto"] || (req.secure ? "https" : "http");
  const sameOrigin = host ? `${proto}://${host}` : null;

  return cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (sameOrigin && origin === sameOrigin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      if (process.env.NODE_ENV !== "production" && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
        return callback(null, true);
      }
      return callback(null, false);
    },
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-CSRF-Token", "Authorization"]
  })(req, res, next);
});

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));
app.use(securityHeadersMiddleware);

/**
 * Fail-closed guard when REQUIRE_MONGODB=true and MongoDB Atlas is disconnected
 */
function requireMongoIfConfigured(req, res, next) {
  if (process.env.REQUIRE_MONGODB === "true" && !isMongoConnected()) {
    return res.status(503).json({
      success: false,
      error: "Persistent database unavailable. Service configured to fail-closed (REQUIRE_MONGODB=true).",
      code: "DB_UNAVAILABLE"
    });
  }
  return next();
}

// Apply rate limiting, NoSQL injection guard & session context to scanning & API routes
app.use("/scan", apiRateLimiter, nosqlInjectionGuard, attachAuthContext);
app.use("/api", apiRateLimiter, nosqlInjectionGuard, attachAuthContext);

/* ================= 4. SOC Authentication, Audit & Operations APIs ================= */
app.use("/api/auth", requireMongoIfConfigured, authRouter);
app.use("/api/soc/audit", requireMongoIfConfigured, auditRouter);
app.use("/api/soc/events", requireMongoIfConfigured, socEventRouter);
app.use("/api/soc/alerts", requireMongoIfConfigured, alertRouter);
app.use("/api/soc/incidents", requireMongoIfConfigured, incidentRouter);

// Attempt database connection & optional env-based initial admin bootstrap non-blockingly
initDb()
  .then(() => bootstrapInitialAdminFromEnv())
  .catch(err => {
    console.error("[SecuNexis Startup] Database initialization error:", err.message);
    if (process.env.REQUIRE_MONGODB === "true" && require.main === module) {
      console.error("[SecuNexis Startup] Exiting due to REQUIRE_MONGODB=true.");
      process.exit(1);
    }
  });

/* ================= 5. Health Checks & Root Route ================= */
app.get("/health", (req, res) => res.status(200).send("OK"));
app.get("/api/health", (req, res) => {
  const dbHealth = getDbHealth();
  return res.status(200).json({
    status: "ok",
    service: "SecuNexis Web Threat Detection",
    database: {
      connected: dbHealth.connected,
      mode: dbHealth.mode,
      readyState: dbHealth.readyState
    }
  });
});
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
          httpAgent: ssrfHttpAgent,
          httpsAgent: ssrfHttpsAgent,
          headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SecuNexis/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"
          },
          beforeRedirect: (options) => {
            const redirectUrl = options.href || (options.hostname ? `${options.protocol || "http:"}//${options.hostname}${options.port ? `:${options.port}` : ""}${options.path || "/"}` : "");
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

    /* ---------- SOC Event Recording, Alerting & Incident Correlation ---------- */
    try {
      const recordResult = await recordScanEvent(
        { target: targetUrl || "HTML Source", url: targetUrl, html: req.body?.html },
        { analysis: analysisResult, risk: riskResult, virusTotal: vtResult },
        {
          source: targetUrl ? "URL_SCANNER" : "HTML_SCANNER",
          clientIp: req.ip || req.socket?.remoteAddress || "127.0.0.1",
          userAgent: req.headers["user-agent"] || ""
        }
      );

      if (recordResult && recordResult.event) {
        const alertResult = await generateAlertFromEvent(recordResult.event);
        if (alertResult && alertResult.created && alertResult.alert) {
          await correlateAlertToIncident(alertResult.alert);
        }
      }
    } catch (socErr) {
      console.warn("SOC pipeline processing error:", socErr.message);
    }

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

/* ================= 8. Global Safe Error Handler ================= */
app.use((err, req, res, next) => {
  if (err && err.type === "entity.parse.failed") {
    return res.status(400).json({
      success: false,
      error: "Malformed JSON request payload."
    });
  }
  if (err && err.type === "entity.too.large") {
    return res.status(413).json({
      success: false,
      error: "Request payload exceeds maximum allowed size."
    });
  }
  console.error("[SecuNexis Unhandled Error]:", err ? err.message : "Unknown error");
  return res.status(500).json({
    success: false,
    error: "Internal Server Error"
  });
});

/* ================= 9. Server Startup & Graceful Shutdown ================= */
const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";

if (require.main === module) {
  const server = app.listen(PORT, HOST, () => {
    console.log(`SecuNexis Web Threat Detection Platform running on http://${HOST}:${PORT}`);
  });

  const gracefulShutdown = async (signal) => {
    console.log(`[SecuNexis] Received ${signal}. Shutting down cleanly...`);
    server.close(async () => {
      try {
        await disconnectDb();
      } catch (_) {}
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000).unref();
  };

  process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
  process.on("SIGINT", () => gracefulShutdown("SIGINT"));
}

module.exports = app;
