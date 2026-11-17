/**
 * SentinelCore — Enterprise SOC Events Automated Test Suite (v1.0)
 *
 * Verifies Phase 1: SOC Event Management implementation:
 * 1. SecurityEvent Model & Storage (schema, indexes, query operations)
 * 2. Scan Result Adapter (taxonomy categorization, raw input sanitization, incomplete payloads)
 * 3. Idempotent Deduplication (deterministic scanReference, duplicate prevention on rescan)
 * 4. Filtering Engine (verdict, severity, target search with regex escaping, date ranges)
 * 5. Pagination & Sorting (page, limit, totalPages, hasMore, score ordering)
 * 6. Additive REST API Endpoints (GET /api/soc/events, GET /stats, GET /:id)
 * 7. Contract Preservation (GET / responds, POST /scan retains exact { analysis, risk, virusTotal })
 */

const assert = require("assert");
const { Readable } = require("stream");
const { EventEmitter } = require("events");

const app = require("../src/server");
const staticAnalyze = require("../src/analyzers/staticAnalyzer");
const calculateRisk = require("../src/risk/riskEngine");
const {
  getSecurityEventModel,
  adaptScanResult,
  generateScanReference,
  categorizeFinding,
  sanitizeRawInputPreview,
  recordScanEvent,
  getEvents,
  getEventById,
  getEventStats,
  clearAllEvents
} = require("../src/soc/events");

/**
 * Pure in-process HTTP dispatch helper for Express (avoids TCP socket sandbox restrictions)
 */
function invokeApp(expressApp, method, url, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const rawPayload = body ? (typeof body === "string" ? body : JSON.stringify(body)) : null;

    const { PassThrough } = require("stream");
    const mockSocket = new PassThrough();
    mockSocket.remoteAddress = "127.0.0.1";

    const req = new Readable({
      read() {
        if (rawPayload) {
          this.push(Buffer.from(rawPayload, "utf8"));
        }
        this.push(null);
      }
    });

    Object.assign(req, {
      method: method.toUpperCase(),
      url,
      originalUrl: url,
      headers: {
        "content-type": typeof body === "object" ? "application/json" : "text/plain",
        "user-agent": "SentinelCore-SOC-TestRunner/1.0",
        ...(rawPayload ? { "content-length": String(Buffer.byteLength(rawPayload)) } : {}),
        ...headers
      },
      connection: mockSocket,
      socket: mockSocket
    });

    const res = new EventEmitter();
    let statusCode = 200;
    const responseHeaders = {};
    const chunks = [];

    res.setHeader = (k, v) => { responseHeaders[k.toLowerCase()] = v; };
    res.getHeader = (k) => responseHeaders[k.toLowerCase()];
    res.writeHead = (code, hdrs) => {
      statusCode = code;
      res.statusCode = code;
      if (hdrs) Object.assign(responseHeaders, hdrs);
    };
    res.status = (c) => {
      statusCode = c;
      res.statusCode = c;
      return res;
    };
    res.json = (data) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(data));
    };
    res.send = (data) => {
      if (typeof data === "object") return res.json(data);
      res.end(String(data));
    };
    res.sendFile = (filepath) => {
      const fs = require("fs");
      res.setHeader("content-type", "text/html");
      res.end(fs.readFileSync(filepath, "utf8"));
    };
    res.write = (chunk) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    };
    res.end = (chunk) => {
      if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      const rawText = Buffer.concat(chunks).toString("utf8");
      let parsed = rawText;
      try {
        parsed = JSON.parse(rawText);
      } catch (_) {}

      resolve({
        status: res.statusCode || statusCode,
        statusCode: res.statusCode || statusCode,
        headers: responseHeaders,
        data: parsed
      });
    };

    expressApp.handle(req, res, (err) => {
      if (err) reject(err);
      else resolve({ status: 404, statusCode: 404, data: "Not Found" });
    });
  });
}

async function runTests() {
  console.log("==========================================================================================");
  console.log("  SENTINELCORE ENTERPRISE SOC: PHASE 1 SOC EVENTS TEST SUITE");
  console.log("==========================================================================================\n");

  let passed = 0;
  let failed = 0;

  function test(name, fn) {
    try {
      fn();
      console.log(`  [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  [FAIL] ${name}`);
      console.error(`         ${err.message}`);
      failed++;
    }
  }

  async function testAsync(name, fn) {
    try {
      await fn();
      console.log(`  [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  [FAIL] ${name}`);
      console.error(`         ${err.message}`);
      failed++;
    }
  }

  // Clear any existing test events
  await clearAllEvents();

  /* ================= 1. MODEL & STORE UNIT TESTS ================= */
  console.log("--- 1. SecurityEvent Model & Store Tests ---");

  test("SecurityEvent model provides standard query methods", () => {
    const model = getSecurityEventModel();
    assert.strictEqual(typeof model.find, "function", "find should be a function");
    assert.strictEqual(typeof model.findOne, "function", "findOne should be a function");
    assert.strictEqual(typeof model.countDocuments, "function", "countDocuments should be a function");
  });

  test("Model creates document with required fields and defaults", async () => {
    const model = getSecurityEventModel();
    const doc = await model.create({
      scanReference: "test-ref-001",
      target: "https://test-example.com",
      targetType: "URL",
      verdict: "SAFE",
      severity: "LOW",
      riskScore: 0,
      threatCount: 0,
      infoCount: 1
    });

    assert(doc.eventId && doc.eventId.startsWith("sec_"), "eventId should start with sec_");
    assert.strictEqual(doc.scanReference, "test-ref-001");
    assert.strictEqual(doc.target, "https://test-example.com");
    assert.strictEqual(doc.verdict, "SAFE");
    assert.strictEqual(doc.riskScore, 0);
  });

  /* ================= 2. ADAPTER & SANITIZATION TESTS ================= */
  console.log("\n--- 2. Adapter Transformation & Sanitization Tests ---");

  test("Taxonomy categorization maps findings correctly", () => {
    assert.strictEqual(categorizeFinding({ id: "THREAT_KEYLOGGER_LISTENER" }), "Keylogger indicators");
    assert.strictEqual(categorizeFinding({ id: "THREAT_HIDDEN_CREDENTIAL_FORM" }), "Credential harvesting");
    assert.strictEqual(categorizeFinding({ id: "THREAT_EXTERNAL_CREDENTIAL_ACTION" }), "Cross-domain form submissions");
    assert.strictEqual(categorizeFinding({ id: "THREAT_JS_EVAL_ENCODED_PAYLOAD" }), "Obfuscated JavaScript");
    assert.strictEqual(categorizeFinding({ id: "THREAT_SUSPICIOUS_IFRAME" }), "Suspicious iframes");
    assert.strictEqual(categorizeFinding({ id: "INFO_FORM_TAGS" }), "Other detected anomalies");
  });

  test("Sensitive raw input is sanitized and passwords redacted", () => {
    const raw = `<form action="/login"><input type="password" value="SuperSecretPassword123"><input name="api_key" value="ak_live_998877"></form>`;
    const sanitized = sanitizeRawInputPreview(raw);
    assert(!sanitized.includes("SuperSecretPassword123"), "Password must be redacted");
    assert(!sanitized.includes("ak_live_998877"), "API key must be redacted");
    assert(sanitized.includes("[REDACTED]"), "Should contain [REDACTED]");
  });

  test("Adapter handles incomplete / missing scan payloads safely", () => {
    const emptyDoc = adaptScanResult({}, {});
    assert.strictEqual(emptyDoc.verdict, "INCONCLUSIVE");
    assert.strictEqual(emptyDoc.riskScore, 0);
    assert.strictEqual(emptyDoc.severity, "LOW");
    assert(Array.isArray(emptyDoc.detectionEvidence));
    assert.strictEqual(emptyDoc.virusTotal.status, "unavailable");
  });

  /* ================= 3. DUPLICATE PREVENTION & IDEMPOTENCY ================= */
  console.log("\n--- 3. Duplicate Prevention & Idempotency Tests ---");

  await testAsync("Deterministic scanReference derives identical hash for identical input", async () => {
    const input = { target: "https://example.com/login", html: "<html><body>Login</body></html>" };
    const result = {
      risk: { verdict: "SAFE", riskScore: 0, scoredThreats: [] },
      analysis: { findings: [] }
    };

    const ref1 = generateScanReference(input, result);
    const ref2 = generateScanReference(input, result);
    assert.strictEqual(ref1, ref2, "Same input and result must produce identical scanReference");

    // Different target must produce different hash
    const ref3 = generateScanReference({ target: "https://other.com", html: "<html><body>Login</body></html>" }, result);
    assert.notStrictEqual(ref1, ref3, "Different target must produce different scanReference");
  });

  await testAsync("Recording duplicate scan returns isDuplicate: true and does not create new document", async () => {
    await clearAllEvents();

    const scanInput = { target: "https://rescan-target.org", url: "https://rescan-target.org" };
    const scanResult = {
      risk: { verdict: "SAFE", severity: "LOW", riskScore: 0, scoredThreats: [], threatCount: 0, infoCount: 1 },
      analysis: { findings: [], metrics: { totalScripts: 2 } },
      virusTotal: { available: false, status: "unavailable" }
    };

    const first = await recordScanEvent(scanInput, scanResult);
    assert.strictEqual(first.isDuplicate, false, "First insertion must not be marked duplicate");

    const second = await recordScanEvent(scanInput, scanResult);
    assert.strictEqual(second.isDuplicate, true, "Second insertion must be identified as duplicate");
    assert.strictEqual(first.event.scanReference, second.event.scanReference, "References must match");

    const stats = await getEventStats();
    assert.strictEqual(stats.totalEvents, 1, "Total event count must remain 1 after rescanning");
  });

  /* ================= 4. FILTERING ENGINE TESTS ================= */
  console.log("\n--- 4. Filtering Engine Tests ---");

  await testAsync("Filters by verdict, severity, and target substring", async () => {
    await clearAllEvents();

    // Ingest 3 distinct mock events
    await recordScanEvent(
      { target: "https://clean-portal.com" },
      { risk: { verdict: "SAFE", severity: "LOW", riskScore: 5 } }
    );
    await recordScanEvent(
      { target: "https://phishing-alert.net/login" },
      { risk: { verdict: "MALICIOUS", severity: "HIGH", riskScore: 85 } }
    );
    await recordScanEvent(
      { target: "https://anomalous-site.org" },
      { risk: { verdict: "SUSPICIOUS", severity: "MEDIUM", riskScore: 40 } }
    );

    // Filter by verdict=MALICIOUS
    const malRes = await getEvents({ verdict: "MALICIOUS" });
    assert.strictEqual(malRes.total, 1);
    assert.strictEqual(malRes.events[0].verdict, "MALICIOUS");

    // Filter by severity=MEDIUM
    const medRes = await getEvents({ severity: "MEDIUM" });
    assert.strictEqual(medRes.total, 1);
    assert.strictEqual(medRes.events[0].target, "https://anomalous-site.org");

    // Filter by target substring search
    const searchRes = await getEvents({ target: "phishing" });
    assert.strictEqual(searchRes.total, 1);
    assert(searchRes.events[0].target.includes("phishing"));

    // Multiple comma-separated verdicts
    const multiRes = await getEvents({ verdict: "SAFE,SUSPICIOUS" });
    assert.strictEqual(multiRes.total, 2);
  });

  /* ================= 5. PAGINATION & SORTING TESTS ================= */
  console.log("\n--- 5. Pagination & Sorting Tests ---");

  await testAsync("Pagination calculates page, limit, totalPages, and hasMore accurately", async () => {
    await clearAllEvents();

    for (let i = 1; i <= 5; i++) {
      await recordScanEvent(
        { target: `https://site-${i}.test` },
        { risk: { verdict: "SAFE", severity: "LOW", riskScore: i * 10 } }
      );
    }

    const page1 = await getEvents({ page: 1, limit: 2 });
    assert.strictEqual(page1.total, 5);
    assert.strictEqual(page1.events.length, 2);
    assert.strictEqual(page1.totalPages, 3);
    assert.strictEqual(page1.hasMore, true);

    const page2 = await getEvents({ page: 2, limit: 2 });
    assert.strictEqual(page2.events.length, 2);
    assert.strictEqual(page2.page, 2);
    assert.strictEqual(page2.hasMore, true);

    const page3 = await getEvents({ page: 3, limit: 2 });
    assert.strictEqual(page3.events.length, 1);
    assert.strictEqual(page3.hasMore, false);
  });

  await testAsync("Sorting orders by score descending and ascending", async () => {
    const desc = await getEvents({ sort: "score_desc", limit: 5 });
    assert(desc.events[0].riskScore >= desc.events[desc.events.length - 1].riskScore);

    const asc = await getEvents({ sort: "score_asc", limit: 5 });
    assert(asc.events[0].riskScore <= asc.events[asc.events.length - 1].riskScore);
  });

  /* ================= 6. REST API INTEGRATION TESTS ================= */
  console.log("\n--- 6. REST API Endpoint Integration Tests (In-Process) ---");

  await testAsync("GET / responds with API running health status", async () => {
    const res = await invokeApp(app, "GET", "/");
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data, "Web Threat Detection API is running");
  });

  await testAsync("GET /api/soc/events returns 200 with paginated JSON structure", async () => {
    const res = await invokeApp(app, "GET", "/api/soc/events?limit=5");
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.success, true);
    assert(typeof res.data.total === "number");
    assert(Array.isArray(res.data.events));
  });

  await testAsync("GET /api/soc/events/stats returns telemetry breakdown", async () => {
    const res = await invokeApp(app, "GET", "/api/soc/events/stats");
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.success, true);
    assert(res.data.stats.byVerdict);
    assert(typeof res.data.stats.totalEvents === "number");
  });

  await testAsync("GET /api/soc/events/:id retrieves single event document", async () => {
    const listRes = await invokeApp(app, "GET", "/api/soc/events?limit=1");
    assert(listRes.data.events.length > 0);
    const eventId = listRes.data.events[0].eventId;

    const singleRes = await invokeApp(app, "GET", `/api/soc/events/${eventId}`);
    assert.strictEqual(singleRes.status, 200);
    assert.strictEqual(singleRes.data.success, true);
    assert.strictEqual(singleRes.data.event.eventId, eventId);
  });

  /* ================= 7. CONTRACT PRESERVATION CHECK ================= */
  console.log("\n--- 7. Existing API Contract Preservation Tests ---");

  await testAsync("POST /scan preserves existing contract schema { analysis, risk, virusTotal }", async () => {
    const res = await invokeApp(app, "POST", "/scan", {
      body: {
        html: `<!DOCTYPE html><html><body><h1>Safe Portal</h1><p>Welcome to our security dashboard.</p></body></html>`
      }
    });

    assert.strictEqual(res.status, 200);
    assert(res.data.analysis, "Response must contain analysis object");
    assert(res.data.risk, "Response must contain risk object");
    assert(res.data.virusTotal, "Response must contain virusTotal object");

    // Verify mathematical integrity of scan response
    assert.strictEqual(res.data.risk.verdict, "SAFE");
    assert.strictEqual(res.data.risk.riskScore, 0);
    assert.strictEqual(res.data.risk.severity, "LOW");

    // Verify that scan automatically created a SOC event
    const socRes = await invokeApp(app, "GET", "/api/soc/events?sort=newest&limit=1");
    assert(socRes.data.events.length > 0);
    assert.strictEqual(socRes.data.events[0].verdict, "SAFE");
  });

  /* ================= 8. RENDER DEPLOYMENT & SSRF SECURITY TESTS ================= */
  console.log("\n--- 8. Render Deployment & Security Hardening Tests ---");

  await testAsync("GET / with text/html accepts header serves dashboard index.html", async () => {
    const res = await invokeApp(app, "GET", "/", {
      headers: {
        accept: "text/html,application/xhtml+xml",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
      }
    });
    assert.strictEqual(res.status, 200);
    assert(typeof res.data === "string" && res.data.includes("<title>Secunexis"), "Must serve dashboard HTML with Secunexis title");
  });

  await testAsync("GET /health responds with 200 OK for Render health monitoring", async () => {
    const res = await invokeApp(app, "GET", "/health");
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data, "OK");
  });

  await testAsync("GET /api/health responds with 200 JSON status for API monitoring", async () => {
    const res = await invokeApp(app, "GET", "/api/health");
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.status, "ok");
  });

  await testAsync("SSRF Protection blocks loopback and private IP scan targets", async () => {
    const targets = [
      "http://127.0.0.1:8080",
      "http://localhost:3000",
      "http://169.254.169.254/latest/meta-data",
      "http://10.0.0.1/admin",
      "http://192.168.1.1/router",
      "http://metadata.google.internal"
    ];

    for (const url of targets) {
      const res = await invokeApp(app, "POST", "/scan", {
        body: { url }
      });
      assert.strictEqual(res.status, 400, `Target ${url} must be rejected with 400`);
      assert(res.data.error.includes("SSRF protection"), `Error message must cite SSRF protection for ${url}`);
    }
  });

  await testAsync("API endpoints return standard rate limiting headers", async () => {
    const res = await invokeApp(app, "GET", "/api/soc/events?limit=1");
    assert.strictEqual(res.status, 200);
    assert(res.headers["x-ratelimit-limit"], "Must include X-RateLimit-Limit header");
    assert(res.headers["x-ratelimit-remaining"] !== undefined, "Must include X-RateLimit-Remaining header");
  });

  console.log("\n==========================================================================================");
  console.log(`  SOC EVENTS TEST RESULTS: ${passed} PASSED | ${failed} FAILED`);
  console.log("==========================================================================================");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error("Test runner fatal error:", err);
  process.exit(1);
});
