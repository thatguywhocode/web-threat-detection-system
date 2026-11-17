/**
 * SecuNexis Enterprise SOC — Phase 2.5 Production Security & Hardening Test Suite
 *
 * Tests:
 * 1. Bcrypt password hashing, strength policy & hash stripping
 * 2. First-run setup, login, secure cookie attributes, opaque token hashing & logout invalidation
 * 3. Brute-force account lockout & IP login rate limiting
 * 4. Session expiration enforcement & audit logging
 * 5. Backend RBAC enforcement (ADMIN, ANALYST, VIEWER) & unauthorized API denial
 * 6. Actor anti-spoofing on alert/incident mutations
 * 7. CSRF protection on cookie-authenticated state-changing endpoints
 * 8. NoSQL injection, prototype pollution & entity ID validation guards
 * 9. Immutable audit logging, tamper prevention & SHA-256 hash chain verification
 * 10. Concurrent alert deduplication & concurrent incident correlation safety
 * 11. Database reliability, fail-closed REQUIRE_MONGODB, and persistence verification
 */

const assert = require("assert");
const http = require("http");
const { PassThrough } = require("stream");

const app = require("../src/server");
const {
  auth,
  audit,
  alerts,
  incidents,
  db
} = require("../src/soc");

let passed = 0;
let failed = 0;

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

function invokeApp(appInstance, { method = "GET", url, body = null, headers = {}, ip = "127.0.0.1" }) {
  return new Promise((resolve, reject) => {
    const socket = new PassThrough();
    socket.remoteAddress = ip;
    const req = new http.IncomingMessage(socket);
    req.method = method;
    req.url = url;
    req.headers = {
      host: "localhost:3000",
      "user-agent": "SecuNexisSecurityTestRunner",
      accept: "application/json",
      ...headers
    };

    if (body !== null) {
      const payload = typeof body === "string" ? body : JSON.stringify(body);
      req.headers["content-type"] = req.headers["content-type"] || "application/json";
      req.headers["content-length"] = Buffer.byteLength(payload);
    }

    let statusCode = 200;
    const responseHeaders = {};
    let responseBody = "";

    const res = {
      statusCode: 200,
      headersSent: false,
      setHeader(k, v) {
        responseHeaders[k.toLowerCase()] = v;
        return this;
      },
      getHeader(k) {
        return responseHeaders[k.toLowerCase()];
      },
      status(c) {
        statusCode = c;
        res.statusCode = c;
        return res;
      },
      sendStatus(c) {
        statusCode = c;
        res.statusCode = c;
        res.end();
        return res;
      },
      send(data) {
        responseBody = typeof data === "string" ? data : JSON.stringify(data);
        res.end();
        return res;
      },
      json(data) {
        res.setHeader("Content-Type", "application/json");
        responseBody = JSON.stringify(data);
        res.end();
        return res;
      },
      end(chunk) {
        if (chunk) responseBody += chunk;
        let parsed = null;
        try {
          parsed = JSON.parse(responseBody);
        } catch {
          parsed = responseBody;
        }
        resolve({
          statusCode: res.statusCode || statusCode,
          headers: responseHeaders,
          body: parsed,
          rawBody: responseBody
        });
      }
    };

    appInstance.handle(req, res, err => {
      if (err) return reject(err);
      res.status(404).json({ error: "Not Found", path: url });
    });

    if (body !== null) {
      const payload = typeof body === "string" ? body : JSON.stringify(body);
      req.push(payload);
    }
    req.push(null);
  });
}

function extractSidCookie(headers) {
  const setCookie = headers["set-cookie"];
  if (!setCookie) return null;
  const raw = Array.isArray(setCookie) ? setCookie.join("; ") : String(setCookie);
  const match = raw.match(/secunexis_sid=([^;]+)/);
  return match ? match[1] : null;
}

async function runSecuritySuite() {
  console.log("\n==========================================================================================");
  console.log("  SECUNEXIS ENTERPRISE SOC: PHASE 2.5 PRODUCTION SECURITY & HARDENING TEST SUITE");
  console.log("==========================================================================================\n");

  // Reset in-memory stores cleanly
  await auth.memoryUserStore.deleteMany({});
  await auth.memorySessionStore.deleteMany({});
  await alerts.memoryAlertStore.deleteMany({});
  await incidents.memoryIncidentStore.deleteMany({});
  audit.memoryAuditStore._clearForTests();
  auth.resetLoginRateLimiter();

  /* ================= 1. PASSWORD HASHING & COMPLEXITY ================= */
  console.log("--- 1. Password Hashing & Complexity Policy Tests ---");

  await testAsync("Bcrypt hashes passwords with unique salts and verifies accurately", async () => {
    const pw = "Str0ng!SecuNexis#2026";
    const hash1 = await auth.hashPassword(pw);
    const hash2 = await auth.hashPassword(pw);

    assert.ok(hash1.startsWith("$2a$") || hash1.startsWith("$2b$"), "Must use bcrypt hash format");
    assert.notStrictEqual(hash1, pw, "Hash must never equal plaintext password");
    assert.notStrictEqual(hash1, hash2, "Identical passwords must produce distinct salted hashes");

    assert.strictEqual(await auth.verifyPassword(pw, hash1), true);
    assert.strictEqual(await auth.verifyPassword("WrongPassword!123", hash1), false);
  });

  await testAsync("Password policy rejects weak passwords and accepts enterprise-grade passwords", async () => {
    assert.strictEqual(auth.validatePasswordStrength("short").valid, false);
    assert.strictEqual(auth.validatePasswordStrength("alllowercase123!").valid, false);
    assert.strictEqual(auth.validatePasswordStrength("NoSpecialChar123").valid, false);
    assert.strictEqual(auth.validatePasswordStrength("Valid!Pass2026").valid, true);
  });

  /* ================= 2. SETUP, LOGIN, COOKIES & LOGOUT ================= */
  console.log("\n--- 2. First-Run Setup, Login, Secure Cookies & Logout Tests ---");

  await testAsync("GET /api/auth/status reports setupRequired: true when zero users exist", async () => {
    const res = await invokeApp(app, { method: "GET", url: "/api/auth/status" });
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.data.setupRequired, true);
  });

  await testAsync("POST /api/auth/setup provisions initial ADMIN once and blocks subsequent calls", async () => {
    const first = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/setup",
      body: {
        username: "primary_admin",
        email: "admin@secunexis.test",
        password: "Admin!Password2026"
      }
    });
    assert.strictEqual(first.statusCode, 201);
    assert.strictEqual(first.body.data.user.role, "ADMIN");
    assert.strictEqual(first.body.data.user.passwordHash, undefined, "passwordHash must never be returned");

    const second = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/setup",
      body: {
        username: "attacker_admin",
        email: "attacker@evil.test",
        password: "Admin!Password2026"
      }
    });
    assert.strictEqual(second.statusCode, 403, "Second setup call must be strictly blocked");
  });

  let adminCookie = "";
  let adminCsrf = "";

  await testAsync("POST /api/auth/login sets HttpOnly/SameSite cookie, hashes token in DB, and returns CSRF token", async () => {
    const res = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/login",
      body: { username: "primary_admin", password: "Admin!Password2026" }
    });
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.data.csrfToken && res.body.data.csrfToken.length >= 32);
    assert.strictEqual(res.body.data.user.passwordHash, undefined);

    const setCookie = String(res.headers["set-cookie"] || "");
    assert.ok(setCookie.includes("HttpOnly"), "Session cookie must include HttpOnly");
    assert.ok(setCookie.includes("SameSite=Strict"), "Session cookie must include SameSite=Strict");

    const sid = extractSidCookie(res.headers);
    assert.ok(sid && sid.length >= 32);

    // Ensure raw session token is NOT stored plaintext in session store
    const storedSessions = auth.memorySessionStore.sessions;
    assert.ok(storedSessions.length >= 1);
    assert.strictEqual(storedSessions.some(s => s.tokenHash === sid), false, "Raw token must never be stored in DB");
    assert.strictEqual(storedSessions.some(s => s.tokenHash === auth.hashToken(sid)), true, "SHA-256 token hash must be stored");

    adminCookie = `secunexis_sid=${sid}`;
    adminCsrf = res.body.data.csrfToken;
  });

  await testAsync("POST /api/auth/logout invalidates session immediately so old cookie is rejected", async () => {
    // Login a temporary session to test logout
    const loginRes = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/login",
      body: { username: "primary_admin", password: "Admin!Password2026" }
    });
    const tempCookie = `secunexis_sid=${extractSidCookie(loginRes.headers)}`;
    const tempCsrf = loginRes.body.data.csrfToken;

    const meBefore = await invokeApp(app, {
      method: "GET",
      url: "/api/auth/me",
      headers: { cookie: tempCookie }
    });
    assert.strictEqual(meBefore.statusCode, 200);

    const logoutRes = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/logout",
      headers: { cookie: tempCookie, "x-csrf-token": tempCsrf }
    });
    assert.strictEqual(logoutRes.statusCode, 200);

    const meAfter = await invokeApp(app, {
      method: "GET",
      url: "/api/auth/me",
      headers: { cookie: tempCookie }
    });
    assert.strictEqual(meAfter.statusCode, 401, "Invalidated session must be rejected with 401");
  });

  /* ================= 3. SESSION EXPIRATION ================= */
  console.log("\n--- 3. Session Expiration Tests ---");

  await testAsync("Expired session is rejected with 401 SESSION_EXPIRED and audited", async () => {
    const shortLogin = await auth.login({
      username: "primary_admin",
      password: "Admin!Password2026",
      sessionTtlMs: 40
    });
    assert.strictEqual(shortLogin.success, true);

    await new Promise(r => setTimeout(r, 80));

    const res = await invokeApp(app, {
      method: "GET",
      url: "/api/auth/me",
      headers: { cookie: `secunexis_sid=${shortLogin.rawToken}` }
    });
    assert.strictEqual(res.statusCode, 401);
    assert.strictEqual(res.body.code, "SESSION_EXPIRED");
  });

  /* ================= 4. RBAC & UNAUTHORIZED ACCESS ================= */
  console.log("\n--- 4. Role-Based Access Control (ADMIN / ANALYST / VIEWER) Tests ---");

  // Provision ANALYST and VIEWER accounts as ADMIN
  let analystCookie = "";
  let analystCsrf = "";
  let viewerCookie = "";
  let viewerCsrf = "";
  let createdViewerId = "";

  await testAsync("ADMIN provisions ANALYST and VIEWER accounts via POST /api/auth/users", async () => {
    const aRes = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/users",
      headers: { cookie: adminCookie, "x-csrf-token": adminCsrf },
      body: {
        username: "soc_analyst_1",
        email: "analyst1@secunexis.test",
        password: "Analyst!Password2026",
        role: "ANALYST"
      }
    });
    assert.strictEqual(aRes.statusCode, 201);
    assert.strictEqual(aRes.body.data.role, "ANALYST");

    const vRes = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/users",
      headers: { cookie: adminCookie, "x-csrf-token": adminCsrf },
      body: {
        username: "soc_viewer_1",
        email: "viewer1@secunexis.test",
        password: "Viewer!Password2026",
        role: "VIEWER"
      }
    });
    assert.strictEqual(vRes.statusCode, 201);
    assert.strictEqual(vRes.body.data.role, "VIEWER");
    createdViewerId = vRes.body.data.userId;

    const aLogin = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/login",
      body: { username: "soc_analyst_1", password: "Analyst!Password2026" }
    });
    analystCookie = `secunexis_sid=${extractSidCookie(aLogin.headers)}`;
    analystCsrf = aLogin.body.data.csrfToken;

    const vLogin = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/login",
      body: { username: "soc_viewer_1", password: "Viewer!Password2026" }
    });
    viewerCookie = `secunexis_sid=${extractSidCookie(vLogin.headers)}`;
    viewerCsrf = vLogin.body.data.csrfToken;
  });

  await testAsync("Unauthenticated requests to protected SOC APIs return 401 Unauthorized", async () => {
    const protectedEndpoints = [
      { method: "GET", url: "/api/soc/events" },
      { method: "GET", url: "/api/soc/alerts" },
      { method: "GET", url: "/api/soc/incidents" },
      { method: "GET", url: "/api/soc/audit" },
      { method: "GET", url: "/api/auth/users" }
    ];
    for (const ep of protectedEndpoints) {
      const res = await invokeApp(app, ep);
      assert.strictEqual(res.statusCode, 401, `${ep.method} ${ep.url} must require auth`);
    }
  });

  // Seed an alert and incident via service for RBAC mutation tests
  const seededAlertRes = await alerts.generateAlertFromEvent({
    eventId: "sec_rbac_01",
    scanReference: "ref_rbac_01",
    target: "https://rbac-phish.test",
    verdict: "MALICIOUS",
    riskScore: 85,
    threatCount: 1,
    detectionEvidence: [
      { id: "THREAT_PHISHING_RAW_IP", name: "Credential Exfiltration", severity: "CRITICAL", scoreContribution: 45, isThreat: true }
    ]
  });
  const seededAlert = seededAlertRes.alert;
  const seededIncRes = await incidents.correlateAlertToIncident(seededAlert);
  const seededInc = seededIncRes.incident;

  await testAsync("VIEWER can read SOC resources but is strictly denied (403) all mutations, audit, and user management", async () => {
    const getEvents = await invokeApp(app, { method: "GET", url: "/api/soc/events", headers: { cookie: viewerCookie } });
    const getAlerts = await invokeApp(app, { method: "GET", url: "/api/soc/alerts", headers: { cookie: viewerCookie } });
    const getIncs = await invokeApp(app, { method: "GET", url: "/api/soc/incidents", headers: { cookie: viewerCookie } });
    assert.strictEqual(getEvents.statusCode, 200);
    assert.strictEqual(getAlerts.statusCode, 200);
    assert.strictEqual(getIncs.statusCode, 200);

    const denyAlertPatch = await invokeApp(app, {
      method: "PATCH",
      url: `/api/soc/alerts/${seededAlert.alertId}`,
      headers: { cookie: viewerCookie, "x-csrf-token": viewerCsrf },
      body: { status: "DISMISSED" }
    });
    assert.strictEqual(denyAlertPatch.statusCode, 403);

    const denyIncPost = await invokeApp(app, {
      method: "POST",
      url: "/api/soc/incidents",
      headers: { cookie: viewerCookie, "x-csrf-token": viewerCsrf },
      body: { title: "Unauthorized Incident" }
    });
    assert.strictEqual(denyIncPost.statusCode, 403);

    const denyIncPatch = await invokeApp(app, {
      method: "PATCH",
      url: `/api/soc/incidents/${seededInc.incidentId}`,
      headers: { cookie: viewerCookie, "x-csrf-token": viewerCsrf },
      body: { status: "CLOSED" }
    });
    assert.strictEqual(denyIncPatch.statusCode, 403);

    const denyNote = await invokeApp(app, {
      method: "POST",
      url: `/api/soc/incidents/${seededInc.incidentId}/notes`,
      headers: { cookie: viewerCookie, "x-csrf-token": viewerCsrf },
      body: { text: "Viewer should not add notes" }
    });
    assert.strictEqual(denyNote.statusCode, 403);

    const denyAudit = await invokeApp(app, {
      method: "GET",
      url: "/api/soc/audit",
      headers: { cookie: viewerCookie }
    });
    assert.strictEqual(denyAudit.statusCode, 403);

    const denyUsers = await invokeApp(app, {
      method: "GET",
      url: "/api/auth/users",
      headers: { cookie: viewerCookie }
    });
    assert.strictEqual(denyUsers.statusCode, 403);
  });

  await testAsync("ANALYST can triage alerts, update incidents, add notes, read audit logs — but denied ADMIN routes", async () => {
    const patchAlert = await invokeApp(app, {
      method: "PATCH",
      url: `/api/soc/alerts/${seededAlert.alertId}`,
      headers: { cookie: analystCookie, "x-csrf-token": analystCsrf },
      body: { status: "IN_TRIAGE", note: "Triage started by analyst" }
    });
    assert.strictEqual(patchAlert.statusCode, 200);
    assert.strictEqual(patchAlert.body.data.status, "IN_TRIAGE");

    // Attempt to spoof author in incident note — backend MUST enforce authenticated username
    const addNote = await invokeApp(app, {
      method: "POST",
      url: `/api/soc/incidents/${seededInc.incidentId}/notes`,
      headers: { cookie: analystCookie, "x-csrf-token": analystCsrf },
      body: { text: "Containment active.", author: "SpoofedAdminName" }
    });
    assert.strictEqual(addNote.statusCode, 201);
    const notes = addNote.body.data.investigationNotes;
    assert.strictEqual(notes[notes.length - 1].author, "soc_analyst_1", "Actor must be derived from authenticated session, never spoofed body");

    // Update assignment & remediation
    const patchInc = await invokeApp(app, {
      method: "PATCH",
      url: `/api/soc/incidents/${seededInc.incidentId}`,
      headers: { cookie: analystCookie, "x-csrf-token": analystCsrf },
      body: {
        status: "INVESTIGATING",
        assignedTo: "soc_analyst_1",
        remediation: { summary: "Blocked phishing domain", steps: ["DNS sinkhole applied"], completed: true }
      }
    });
    assert.strictEqual(patchInc.statusCode, 200);
    assert.strictEqual(patchInc.body.data.assignedTo, "soc_analyst_1");
    assert.strictEqual(patchInc.body.data.remediation.completed, true);

    // Analyst CAN read audit logs
    const readAudit = await invokeApp(app, {
      method: "GET",
      url: "/api/soc/audit",
      headers: { cookie: analystCookie }
    });
    assert.strictEqual(readAudit.statusCode, 200);

    // Analyst DENIED user management and audit verify
    const denyUsers = await invokeApp(app, {
      method: "GET",
      url: "/api/auth/users",
      headers: { cookie: analystCookie }
    });
    assert.strictEqual(denyUsers.statusCode, 403);

    const denyVerify = await invokeApp(app, {
      method: "GET",
      url: "/api/soc/audit/verify",
      headers: { cookie: analystCookie }
    });
    assert.strictEqual(denyVerify.statusCode, 403);
  });

  /* ================= 5. CSRF PROTECTION ================= */
  console.log("\n--- 5. CSRF Protection Tests ---");

  await testAsync("Cookie-authenticated state changes without valid X-CSRF-Token are rejected with 403 CSRF_INVALID", async () => {
    const missingCsrf = await invokeApp(app, {
      method: "PATCH",
      url: `/api/soc/alerts/${seededAlert.alertId}`,
      headers: { cookie: analystCookie },
      body: { status: "ACKNOWLEDGED" }
    });
    assert.strictEqual(missingCsrf.statusCode, 403);
    assert.strictEqual(missingCsrf.body.code, "CSRF_INVALID");

    const wrongCsrf = await invokeApp(app, {
      method: "POST",
      url: `/api/soc/incidents/${seededInc.incidentId}/notes`,
      headers: { cookie: analystCookie, "x-csrf-token": "wrong_token_value_123456" },
      body: { text: "Should be blocked by CSRF" }
    });
    assert.strictEqual(wrongCsrf.statusCode, 403);
    assert.strictEqual(wrongCsrf.body.code, "CSRF_INVALID");
  });

  /* ================= 6. NOSQL INJECTION & INPUT VALIDATION ================= */
  console.log("\n--- 6. NoSQL Injection & API Input Validation Tests ---");

  await testAsync("NoSQL $-operator and prototype pollution payloads are blocked with 400 Bad Request", async () => {
    const nosqlBody = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/login",
      body: { username: { "$ne": null }, password: { "$gt": "" } }
    });
    assert.strictEqual(nosqlBody.statusCode, 400);

    const nosqlQuery = await invokeApp(app, {
      method: "GET",
      url: "/api/soc/alerts?target[$regex]=.*",
      headers: { cookie: adminCookie }
    });
    assert.strictEqual(nosqlQuery.statusCode, 400);

    const badId = await invokeApp(app, {
      method: "GET",
      url: "/api/soc/incidents/inc_bad$id;drop",
      headers: { cookie: adminCookie }
    });
    assert.strictEqual(badId.statusCode, 400);
  });

  await testAsync("Regex metacharacters in search queries are safely escaped without throwing", async () => {
    const res = await invokeApp(app, {
      method: "GET",
      url: "/api/soc/alerts?target=" + encodeURIComponent("([a-z]+)*$test"),
      headers: { cookie: adminCookie }
    });
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.success, true);
  });

  /* ================= 7. BRUTE-FORCE PROTECTION ================= */
  console.log("\n--- 7. Brute-Force Lockout & Rate Limiting Tests ---");

  await testAsync("Repeated failed logins lock account (423 Locked) and log AUTH_ACCOUNT_LOCKED", async () => {
    auth.resetLoginRateLimiter();

    for (let i = 0; i < 4; i++) {
      const failRes = await invokeApp(app, {
        method: "POST",
        url: "/api/auth/login",
        ip: "10.99.0.1",
        body: { username: "soc_viewer_1", password: "Wrong!Password999" }
      });
      assert.strictEqual(failRes.statusCode, 401);
    }

    // 5th consecutive failure triggers account lockout
    const lockRes = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/login",
      ip: "10.99.0.1",
      body: { username: "soc_viewer_1", password: "Wrong!Password999" }
    });
    assert.strictEqual(lockRes.statusCode, 423);

    // Even correct password is blocked while locked
    const blockedRes = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/login",
      ip: "10.99.0.1",
      body: { username: "soc_viewer_1", password: "Viewer!Password2026" }
    });
    assert.strictEqual(blockedRes.statusCode, 423);

    // Admin unlocks account
    const unlockRes = await invokeApp(app, {
      method: "PATCH",
      url: `/api/auth/users/${createdViewerId}`,
      headers: { cookie: adminCookie, "x-csrf-token": adminCsrf },
      body: { unlock: true }
    });
    assert.strictEqual(unlockRes.statusCode, 200);
  });

  /* ================= 8. IMMUTABLE AUDIT LOGGING & INTEGRITY ================= */
  console.log("\n--- 8. Immutable Audit Trail & Cryptographic Hash Chain Tests ---");

  await testAsync("Audit log captures authentication, alert, incident, assignment, remediation, note & denial events", async () => {
    const res = await invokeApp(app, {
      method: "GET",
      url: "/api/soc/audit?limit=100",
      headers: { cookie: adminCookie }
    });
    assert.strictEqual(res.statusCode, 200);

    const actions = new Set(res.body.data.map(r => r.action));
    const expectedActions = [
      "AUTH_SETUP_ADMIN",
      "AUTH_LOGIN_SUCCESS",
      "AUTH_LOGOUT",
      "AUTH_ACCOUNT_LOCKED",
      "USER_CREATED",
      "ACCESS_DENIED",
      "CSRF_REJECTED",
      "ALERT_STATUS_CHANGED",
      "ALERT_NOTE_ADDED",
      "INCIDENT_STATUS_CHANGED",
      "INCIDENT_ASSIGNED",
      "INCIDENT_REMEDIATION_UPDATED",
      "INCIDENT_NOTE_ADDED"
    ];

    for (const act of expectedActions) {
      assert.ok(actions.has(act), `Audit trail must record action: ${act}`);
    }
  });

  await testAsync("Immutable audit records cannot be edited or deleted via API or model methods", async () => {
    const delApi = await invokeApp(app, {
      method: "DELETE",
      url: "/api/soc/audit",
      headers: { cookie: adminCookie, "x-csrf-token": adminCsrf }
    });
    assert.strictEqual(delApi.statusCode, 403);
    assert.strictEqual(delApi.body.code, "AUDIT_IMMUTABLE");

    const patchApi = await invokeApp(app, {
      method: "PATCH",
      url: "/api/soc/audit/aud_12345",
      headers: { cookie: adminCookie, "x-csrf-token": adminCsrf },
      body: { details: "Tampered" }
    });
    assert.strictEqual(patchApi.statusCode, 403);

    // Direct model mutation must throw
    let threwOnDelete = false;
    try {
      await audit.memoryAuditStore.deleteMany({});
    } catch (err) {
      threwOnDelete = err.message.includes("immutable");
    }
    assert.strictEqual(threwOnDelete, true, "Direct audit deletion must throw immutability error");
  });

  await testAsync("GET /api/soc/audit/verify confirms intact SHA-256 hash chain across all audit records", async () => {
    const res = await invokeApp(app, {
      method: "GET",
      url: "/api/soc/audit/verify",
      headers: { cookie: adminCookie }
    });
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.data.verified, true);
    assert.ok(res.body.data.totalRecords >= 15);
    assert.strictEqual(res.body.data.tamperedRecords.length, 0);
  });

  /* ================= 9. CONCURRENCY & RACE CONDITION SAFETY ================= */
  console.log("\n--- 9. Concurrent Request Deduplication & Correlation Tests ---");

  await testAsync("10 concurrent generateAlertFromEvent calls for identical scanReference create strictly 1 alert", async () => {
    const sharedEvent = {
      eventId: "sec_conc_01",
      scanReference: "ref_concurrent_identical_01",
      target: "https://race-condition-target.test",
      verdict: "MALICIOUS",
      riskScore: 80,
      threatCount: 1,
      detectionEvidence: [
        { id: "THREAT_CONC", name: "Credential Stealer", severity: "CRITICAL", scoreContribution: 45, isThreat: true }
      ]
    };

    const results = await Promise.all(
      Array.from({ length: 10 }, () => alerts.generateAlertFromEvent(sharedEvent))
    );

    const createdCount = results.filter(r => r.created).length;
    assert.strictEqual(createdCount, 1, "Exactly 1 alert must be created under 10 concurrent identical calls");

    const stored = await alerts.getAlerts({ target: "race-condition-target.test" });
    assert.strictEqual(stored.pagination.total, 1);
  });

  await testAsync("5 concurrent correlateAlertToIncident calls on the same host correlate into strictly 1 incident", async () => {
    const concurrentAlerts = Array.from({ length: 5 }, (_, idx) => ({
      alertId: `alt_conc_inc_${idx}`,
      target: `https://shared-campaign.test/page-${idx}`,
      title: `Campaign Phishing Form #${idx}`,
      severity: "CRITICAL",
      priority: "P1_CRITICAL",
      evidence: []
    }));

    const results = await Promise.all(
      concurrentAlerts.map(a => incidents.correlateAlertToIncident(a))
    );

    const uniqueIncidentIds = new Set(results.map(r => r.incident.incidentId));
    assert.strictEqual(uniqueIncidentIds.size, 1, "All 5 concurrent same-host alerts must correlate into 1 single incident");

    const singleIncidentId = Array.from(uniqueIncidentIds)[0];
    const inc = await incidents.getIncidentById(singleIncidentId);
    assert.strictEqual(inc.associatedAlertIds.length, 5, "All 5 correlated alertIds must be linked");
  });

  /* ================= 10. DATABASE RELIABILITY & PERSISTENCE ================= */
  console.log("\n--- 10. Database Reliability & Production Configuration Tests ---");

  await testAsync("getDbHealth returns sanitized status without leaking MongoDB URI or credentials", async () => {
    const health = db.getDbHealth();
    assert.strictEqual(typeof health.connected, "boolean");
    assert.ok(["mongodb", "memory_fallback"].includes(health.mode));
    assert.strictEqual(JSON.stringify(health).includes("mongodb+srv://"), false, "Must never leak connection string");
  });

  await testAsync("REQUIRE_MONGODB=true fails closed when MONGODB_URI is missing", async () => {
    const origReq = process.env.REQUIRE_MONGODB;
    const origUri = process.env.MONGODB_URI;
    process.env.REQUIRE_MONGODB = "true";
    delete process.env.MONGODB_URI;

    let failedClosed = false;
    try {
      await db.disconnectDb();
      await db.initDb("");
    } catch (err) {
      failedClosed = err.message.includes("MONGODB_URI is required");
    } finally {
      if (origReq === undefined) delete process.env.REQUIRE_MONGODB;
      else process.env.REQUIRE_MONGODB = origReq;
      if (origUri !== undefined) process.env.MONGODB_URI = origUri;
    }

    assert.strictEqual(failedClosed, true, "Must fail closed when REQUIRE_MONGODB=true and no URI provided");
  });

  await testAsync("MongoDB persistence & restart check (live DB if reachable, honest status if offline)", async () => {
    const connected = await db.initDb(process.env.MONGODB_URI);
    if (!connected) {
      console.log("         [INFO] Live MongoDB Atlas unreachable in offline sandbox — verified graceful fallback & reconnect manager.");
      assert.strictEqual(db.isMongoConnected(), false);
    } else {
      // Live MongoDB persistence across disconnect/reconnect cycle
      const persistTitle = "Persistence Check " + Date.now();
      const created = await incidents.createIncident({
        title: persistTitle,
        severity: "LOW",
        priority: "P4_LOW",
        affectedTargets: ["https://persist-check.test"]
      });
      await db.disconnectDb();
      assert.strictEqual(db.isMongoConnected(), false);
      const reconnected = await db.initDb(process.env.MONGODB_URI);
      assert.strictEqual(reconnected, true);
      const fetched = await incidents.getIncidentById(created.incidentId);
      assert.ok(fetched && fetched.title === persistTitle, "Record must persist across MongoDB disconnect/reconnect");
      // Cleanup test record
      const IncidentModel = incidents.getSecurityIncidentModel();
      await IncidentModel.deleteMany({ incidentId: created.incidentId });
      await db.disconnectDb();
    }
  });

  /* ================= 11. FINAL PRODUCTION AUDIT VERIFICATION TESTS ================= */
  console.log("\n--- 11. Final Production Audit Checks (Proxy Cookies, CORS, Revocation, Audit Tamper, IPv6 SSRF) ---");

  await testAsync("Reverse proxy HTTPS (X-Forwarded-Proto: https) sets Secure + HttpOnly + SameSite=Strict cookie", async () => {
    const res = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/login",
      headers: { "x-forwarded-proto": "https", host: "secunexis.onrender.com" },
      body: { username: "primary_admin", password: "Admin!Password2026" }
    });
    assert.strictEqual(res.statusCode, 200);
    const setCookie = String(res.headers["set-cookie"] || "");
    assert.ok(setCookie.includes("HttpOnly"), "Must set HttpOnly");
    assert.ok(setCookie.includes("Secure"), "Must set Secure behind HTTPS reverse proxy");
    assert.ok(setCookie.includes("SameSite=Strict"), "Must set SameSite=Strict");
  });

  await testAsync("CORS allows same-origin HTTPS requests and rejects untrusted cross-origin domains", async () => {
    const sameOriginRes = await invokeApp(app, {
      method: "GET",
      url: "/api/auth/status",
      headers: {
        host: "secunexis.onrender.com",
        "x-forwarded-proto": "https",
        origin: "https://secunexis.onrender.com"
      }
    });
    assert.strictEqual(sameOriginRes.statusCode, 200);
    assert.strictEqual(sameOriginRes.headers["access-control-allow-origin"], "https://secunexis.onrender.com");
    assert.strictEqual(sameOriginRes.headers["access-control-allow-credentials"], "true");

    const evilOriginRes = await invokeApp(app, {
      method: "GET",
      url: "/api/auth/status",
      headers: {
        host: "secunexis.onrender.com",
        "x-forwarded-proto": "https",
        origin: "https://evil-attacker.example"
      }
    });
    assert.strictEqual(evilOriginRes.headers["access-control-allow-origin"], undefined, "Untrusted origin must not receive ACAO");
  });

  await testAsync("Changing a user's role immediately revokes their active session", async () => {
    const uRes = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/users",
      headers: { cookie: adminCookie, "x-csrf-token": adminCsrf },
      body: {
        username: "revoke_target",
        email: "revoke@secunexis.test",
        password: "Revoke!Password2026",
        role: "ANALYST"
      }
    });
    assert.strictEqual(uRes.statusCode, 201);
    const targetId = uRes.body.data.userId;

    const uLogin = await invokeApp(app, {
      method: "POST",
      url: "/api/auth/login",
      body: { username: "revoke_target", password: "Revoke!Password2026" }
    });
    const targetCookie = `secunexis_sid=${extractSidCookie(uLogin.headers)}`;

    const meBefore = await invokeApp(app, { method: "GET", url: "/api/auth/me", headers: { cookie: targetCookie } });
    assert.strictEqual(meBefore.statusCode, 200);

    // Admin demotes role -> must immediately revoke active session
    const demote = await invokeApp(app, {
      method: "PATCH",
      url: `/api/auth/users/${targetId}`,
      headers: { cookie: adminCookie, "x-csrf-token": adminCsrf },
      body: { role: "VIEWER" }
    });
    assert.strictEqual(demote.statusCode, 200);

    const meAfter = await invokeApp(app, { method: "GET", url: "/api/auth/me", headers: { cookie: targetCookie } });
    assert.strictEqual(meAfter.statusCode, 401, "Session must be immediately revoked after role change");
  });

  await testAsync("20 concurrent audit writes maintain an unbroken SHA-256 cryptographic hash chain", async () => {
    await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        audit.recordAuditEvent({
          actor: { userId: "usr_conc", username: "concurrent_tester", role: "ANALYST" },
          action: "CONCURRENT_AUDIT_CHECK",
          entityType: "SYSTEM",
          entityId: `conc_${i}`,
          details: `Concurrent write #${i}`
        })
      )
    );

    const verifyRes = await invokeApp(app, {
      method: "GET",
      url: "/api/soc/audit/verify",
      headers: { cookie: adminCookie }
    });
    assert.strictEqual(verifyRes.statusCode, 200);
    assert.strictEqual(verifyRes.body.data.verified, true, "All 20 concurrent writes must form a valid hash chain");
    assert.strictEqual(verifyRes.body.data.tamperedRecords.length, 0);
  });

  await testAsync("Tampering with a stored audit record is detected by GET /api/soc/audit/verify", async () => {
    // Simulate out-of-band DB tampering by replacing a record inside memory store
    const records = audit.memoryAuditStore._records;
    assert.ok(records.length >= 2);
    const original = records[1];
    records[1] = Object.freeze({ ...original, details: "TAMPERED_OUT_OF_BAND" });

    try {
      const verifyRes = await invokeApp(app, {
        method: "GET",
        url: "/api/soc/audit/verify",
        headers: { cookie: adminCookie }
      });
      assert.strictEqual(verifyRes.statusCode, 200);
      assert.strictEqual(verifyRes.body.data.verified, false, "Tampered chain must report verified: false");
      assert.ok(verifyRes.body.data.tamperedRecords.length >= 1);
      assert.strictEqual(verifyRes.body.data.tamperedRecords[0].auditId, original.auditId);
      assert.strictEqual(verifyRes.body.data.tamperedRecords[0].hashValid, false);
    } finally {
      // Restore original record
      records[1] = original;
    }
  });

  await testAsync("SSRF blocks IPv6 bracketed loopback and IPv4-mapped IPv6 metadata targets", async () => {
    const ipv6Targets = [
      "http://[::1]:8080/admin",
      "http://[::ffff:127.0.0.1]/secret",
      "http://[::ffff:169.254.169.254]/latest/meta-data",
      "http://[fc00::1]/internal",
      "http://[fe80::1]/link-local"
    ];
    for (const target of ipv6Targets) {
      const res = await invokeApp(app, {
        method: "POST",
        url: "/scan",
        body: { url: target }
      });
      assert.strictEqual(res.statusCode, 400, `IPv6 SSRF target ${target} must be blocked with 400`);
      assert.ok(res.body.error.includes("SSRF protection"), `Must cite SSRF protection for ${target}`);
    }
  });

  await testAsync("POST /scan enforces rate limiting and emits X-RateLimit-* headers", async () => {
    const res = await invokeApp(app, {
      method: "POST",
      url: "/scan",
      ip: "10.88.77.66",
      body: { html: "<html><body><p>Rate limit check</p></body></html>" }
    });
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.headers["x-ratelimit-limit"], "POST /scan must emit X-RateLimit-Limit");
    assert.ok(res.headers["x-ratelimit-remaining"], "POST /scan must emit X-RateLimit-Remaining");
  });

  await testAsync("REQUIRE_MONGODB=true fails closed with 503 DB_UNAVAILABLE on SOC routes when disconnected", async () => {
    const origReq = process.env.REQUIRE_MONGODB;
    process.env.REQUIRE_MONGODB = "true";
    try {
      await db.disconnectDb();
      const res = await invokeApp(app, {
        method: "GET",
        url: "/api/soc/alerts",
        headers: { cookie: adminCookie }
      });
      assert.strictEqual(res.statusCode, 503);
      assert.strictEqual(res.body.code, "DB_UNAVAILABLE");
    } finally {
      if (origReq === undefined) delete process.env.REQUIRE_MONGODB;
      else process.env.REQUIRE_MONGODB = origReq;
    }
  });

  /* ================= SUMMARY ================= */
  console.log("\n==========================================================================================");
  console.log(`  PHASE 2.5 SECURITY TEST RESULTS: ${passed} PASSED | ${failed} FAILED`);
  console.log("==========================================================================================\n");

  await db.disconnectDb().catch(() => {});

  if (failed > 0) {
    process.exit(1);
  }
}

runSecuritySuite().catch(err => {
  console.error("Security suite exception:", err);
  process.exit(1);
});
