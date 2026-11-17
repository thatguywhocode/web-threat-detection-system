/**
 * SecuNexis Enterprise SOC — Phase 2 Alerting & Incident Management Test Suite
 *
 * Verifies:
 * 1. SecurityAlert model & memory store semantics
 * 2. Alert rules engine (fatigue prevention, severity/priority mapping, evidence structure)
 * 3. Alert service (idempotent generation, deduplication, search/pagination, triage updates, stats)
 * 4. SecurityIncident model & memory store semantics
 * 5. Incident correlation engine (defensible host/endpoint matching, no arbitrary grouping, dynamic elevation)
 * 6. Incident service (escalation, correlation, lifecycle transitions, investigation notes log, stats)
 * 7. In-process REST API integration (/api/soc/alerts, /api/soc/incidents)
 * 8. End-to-end scan pipeline triggering automated event -> alert -> incident correlation
 */

const assert = require("assert");
const http = require("http");
const { PassThrough } = require("stream");

// SOC Phase 2 Imports
const {
  getSecurityAlertModel,
  memoryAlertStore,
  evaluateAlertRules,
  generateAlertFromEvent,
  getAlerts,
  getAlertById,
  updateAlert,
  getAlertStats
} = require("../src/soc/alerts");

const {
  getSecurityIncidentModel,
  memoryIncidentStore,
  findCorrelatedIncident,
  elevateSeverity,
  elevatePriority,
  createIncident,
  correlateAlertToIncident,
  getIncidents,
  getIncidentById,
  updateIncident,
  addInvestigationNote,
  getIncidentStats
} = require("../src/soc/incidents");

const app = require("../src/server");

// Test Counters
let passed = 0;
let failed = 0;

function runTest(name, fn) {
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

async function runAsyncTest(name, fn) {
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

/**
 * In-process mock dispatcher for Express app without opening live TCP ports
 */
function invokeApp(appInstance, { method, url, body = null, headers = {} }) {
  return new Promise((resolve, reject) => {
    const socket = new PassThrough();
    const req = new http.IncomingMessage(socket);
    req.method = method;
    req.url = url;
    req.headers = {
      host: "localhost:3000",
      "user-agent": "SecuNexisPhase2TestRunner",
      accept: "application/json",
      ...headers
    };

    if (body) {
      const payload = typeof body === "string" ? body : JSON.stringify(body);
      req.headers["content-type"] = req.headers["content-type"] || "application/json";
      req.headers["content-length"] = Buffer.byteLength(payload);
    }

    let statusCode = 200;
    const responseHeaders = {};
    let responseBody = "";

    const res = {
      _headerSent: false,
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

    if (body) {
      const payload = typeof body === "string" ? body : JSON.stringify(body);
      req.push(payload);
    }
    req.push(null);
  });
}

async function runAllTests() {
  console.log("\n==========================================================================================");
  console.log("  SECUNEXIS ENTERPRISE SOC: PHASE 2 ALERTS & INCIDENTS TEST SUITE");
  console.log("==========================================================================================\n");

  // Reset in-memory stores before tests
  await memoryAlertStore.deleteMany({});
  await memoryIncidentStore.deleteMany({});

  /* ================= 1. SECURITY ALERT MODEL TESTS ================= */
  console.log("--- 1. SecurityAlert Model & Memory Store Tests ---");

  runTest("SecurityAlert store provides standard query operations", () => {
    const Model = getSecurityAlertModel();
    assert.strictEqual(typeof Model.find, "function");
    assert.strictEqual(typeof Model.findOne, "function");
    assert.strictEqual(typeof Model.findOneAndUpdate, "function");
    assert.strictEqual(typeof Model.countDocuments, "function");
  });

  await runAsyncTest("SecurityAlert instantiates with default alertId and valid timestamps", async () => {
    const Model = getSecurityAlertModel();
    const alert = new Model({
      eventId: "sec_test_001",
      scanReference: "scan_ref_test_001",
      target: "https://phishing-portal.com",
      title: "Credential Harvesting Detected",
      severity: "CRITICAL",
      priority: "P1_CRITICAL",
      riskScore: 85
    });

    const saved = await alert.save();
    assert.ok(saved.alertId.startsWith("alt_"));
    assert.strictEqual(saved.status, "NEW");
    assert.strictEqual(saved.severity, "CRITICAL");
    assert.strictEqual(saved.priority, "P1_CRITICAL");
    assert.ok(saved.createdAt instanceof Date);
  });

  /* ================= 2. ALERT RULES ENGINE TESTS ================= */
  console.log("\n--- 2. Alert Rules Engine Tests ---");

  runTest("Rule engine suppresses alert for SAFE target with 0 threats (Fatigue Prevention)", () => {
    const safeEvent = {
      eventId: "sec_safe_01",
      scanReference: "ref_safe_01",
      target: "https://github.com",
      verdict: "SAFE",
      riskScore: 0,
      threatCount: 0,
      findings: [
        { id: "info_1", name: "Modern Scripts", isThreat: false, scoreContribution: 0 }
      ],
      virusTotalSummary: { available: true, malicious: 0, suspicious: 0 }
    };

    const res = evaluateAlertRules(safeEvent);
    assert.strictEqual(res.shouldAlert, false);
    assert.strictEqual(res.alertData, null);
    assert.ok(res.reason.includes("SAFE"));
  });

  runTest("Rule engine suppresses alert for INCONCLUSIVE target with 0 threats", () => {
    const inconclusiveEvent = {
      eventId: "sec_inc_01",
      scanReference: "ref_inc_01",
      target: "https://example-inconclusive.com",
      verdict: "INCONCLUSIVE",
      riskScore: 0,
      threatCount: 0,
      findings: [],
      virusTotalSummary: { available: false, malicious: 0 }
    };

    const res = evaluateAlertRules(inconclusiveEvent);
    assert.strictEqual(res.shouldAlert, false);
    assert.strictEqual(res.alertData, null);
  });

  runTest("Rule engine generates CRITICAL / P1_CRITICAL alert for hidden credential harvester", () => {
    const maliciousEvent = {
      eventId: "sec_mal_01",
      scanReference: "ref_mal_01",
      target: "https://secure-login-steal.com/auth",
      verdict: "MALICIOUS",
      riskScore: 80,
      threatCount: 2,
      findings: [
        {
          id: "THREAT_HIDDEN_CREDENTIAL_FORM",
          name: "Hidden Credential Form",
          severity: "HIGH",
          scoreContribution: 30,
          isThreat: true,
          explanation: "Form hidden with display:none"
        },
        {
          id: "THREAT_PHISHING_CREDENTIAL_SUBMISSION_RAW_IP",
          name: "Exfiltration to Raw IP",
          severity: "CRITICAL",
          scoreContribution: 45,
          isThreat: true,
          explanation: "Form action points to raw IP 192.168.1.100"
        }
      ],
      virusTotalSummary: { available: false, malicious: 0 }
    };

    const res = evaluateAlertRules(maliciousEvent);
    assert.strictEqual(res.shouldAlert, true);
    assert.ok(res.alertData);
    assert.strictEqual(res.alertData.severity, "CRITICAL");
    assert.strictEqual(res.alertData.priority, "P1_CRITICAL");
    assert.strictEqual(res.alertData.verdict, "MALICIOUS");
    assert.strictEqual(res.alertData.evidence.length, 2);
    assert.ok(res.alertData.title.includes("Critical Threat Detected"));
  });

  runTest("Rule engine generates CRITICAL alert when VirusTotal confirms >= 3 malicious detections", () => {
    const vtEvent = {
      eventId: "sec_vt_01",
      scanReference: "ref_vt_01",
      target: "https://confirmed-malware-drop.ru",
      verdict: "MALICIOUS",
      riskScore: 75,
      threatCount: 1,
      findings: [],
      virusTotalSummary: { available: true, malicious: 5, suspicious: 1, message: "Flagged by 5 engines" }
    };

    const res = evaluateAlertRules(vtEvent);
    assert.strictEqual(res.shouldAlert, true);
    assert.strictEqual(res.alertData.severity, "CRITICAL");
    assert.strictEqual(res.alertData.priority, "P1_CRITICAL");
    assert.strictEqual(res.alertData.detectionSource, "VIRUSTOTAL_THREAT_INTEL");
    assert.ok(res.alertData.title.includes("VirusTotal") || res.alertData.title.includes("Security Engines"));
  });

  /* ================= 3. ALERT SERVICE & DEDUPLICATION TESTS ================= */
  console.log("\n--- 3. Alert Service & Deduplication Tests ---");

  await runAsyncTest("generateAlertFromEvent idempotently handles duplicate events", async () => {
    const event = {
      eventId: "sec_dedup_01",
      scanReference: "ref_dedup_01",
      target: "https://phish-site.org",
      verdict: "MALICIOUS",
      riskScore: 70,
      threatCount: 1,
      findings: [
        { id: "t1", name: "Malicious Script", severity: "HIGH", scoreContribution: 25, isThreat: true }
      ]
    };

    const first = await generateAlertFromEvent(event);
    assert.strictEqual(first.created, true);
    assert.ok(first.alert);

    // Second call with same scanReference
    const second = await generateAlertFromEvent(event);
    assert.strictEqual(second.created, false);
    assert.strictEqual(second.alert.alertId, first.alert.alertId);
    assert.ok(second.reason.includes("already exists"));
  });

  await runAsyncTest("getAlerts filters by severity and target substring with pagination", async () => {
    const res = await getAlerts({ severity: "CRITICAL", page: 1, limit: 10 });
    assert.ok(Array.isArray(res.alerts));
    assert.ok(res.pagination.total >= 1);
    assert.strictEqual(res.alerts[0].severity, "CRITICAL");
  });

  await runAsyncTest("updateAlert updates status and appends analyst notes", async () => {
    const { alerts } = await getAlerts({ limit: 1 });
    const targetAlert = alerts[0];

    const updated = await updateAlert(
      targetAlert.alertId,
      { status: "IN_TRIAGE", note: "Analyst investigating observed payload" },
      "Senior Analyst Alice"
    );

    assert.strictEqual(updated.status, "IN_TRIAGE");
    assert.ok(Array.isArray(updated.analystNotes));
    assert.strictEqual(updated.analystNotes[0].author, "Senior Analyst Alice");
    assert.ok(updated.analystNotes[0].note.includes("investigating"));
  });

  await runAsyncTest("getAlertStats computes aggregate counts correctly", async () => {
    const stats = await getAlertStats();
    assert.ok(stats.totalAlerts >= 1);
    assert.ok(typeof stats.bySeverity.CRITICAL === "number");
    assert.ok(typeof stats.byPriority.P1_CRITICAL === "number");
    assert.ok(typeof stats.unassignedCount === "number");
  });

  /* ================= 4. INCIDENT MODEL & CORRELATION TESTS ================= */
  console.log("\n--- 4. Incident Model & Correlation Tests ---");

  runTest("Incident store provides standard query operations", () => {
    const Model = getSecurityIncidentModel();
    assert.strictEqual(typeof Model.find, "function");
    assert.strictEqual(typeof Model.findOne, "function");
    assert.strictEqual(typeof Model.findOneAndUpdate, "function");
  });

  await runAsyncTest("SecurityIncident creates instance with inc_ prefix and default status OPEN", async () => {
    const Model = getSecurityIncidentModel();
    const inc = new Model({
      title: "Phishing Campaign targeting Corp Credentials",
      severity: "HIGH",
      priority: "P2_HIGH",
      attackVector: "CREDENTIAL_HARVESTING",
      affectedTargets: ["https://login.victim-corp.com"]
    });

    const saved = await inc.save();
    assert.ok(saved.incidentId.startsWith("inc_"));
    assert.strictEqual(saved.status, "OPEN");
    assert.strictEqual(saved.attackVector, "CREDENTIAL_HARVESTING");
    assert.ok(Array.isArray(saved.investigationNotes));
  });

  runTest("Correlation Engine correlates alert by target host match", () => {
    const activeIncidents = [
      {
        incidentId: "inc_001",
        status: "OPEN",
        affectedTargets: ["https://auth.sample-phish.net/login"],
        attackVector: "CREDENTIAL_HARVESTING",
        severity: "MEDIUM",
        priority: "P3_MEDIUM"
      }
    ];

    const alert = {
      alertId: "alt_101",
      target: "https://auth.sample-phish.net/verify",
      title: "Credential Stealer Detected",
      severity: "HIGH",
      priority: "P2_HIGH"
    };

    const correlation = findCorrelatedIncident(alert, activeIncidents);
    assert.ok(correlation.matchedIncident);
    assert.strictEqual(correlation.matchedIncident.incidentId, "inc_001");
    assert.ok(correlation.reason.includes("Target host match"));
  });

  runTest("Correlation Engine correlates alert by shared exfiltration endpoint", () => {
    const activeIncidents = [
      {
        incidentId: "inc_002",
        status: "OPEN",
        affectedTargets: ["https://first-landing.xyz"],
        exfiltrationEndpoints: ["http://185.220.101.5/collect.php"],
        attackVector: "CREDENTIAL_HARVESTING",
        severity: "HIGH"
      }
    ];

    const alert = {
      alertId: "alt_102",
      target: "https://second-landing.xyz",
      title: "Phishing Form",
      severity: "CRITICAL",
      evidence: [
        {
          name: "Exfiltration",
          explanation: "Submits to http://185.220.101.5/collect.php",
          evidence: "form action=http://185.220.101.5/collect.php"
        }
      ]
    };

    const correlation = findCorrelatedIncident(alert, activeIncidents);
    assert.ok(correlation.matchedIncident);
    assert.strictEqual(correlation.matchedIncident.incidentId, "inc_002");
    assert.ok(correlation.reason.includes("Exfiltration endpoint match"));
  });

  runTest("Correlation Engine strictly NEVER correlates unrelated targets solely by severity similarity", () => {
    const activeIncidents = [
      {
        incidentId: "inc_003",
        status: "OPEN",
        affectedTargets: ["https://alpha-bank-phish.com"],
        exfiltrationEndpoints: ["http://10.0.0.1/drop"],
        attackVector: "CREDENTIAL_HARVESTING",
        severity: "HIGH",
        priority: "P2_HIGH"
      }
    ];

    const alert = {
      alertId: "alt_103",
      target: "https://completely-unrelated-malware.org",
      title: "Suspicious Script Download",
      severity: "HIGH", // Same severity!
      priority: "P2_HIGH",
      evidence: []
    };

    const correlation = findCorrelatedIncident(alert, activeIncidents);
    assert.strictEqual(correlation.matchedIncident, null);
  });

  /* ================= 5. INCIDENT SERVICE & LIFECYCLE TESTS ================= */
  console.log("\n--- 5. Incident Service & Lifecycle Tests ---");

  await runAsyncTest("correlateAlertToIncident escalates critical alert into a new incident", async () => {
    const alert = {
      alertId: "alt_esc_001",
      target: "https://critical-threat-vector.com",
      title: "Critical Malware Dropper",
      severity: "CRITICAL",
      priority: "P1_CRITICAL",
      description: "Severe dropper active",
      evidence: []
    };

    const res = await correlateAlertToIncident(alert);
    assert.strictEqual(res.correlated, true);
    assert.strictEqual(res.action, "CREATED_NEW_INCIDENT");
    assert.ok(res.incident);
    assert.strictEqual(res.incident.severity, "CRITICAL");
    assert.ok(res.incident.associatedAlertIds.includes(alert.alertId));
  });

  await runAsyncTest("correlateAlertToIncident merges correlated alert and dynamically elevates incident", async () => {
    // Initial medium incident
    const initialInc = await createIncident({
      title: "Campaign on target-ecosystem.com",
      severity: "MEDIUM",
      priority: "P3_MEDIUM",
      affectedTargets: ["https://sub1.target-ecosystem.com"],
      attackVector: "SUSPICIOUS_OBFUSCATION"
    });

    // Incoming CRITICAL alert on same host root
    const alert = {
      alertId: "alt_merge_001",
      target: "https://sub1.target-ecosystem.com/exploit",
      title: "Confirmed Exploit Payload",
      severity: "CRITICAL",
      priority: "P1_CRITICAL"
    };

    const res = await correlateAlertToIncident(alert);
    assert.strictEqual(res.correlated, true);
    assert.strictEqual(res.action, "MERGED_INTO_EXISTING");
    assert.strictEqual(res.incident.incidentId, initialInc.incidentId);
    assert.strictEqual(res.incident.severity, "CRITICAL"); // Elevated!
    assert.strictEqual(res.incident.priority, "P1_CRITICAL"); // Elevated!
    assert.ok(res.incident.associatedAlertIds.includes(alert.alertId));
  });

  await runAsyncTest("addInvestigationNote adds timestamped entry to incident log", async () => {
    const { incidents } = await getIncidents({ limit: 1 });
    const targetInc = incidents[0];

    const updated = await addInvestigationNote(targetInc.incidentId, {
      text: "Firewall block applied to target host. No further beacons observed.",
      author: "SOC Lead Bob"
    });

    assert.ok(updated);
    const lastNote = updated.investigationNotes[updated.investigationNotes.length - 1];
    assert.strictEqual(lastNote.author, "SOC Lead Bob");
    assert.ok(lastNote.text.includes("Firewall block applied"));
  });

  await runAsyncTest("updateIncident updates status to RESOLVED and sets resolvedAt timestamp", async () => {
    const { incidents } = await getIncidents({ limit: 1 });
    const targetInc = incidents[0];

    const updated = await updateIncident(
      targetInc.incidentId,
      { status: "RESOLVED", rootCause: "Compromised DNS record redirected to malicious IP" },
      "SOC Lead Bob"
    );

    assert.strictEqual(updated.status, "RESOLVED");
    assert.ok(updated.resolvedAt);
    assert.strictEqual(updated.rootCause, "Compromised DNS record redirected to malicious IP");
  });

  /* ================= 6. REST API INTEGRATION TESTS (IN-PROCESS) ================= */
  console.log("\n--- 6. REST API Integration Tests (In-Process) ---");

  // Authenticate an ANALYST session for protected /api/soc/* routes (Phase 2.5 RBAC + CSRF)
  const { createUser, login, memoryUserStore, memorySessionStore } = require("../src/soc/auth");
  await memoryUserStore.deleteMany({});
  await memorySessionStore.deleteMany({});
  await createUser({
    username: "soc_phase2_analyst",
    email: "phase2.analyst@secunexis.test",
    password: "Phase2!TestPass999",
    role: "ANALYST"
  });
  const analystAuth = await login({ username: "soc_phase2_analyst", password: "Phase2!TestPass999" });
  const authHeaders = {
    cookie: `secunexis_sid=${analystAuth.rawToken}`,
    "x-csrf-token": analystAuth.csrfToken
  };

  await runAsyncTest("GET /api/soc/alerts responds with 200 and paginated list", async () => {
    const res = await invokeApp(app, { method: "GET", url: "/api/soc/alerts", headers: authHeaders });
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(Array.isArray(res.body.data));
    assert.ok(res.body.pagination);
  });

  await runAsyncTest("GET /api/soc/alerts/stats responds with 200 and breakdown", async () => {
    const res = await invokeApp(app, { method: "GET", url: "/api/soc/alerts/stats", headers: authHeaders });
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(typeof res.body.data.totalAlerts === "number");
    assert.ok(res.body.data.bySeverity);
  });

  await runAsyncTest("GET /api/soc/alerts/:id retrieves single alert", async () => {
    const { alerts } = await getAlerts({ limit: 1 });
    const alertId = alerts[0].alertId;

    const res = await invokeApp(app, { method: "GET", url: `/api/soc/alerts/${alertId}`, headers: authHeaders });
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.data.alertId, alertId);
  });

  await runAsyncTest("PATCH /api/soc/alerts/:id updates status and validates input", async () => {
    const { alerts } = await getAlerts({ limit: 1 });
    const alertId = alerts[0].alertId;

    // Bad status
    const badRes = await invokeApp(app, {
      method: "PATCH",
      url: `/api/soc/alerts/${alertId}`,
      headers: authHeaders,
      body: { status: "INVALID_STATUS" }
    });
    assert.strictEqual(badRes.statusCode, 400);

    // Valid status
    const goodRes = await invokeApp(app, {
      method: "PATCH",
      url: `/api/soc/alerts/${alertId}`,
      headers: authHeaders,
      body: { status: "ACKNOWLEDGED", note: "Alert acknowledged by analyst." }
    });
    assert.strictEqual(goodRes.statusCode, 200);
    assert.strictEqual(goodRes.body.data.status, "ACKNOWLEDGED");
  });

  await runAsyncTest("GET /api/soc/incidents responds with 200 and paginated list", async () => {
    const res = await invokeApp(app, { method: "GET", url: "/api/soc/incidents", headers: authHeaders });
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(Array.isArray(res.body.data));
    assert.ok(res.body.pagination);
  });

  await runAsyncTest("POST /api/soc/incidents establishes new incident manually", async () => {
    const res = await invokeApp(app, {
      method: "POST",
      url: "/api/soc/incidents",
      headers: authHeaders,
      body: {
        title: "Manual SOC Triage Incident: Spear Phishing Infiltration",
        severity: "HIGH",
        priority: "P2_HIGH",
        attackVector: "CREDENTIAL_HARVESTING",
        affectedTargets: ["https://portal-spoof.net"],
        assignedTo: "Analyst Charlie"
      }
    });

    assert.strictEqual(res.statusCode, 201);
    assert.strictEqual(res.body.success, true);
    assert.ok(res.body.data.incidentId.startsWith("inc_"));
    assert.strictEqual(res.body.data.assignedTo, "Analyst Charlie");
  });

  await runAsyncTest("POST /api/soc/incidents/:id/notes appends note and returns 201", async () => {
    const { incidents } = await getIncidents({ limit: 1 });
    const incId = incidents[0].incidentId;

    const res = await invokeApp(app, {
      method: "POST",
      url: `/api/soc/incidents/${incId}/notes`,
      headers: authHeaders,
      body: {
        text: "Domain registrar contact initiated for takedown."
      }
    });

    assert.strictEqual(res.statusCode, 201);
    assert.strictEqual(res.body.success, true);
    const notes = res.body.data.investigationNotes;
    assert.strictEqual(notes[notes.length - 1].text, "Domain registrar contact initiated for takedown.");
  });

  /* ================= 7. END-TO-END SCAN INTEGRATION PIPELINE ================= */
  console.log("\n--- 7. End-to-End Scan Pipeline Integration Tests ---");

  await runAsyncTest("Scanning a malicious payload automatically generates Alert and correlates Incident", async () => {
    const maliciousHtml = `
      <!DOCTYPE html>
      <html>
      <head><title>Urgent Bank Login</title></head>
      <body>
        <h2>Account Locked</h2>
        <!-- Hidden credential harvesting form to raw IP -->
        <form action="http://192.168.1.200/steal" method="POST" style="display:none;">
          <input type="text" name="username" />
          <input type="password" name="password" />
        </form>
      </body>
      </html>
    `;

    const res = await invokeApp(app, {
      method: "POST",
      url: "/scan",
      body: { html: maliciousHtml }
    });

    // 1. Core API contract strictly preserved
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.analysis);
    assert.ok(res.body.risk);
    assert.ok(res.body.virusTotal);
    assert.strictEqual(res.body.risk.verdict, "MALICIOUS");

    // 2. Alert generated automatically
    const alertRes = await getAlerts({ severity: "CRITICAL", limit: 1 });
    assert.ok(alertRes.alerts.length >= 1);
    const alert = alertRes.alerts[0];
    assert.strictEqual(alert.severity, "CRITICAL");
    assert.strictEqual(alert.status, "ESCALATED_TO_INCIDENT");

    // 3. Incident correlated automatically
    assert.ok(alert.incidentId);
    const inc = await getIncidentById(alert.incidentId);
    assert.ok(inc);
    assert.strictEqual(inc.attackVector, "CREDENTIAL_HARVESTING");
    assert.ok(inc.associatedAlertIds.includes(alert.alertId));
  });

  await runAsyncTest("Scanning a benign payload produces 0 alerts (Fatigue Prevention)", async () => {
    const cleanHtml = `
      <!DOCTYPE html>
      <html>
      <head><title>Clean Organization Portal</title></head>
      <body>
        <h1>Welcome to our Documentation</h1>
        <p>Browse our developer guides and open source SDKs.</p>
      </body>
      </html>
    `;

    const beforeAlerts = await getAlertStats();

    const res = await invokeApp(app, {
      method: "POST",
      url: "/scan",
      body: { html: cleanHtml }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.risk.verdict, "SAFE");

    const afterAlerts = await getAlertStats();
    assert.strictEqual(afterAlerts.totalAlerts, beforeAlerts.totalAlerts); // No new alert!
  });

  console.log("\n==========================================================================================");
  console.log(`  PHASE 2 TEST RESULTS: ${passed} PASSED | ${failed} FAILED`);
  console.log("==========================================================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runAllTests().catch(err => {
  console.error("Test execution exception:", err);
  process.exit(1);
});
