/**
 * SentinelCore — SOC Scan Result Adapter (v1.0)
 *
 * Consumes completed scan results without modifying the core detection engine:
 * - Deterministically derives scanReference for idempotent event ingestion
 * - Normalizes detection findings into standard enterprise taxonomy categories
 * - Sanitizes targets and payloads to avoid logging sensitive credentials or executing scripts
 * - Explicitly handles incomplete or partial scan payloads
 */

const crypto = require("crypto");

/**
 * Standard enterprise taxonomy categories matching SOC triage conventions
 */
function categorizeFinding(finding) {
  const id = String(finding?.id || "").toUpperCase();
  const name = String(finding?.name || "").toUpperCase();

  if (id.includes("KEYLOGGER") || name.includes("KEYSTROKE") || id.includes("KEY_LISTENER")) {
    return "Keylogger indicators";
  }
  if (id.includes("EXTERNAL_CREDENTIAL_ACTION") || id.includes("CROSS_DOMAIN")) {
    return "Cross-domain form submissions";
  }
  if (
    id.includes("HIDDEN_CREDENTIAL") ||
    id.includes("HIDDEN_PASSWORD") ||
    id.includes("CREDENTIAL_SUBMISSION_RAW_IP") ||
    id.includes("INSECURE_PASSWORD") ||
    id.includes("SOCIAL_ENGINEERING") ||
    name.includes("CREDENTIAL") ||
    name.includes("HARVEST")
  ) {
    return "Credential harvesting";
  }
  if (
    id.includes("EVAL_ENCODED") ||
    id.includes("FUNCTION_CONSTRUCTOR") ||
    id.includes("HEX_PACKED") ||
    name.includes("OBFUSCAT")
  ) {
    return "Obfuscated JavaScript";
  }
  if (
    id.includes("DYNAMIC_UNTRUSTED_SCRIPT") ||
    id.includes("IMMEDIATE_REDIRECT") ||
    id.includes("META_REFRESH") ||
    id.includes("INFO_SCRIPT") ||
    name.includes("SCRIPT INJECTION")
  ) {
    return "Suspicious scripts";
  }
  if (id.includes("IFRAME") || name.includes("IFRAME")) {
    return "Suspicious iframes";
  }
  return "Other detected anomalies";
}

/**
 * Strips credentials, tokens, and sensitive authentication fields from raw payload previews
 */
function sanitizeRawInputPreview(rawInput = "") {
  if (typeof rawInput !== "string" || !rawInput.trim()) {
    return "";
  }

  let sanitized = rawInput
    .replace(/(password|passwd|pwd|token|secret|creditcard|api[_-]?key)\s*[:=]\s*["']?[^"'\s&>]+/gi, "$1=[REDACTED]")
    .replace(/<input[^>]+type=["']password["'][^>]*>/gi, "<input type=\"password\" value=\"[REDACTED]\">")
    .replace(/(name=["']?(?:password|passwd|pwd|token|secret|creditcard|api[_-]?key)["']?[^>]*?value=)(["']?)[^"'\s>]+(\2)/gi, "$1$2[REDACTED]$2")
    .replace(/(value=)(["']?)[^"'\s>]+(\2)([^>]*?name=["']?(?:password|passwd|pwd|token|secret|creditcard|api[_-]?key)["']?)/gi, "$1$2[REDACTED]$2$4");

  if (sanitized.length > 500) {
    sanitized = sanitized.slice(0, 500) + "... [truncated]";
  }

  return sanitized;
}

/**
 * Generates a deterministic SHA-256 scan reference for idempotent event deduplication
 */
function generateScanReference(scanInput = {}, scanResult = {}) {
  const target = String(scanInput?.target || scanInput?.url || "").trim().toLowerCase();
  const rawHtml = typeof scanInput?.html === "string" ? scanInput.html.trim() : "";
  const htmlHash = rawHtml ? crypto.createHash("sha256").update(rawHtml).digest("hex") : "";

  const verdict = String(scanResult?.risk?.verdict || "INCONCLUSIVE").toUpperCase();
  const riskScore = Number(scanResult?.risk?.riskScore || 0);
  const scoredIds = Array.isArray(scanResult?.risk?.scoredThreats)
    ? scanResult.risk.scoredThreats.map(t => String(t.id)).sort().join(",")
    : "";

  const seed = `${target}|${htmlHash}|${verdict}|${riskScore}|${scoredIds}`;
  return crypto.createHash("sha256").update(seed).digest("hex");
}

/**
 * Normalizes completed scan outputs into a standard SecurityEvent document
 *
 * @param {Object} scanInput - { target, url, html }
 * @param {Object} scanResult - { analysis, risk, virusTotal }
 * @param {Object} [options={}] - Additional metadata (clientIp, userAgent)
 * @returns {Object} Normalized SecurityEvent object
 */
function adaptScanResult(scanInput = {}, scanResult = {}, options = {}) {
  const isUrl = Boolean(scanInput?.url || (typeof scanInput?.target === "string" && /^https?:\/\//i.test(scanInput.target)));
  const targetLabel = scanInput?.url || scanInput?.target || (scanInput?.html ? "HTML Source Snippet" : "Unknown Target");

  const risk = scanResult?.risk || {};
  const analysis = scanResult?.analysis || {};
  const vt = scanResult?.virusTotal || {};

  // 1. Core security assessment values
  const verdictRaw = String(risk.verdict || "INCONCLUSIVE").toUpperCase();
  const verdict = ["SAFE", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE"].includes(verdictRaw)
    ? verdictRaw
    : "INCONCLUSIVE";

  const severityRaw = String(risk.severity || "LOW").toUpperCase();
  const severity = ["LOW", "MEDIUM", "HIGH"].includes(severityRaw)
    ? severityRaw
    : "LOW";

  const riskScore = typeof risk.riskScore === "number" ? Math.max(0, Math.min(100, Math.round(risk.riskScore))) : 0;
  const scanCoverage = ["FULL", "STATIC_ONLY", "INSUFFICIENT"].includes(risk.scanCoverage)
    ? risk.scanCoverage
    : (analysis.isEssentiallyEmpty ? "INSUFFICIENT" : (vt.available ? "FULL" : "STATIC_ONLY"));

  // 2. Score contribution map from scoredThreats
  const scoreMap = new Map();
  if (Array.isArray(risk.scoredThreats)) {
    risk.scoredThreats.forEach(t => {
      if (t?.id) scoreMap.set(t.id, Number(t.scoreContribution || 0));
    });
  }

  // 3. Evidence findings normalization
  const rawFindings = Array.isArray(risk.evidenceFindings) && risk.evidenceFindings.length > 0
    ? risk.evidenceFindings
    : (Array.isArray(analysis.findings) ? analysis.findings : []);

  const seenIds = new Set();
  const normalizedEvidence = [];

  rawFindings.forEach(f => {
    if (!f || !f.id) return;
    seenIds.add(f.id);
    const score = f.isThreat ? (scoreMap.get(f.id) || 0) : 0;

    normalizedEvidence.push({
      id: String(f.id),
      name: String(f.name || "Security Observation"),
      category: categorizeFinding(f),
      severity: String(f.severity || "INFO").toUpperCase(),
      source: String(f.source || "STATIC_HEURISTICS"),
      scoreContribution: score,
      explanation: String(f.explanation || ""),
      evidence: String(f.evidence || ""),
      whyItMatters: String(f.whyItMatters || ""),
      recommendedAction: String(f.recommendedAction || ""),
      isThreat: Boolean(f.isThreat)
    });
  });

  // Include any scoredThreats not present in findings
  if (Array.isArray(risk.scoredThreats)) {
    risk.scoredThreats.forEach(st => {
      if (!st || !st.id || seenIds.has(st.id)) return;
      seenIds.add(st.id);
      normalizedEvidence.push({
        id: String(st.id),
        name: String(st.name || "Threat Signal"),
        category: categorizeFinding(st),
        severity: String(st.severity || "HIGH").toUpperCase(),
        source: String(st.source || "VIRUSTOTAL_REPUTATION"),
        scoreContribution: Number(st.scoreContribution || 0),
        explanation: String(st.evidence || st.name || ""),
        evidence: String(st.evidence || ""),
        whyItMatters: "External blacklist threat score contribution.",
        recommendedAction: "Investigate and block target host.",
        isThreat: true
      });
    });
  }

  // 4. VirusTotal summary normalization
  const vtMal = typeof vt.malicious === "number" ? vt.malicious : 0;
  const vtSusp = typeof vt.suspicious === "number" ? vt.suspicious : 0;
  const vtHarm = typeof vt.harmless === "number" ? vt.harmless : 0;
  const vtUndet = typeof vt.undetected === "number" ? vt.undetected : 0;

  const virusTotalSummary = {
    available: Boolean(vt.available && vt.status === "success"),
    status: String(vt.status || "unavailable"),
    malicious: vtMal,
    suspicious: vtSusp,
    harmless: vtHarm,
    undetected: vtUndet,
    totalEngines: vtMal + vtSusp + vtHarm + vtUndet,
    reputation: typeof vt.reputation === "number" ? vt.reputation : 0,
    message: String(vt.message || "")
  };

  // 5. Static DOM metrics normalization
  const metrics = analysis.metrics || {};
  const staticMetrics = {
    totalScripts: typeof analysis.totalScripts === "number" ? analysis.totalScripts : 0,
    totalIframes: typeof analysis.totalIframes === "number" ? analysis.totalIframes : 0,
    hiddenElementsDetected: Boolean(analysis.hiddenElementsDetected),
    suspiciousHiddenCount: Number(metrics.suspiciousHiddenCount || 0),
    suspiciousIframesCount: Number(metrics.suspiciousIframesCount || 0),
    jsThreatsCount: Number(metrics.jsThreatsCount || 0),
    phishingThreatsCount: Number(metrics.phishingThreatsCount || 0),
    rawHtmlLength: Number(metrics.rawHtmlLength || (scanInput?.html ? scanInput.html.length : 0))
  };

  // 6. Remediation summary
  const remediation = {
    priority: verdict === "MALICIOUS" ? "IMMEDIATE CONTAINMENT" : verdict === "SUSPICIOUS" ? "ANALYST TRIAGE" : "BASELINE",
    summary: verdict === "MALICIOUS"
      ? "Confirmed threat signals identified. Block destination and isolate compromised endpoints."
      : verdict === "SUSPICIOUS"
        ? "Anomalous heuristics detected. Analyst verification advised before allowlisting."
        : "Standard security posture. No containment required.",
    steps: normalizedEvidence.filter(e => e.isThreat && e.recommendedAction).map(e => e.recommendedAction)
  };

  const threatCount = typeof risk.threatCount === "number"
    ? risk.threatCount
    : normalizedEvidence.filter(e => e.isThreat).length;
  const infoCount = typeof risk.infoCount === "number"
    ? risk.infoCount
    : normalizedEvidence.filter(e => !e.isThreat).length;

  return {
    eventId: "sec_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16),
    scanReference: generateScanReference(scanInput, scanResult),
    target: targetLabel,
    targetType: isUrl ? "URL" : "HTML",
    verdict,
    severity,
    riskScore,
    scanCoverage,
    timestamp: options.timestamp ? new Date(options.timestamp) : new Date(),
    threatCount,
    infoCount,
    detectionEvidence: normalizedEvidence,
    virusTotal: virusTotalSummary,
    staticMetrics,
    remediation,
    rawInputPreview: sanitizeRawInputPreview(scanInput?.html || scanInput?.url || ""),
    metadata: {
      source: options.source || (isUrl ? "URL_SCANNER" : "HTML_SCANNER"),
      clientIp: options.clientIp || "127.0.0.1",
      userAgent: options.userAgent || ""
    }
  };
}

module.exports = {
  adaptScanResult,
  generateScanReference,
  categorizeFinding,
  sanitizeRawInputPreview
};
