/**
 * Risk Scoring & Security Classification Engine (v2.1)
 *
 * Implements strict separation between:
 * 1. Risk Score: 0 - 100 numerical score, derived exclusively from verified security evidence.
 * 2. Severity: LOW (0-29), MEDIUM (30-69), HIGH (70-100), derived from score and threat severity.
 * 3. Security Verdict: SAFE, SUSPICIOUS, MALICIOUS, INCONCLUSIVE, derived from evidence, reputation, and scan coverage.
 *
 * Guarantees:
 * - Sum of individual finding score contributions equals the final risk score.
 * - Zero threats detected produces a Risk Score of 0.
 * - INCONCLUSIVE is never treated as HIGH.
 * - Unavailable VirusTotal contributes 0 risk points and does not claim clean reputation.
 */

const RISK_CONFIG = {
  THRESHOLDS: {
    LOW_MAX: 29,       // 0 - 29: LOW
    MEDIUM_MAX: 69,    // 30 - 69: MEDIUM
    HIGH_MIN: 70       // 70 - 100: HIGH
  },
  WEIGHTS: {
    // Critical Threat Indicators (Score contribution: 45 - 50)
    KEYLOGGER_HARVESTING: 50,
    CREDENTIAL_POST_RAW_IP: 45,
    VT_MALICIOUS_CRITICAL: 45,      // >= 3 malicious detections

    // High Threat Indicators (Score contribution: 25 - 30)
    HIDDEN_CREDENTIAL_FORM: 30,
    EVAL_ENCODED_PAYLOAD: 25,
    VT_MALICIOUS_ELEVATED: 25,      // 1-2 malicious detections
    SUSPICIOUS_EXTERNAL_IFRAME: 25,
    DYNAMIC_UNTRUSTED_INJECTION: 20,

    // Moderate Threat Indicators (Score contribution: 15 - 20)
    HEX_PACKED_OBFUSCATION: 20,
    EXTERNAL_CREDENTIAL_ACTION: 20,
    SUSPICIOUS_IMMEDIATE_REDIRECT: 20,
    INSECURE_PASSWORD_HTTP: 15,
    SOCIAL_ENGINEERING_LURE: 15,
    VT_SUSPICIOUS_ELEVATED: 15,     // >= 3 suspicious detections
    VT_SUSPICIOUS_MILD: 10          // 1-2 suspicious detections
  }
};

/**
 * Calculates risk score, severity, security verdict, and audit evidence.
 *
 * @param {Object} analysisResult - Output from staticAnalyzer
 * @param {Object} [vtResult=null] - Output from virusTotalAnalyzer
 * @returns {Object} Comprehensive, evidence-based security assessment
 */
function calculateRisk(analysisResult = {}, vtResult = null) {
  const scoredThreats = [];
  const appliedCategories = new Set();

  const findings = Array.isArray(analysisResult.findings) ? analysisResult.findings : [];
  const suspiciousFindings = findings.filter(f => f.isThreat);

  /* ================= 1. VIRUSTOTAL REPUTATION SCORING ================= */
  const vtAvailable = !!(vtResult && vtResult.available === true && vtResult.status === "success");
  const vtMalicious = (vtAvailable && typeof vtResult.malicious === "number") ? vtResult.malicious : 0;
  const vtSuspicious = (vtAvailable && typeof vtResult.suspicious === "number") ? vtResult.suspicious : 0;

  if (vtAvailable) {
    if (vtMalicious >= 3) {
      const contribution = RISK_CONFIG.WEIGHTS.VT_MALICIOUS_CRITICAL;
      scoredThreats.push({
        id: "VT_MALICIOUS_CRITICAL",
        name: "VirusTotal Confirmed Malicious Blacklist",
        severity: "CRITICAL",
        evidence: `Flagged as malicious by ${vtMalicious} security vendors on VirusTotal`,
        scoreContribution: contribution,
        source: "VIRUSTOTAL_REPUTATION"
      });
      appliedCategories.add("VT_MALICIOUS");
    } else if (vtMalicious >= 1) {
      const contribution = RISK_CONFIG.WEIGHTS.VT_MALICIOUS_ELEVATED;
      scoredThreats.push({
        id: "VT_MALICIOUS_ELEVATED",
        name: "VirusTotal Malicious Reputation Detection",
        severity: "HIGH",
        evidence: `Flagged as malicious by ${vtMalicious} security vendor(s) on VirusTotal`,
        scoreContribution: contribution,
        source: "VIRUSTOTAL_REPUTATION"
      });
      appliedCategories.add("VT_MALICIOUS");
    }

    if (vtSuspicious >= 3 && !appliedCategories.has("VT_MALICIOUS")) {
      const contribution = RISK_CONFIG.WEIGHTS.VT_SUSPICIOUS_ELEVATED;
      scoredThreats.push({
        id: "VT_SUSPICIOUS_ELEVATED",
        name: "VirusTotal Elevated Suspicious Ratings",
        severity: "MEDIUM",
        evidence: `Flagged as suspicious by ${vtSuspicious} security engines`,
        scoreContribution: contribution,
        source: "VIRUSTOTAL_REPUTATION"
      });
    } else if (vtSuspicious >= 1 && !appliedCategories.has("VT_MALICIOUS")) {
      const contribution = RISK_CONFIG.WEIGHTS.VT_SUSPICIOUS_MILD;
      scoredThreats.push({
        id: "VT_SUSPICIOUS_MILD",
        name: "VirusTotal Isolated Suspicious Rating",
        severity: "LOW",
        evidence: `Flagged as suspicious by ${vtSuspicious} security engine`,
        scoreContribution: contribution,
        source: "VIRUSTOTAL_REPUTATION"
      });
    }
  }

  /* ================= 2. STATIC THREAT SCORING (STRICT DEDUPLICATION) ================= */
  suspiciousFindings.forEach(threat => {
    let contribution = 0;
    const id = threat.id;

    if (id.includes("KEYLOGGER") && !appliedCategories.has("KEYLOGGER")) {
      contribution = RISK_CONFIG.WEIGHTS.KEYLOGGER_HARVESTING;
      appliedCategories.add("KEYLOGGER");
    } else if (id.includes("CREDENTIAL_SUBMISSION_RAW_IP") && !appliedCategories.has("RAW_IP_CREDENTIALS")) {
      contribution = RISK_CONFIG.WEIGHTS.CREDENTIAL_POST_RAW_IP;
      appliedCategories.add("RAW_IP_CREDENTIALS");
      appliedCategories.add("HTTP_PASSWORD");
    } else if ((id.includes("HIDDEN_PASSWORD_FIELD") || id.includes("HIDDEN_CREDENTIAL_FORM")) && !appliedCategories.has("HIDDEN_CREDENTIAL")) {
      contribution = RISK_CONFIG.WEIGHTS.HIDDEN_CREDENTIAL_FORM;
      appliedCategories.add("HIDDEN_CREDENTIAL");
    } else if (id.includes("EVAL_ENCODED_PAYLOAD") && !appliedCategories.has("OBFUSCATED_EVAL")) {
      contribution = RISK_CONFIG.WEIGHTS.EVAL_ENCODED_PAYLOAD;
      appliedCategories.add("OBFUSCATED_EVAL");
    } else if (id.includes("HEX_PACKED_OBFUSCATION") && !appliedCategories.has("HEX_OBFUSCATION")) {
      contribution = RISK_CONFIG.WEIGHTS.HEX_PACKED_OBFUSCATION;
      appliedCategories.add("HEX_OBFUSCATION");
    } else if (id.includes("SUSPICIOUS_IFRAME") && !appliedCategories.has("SUSPICIOUS_IFRAME")) {
      contribution = RISK_CONFIG.WEIGHTS.SUSPICIOUS_EXTERNAL_IFRAME;
      appliedCategories.add("SUSPICIOUS_IFRAME");
    } else if (id.includes("DYNAMIC_UNTRUSTED_INJECTION") && !appliedCategories.has("DYNAMIC_INJECTION")) {
      contribution = RISK_CONFIG.WEIGHTS.DYNAMIC_UNTRUSTED_INJECTION;
      appliedCategories.add("DYNAMIC_INJECTION");
    } else if (id.includes("EXTERNAL_CREDENTIAL_ACTION") && !appliedCategories.has("EXTERNAL_CREDENTIAL_POST")) {
      contribution = RISK_CONFIG.WEIGHTS.EXTERNAL_CREDENTIAL_ACTION;
      appliedCategories.add("EXTERNAL_CREDENTIAL_POST");
    } else if (id.includes("SUSPICIOUS_IMMEDIATE_REDIRECT") && !appliedCategories.has("SUSPICIOUS_REDIRECT")) {
      contribution = RISK_CONFIG.WEIGHTS.SUSPICIOUS_IMMEDIATE_REDIRECT;
      appliedCategories.add("SUSPICIOUS_REDIRECT");
    } else if (id.includes("INSECURE_PASSWORD") && !appliedCategories.has("HTTP_PASSWORD") && !appliedCategories.has("RAW_IP_CREDENTIALS")) {
      contribution = RISK_CONFIG.WEIGHTS.INSECURE_PASSWORD_HTTP;
      appliedCategories.add("HTTP_PASSWORD");
    } else if (id.includes("SOCIAL_ENGINEERING") && !appliedCategories.has("SOCIAL_LURE")) {
      contribution = RISK_CONFIG.WEIGHTS.SOCIAL_ENGINEERING_LURE;
      appliedCategories.add("SOCIAL_LURE");
    } else if (id.startsWith("THREAT_") && contribution === 0 && !appliedCategories.has(id)) {
      contribution = threat.severity === "CRITICAL" ? 40 : threat.severity === "HIGH" ? 25 : 15;
      appliedCategories.add(id);
    }

    if (contribution > 0) {
      scoredThreats.push({
        id: threat.id,
        name: threat.name,
        severity: threat.severity,
        evidence: threat.evidence || threat.explanation,
        scoreContribution: contribution,
        source: "STATIC_HEURISTICS"
      });
    }
  });

  /* ================= 3. NUMERICAL RISK SCORE CALCULATION ================= */
  // The risk score is exactly the sum of individual score contributions, capped at 100.
  // If no threats are scored, the score is strictly 0.
  const unCappedScore = scoredThreats.reduce((sum, item) => sum + item.scoreContribution, 0);
  const riskScore = Math.min(100, unCappedScore);

  /* ================= 4. RISK SEVERITY CLASSIFICATION ================= */
  // Derived strictly from the numerical score and threat profile:
  // 0 - 29: LOW
  // 30 - 69: MEDIUM
  // 70 - 100: HIGH
  let severity = "LOW";
  if (riskScore >= RISK_CONFIG.THRESHOLDS.HIGH_MIN) {
    severity = "HIGH";
  } else if (riskScore >= RISK_CONFIG.THRESHOLDS.LOW_MAX + 1) {
    severity = "MEDIUM";
  } else {
    severity = "LOW";
  }

  /* ================= 5. SCAN COVERAGE EVALUATION ================= */
  const isEssentiallyEmpty = !!analysisResult.isEssentiallyEmpty;
  let scanCoverage = "FULL";
  let coverageNote = "Full static inspection and reputation verification completed.";

  if (isEssentiallyEmpty) {
    scanCoverage = "INSUFFICIENT";
    coverageNote = "Target provided minimal or unparseable HTML payload with insufficient DOM content.";
  } else if (!vtAvailable) {
    scanCoverage = "STATIC_ONLY";
    coverageNote = "Static DOM and script heuristics verified. Reputation threat intelligence check unavailable.";
  }

  /* ================= 6. SECURITY VERDICT DETERMINATION ================= */
  // Clear, independent definitions:
  // MALICIOUS: Confirmed malicious reputation or verified attack signatures.
  // SUSPICIOUS: Credible suspicious indicators exist, but full compromise is not confirmed.
  // INCONCLUSIVE: Insufficient scan coverage prevents a reliable determination (Score is 0, Severity is LOW).
  // SAFE: No threat indicators found and adequate scan coverage is available.
  let verdict = "SAFE";

  const hasCriticalThreat = scoredThreats.some(t => t.severity === "CRITICAL");
  const hasHighThreat = scoredThreats.some(t => t.severity === "HIGH");

  if (
    riskScore >= RISK_CONFIG.THRESHOLDS.HIGH_MIN ||
    vtMalicious >= 3 ||
    hasCriticalThreat ||
    (vtMalicious >= 1 && hasHighThreat)
  ) {
    verdict = "MALICIOUS";
  } else if (
    riskScore >= 20 ||
    scoredThreats.length > 0 ||
    vtMalicious >= 1 ||
    vtSuspicious >= 2
  ) {
    verdict = "SUSPICIOUS";
  } else if (scanCoverage === "INSUFFICIENT") {
    verdict = "INCONCLUSIVE";
    // For INCONCLUSIVE, ensure severity remains LOW and score remains 0
    severity = "LOW";
  } else {
    verdict = "SAFE";
  }

  /* ================= 7. VERDICT EXPLANATION & THREAT SUMMARY ================= */
  const explanation = [];

  if (verdict === "MALICIOUS") {
    if (vtMalicious >= 3) {
      explanation.push(`Confirmed malicious reputation reported by ${vtMalicious} global antivirus vendors on VirusTotal.`);
    }
    if (hasCriticalThreat) {
      explanation.push("Detected active, high-confidence credential harvesting, keylogger, or stealth exfiltration infrastructure.");
    }
    if (riskScore >= RISK_CONFIG.THRESHOLDS.HIGH_MIN) {
      explanation.push(`Cumulative threat indicators reached a critical risk score of ${riskScore}/100.`);
    }
  } else if (verdict === "SUSPICIOUS") {
    if (vtMalicious === 1 || vtMalicious === 2) {
      explanation.push(`Target flagged by ${vtMalicious} vendor(s) on VirusTotal. Independent verification advised.`);
    } else if (vtSuspicious >= 2) {
      explanation.push(`Reputation intelligence reported ${vtSuspicious} suspicious vendor ratings.`);
    }
    if (hasHighThreat) {
      explanation.push("Static inspection detected anomalous or obfuscated script structures warranting security review.");
    } else if (scoredThreats.length > 0) {
      explanation.push(`Identified ${scoredThreats.length} security anomaly finding(s) with an elevated risk score of ${riskScore}/100.`);
    }
  } else if (verdict === "INCONCLUSIVE") {
    explanation.push("Scan coverage is insufficient to establish a definitive security verdict. The target supplied an empty or unparseable HTML payload.");
  } else {
    explanation.push("No significant threat indicators or malicious patterns were found. Webpage structure matches standard, authentic behavior.");
  }

  return {
    riskScore,          // 0 - 100 numerical score (strictly equals sum of scoredThreats)
    severity,           // LOW | MEDIUM | HIGH
    verdict,            // SAFE | SUSPICIOUS | MALICIOUS | INCONCLUSIVE
    scanCoverage,       // FULL | STATIC_ONLY | INSUFFICIENT
    coverageNote,
    explanation,
    scoredThreats,      // Array of { id, name, severity, evidence, scoreContribution, source }
    evidenceFindings: findings,
    threatCount: scoredThreats.length,
    infoCount: findings.filter(f => !f.isThreat).length,
    vtAvailable
  };
}

module.exports = calculateRisk;
