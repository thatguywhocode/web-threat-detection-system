/**
 * SecuNexis — SOC Alert Rules Engine (Phase 2)
 *
 * Implements deterministic, enterprise-grade alert evaluation:
 * - Maps normalized SecurityEvent telemetry to actionable SecurityAlert candidates
 * - Prevents alert fatigue: suppresses safe scans and inconclusive outcomes without threats
 * - Strict severity and priority classification (P1_CRITICAL -> P4_LOW)
 * - Identifies primary threat vectors and detection sources
 */

const url = require("url");

/**
 * Extracts a clean hostname or truncated target descriptor for titles
 * @param {string} target 
 * @returns {string}
 */
function extractTargetHost(target) {
  if (!target || typeof target !== "string") return "Target";
  try {
    if (target.startsWith("http://") || target.startsWith("https://")) {
      const parsed = new url.URL(target);
      return parsed.hostname || target;
    }
    return target.slice(0, 40);
  } catch {
    return target.slice(0, 40);
  }
}

/**
 * Evaluates whether a SecurityEvent should trigger an actionable SecurityAlert
 * @param {object} event - Normalized SecurityEvent document or plain object
 * @returns {{ shouldAlert: boolean, alertData: object|null, reason: string }}
 */
function evaluateAlertRules(event) {
  if (!event) {
    return { shouldAlert: false, alertData: null, reason: "No event provided" };
  }

  const verdict = (event.verdict || "INCONCLUSIVE").toUpperCase();
  const riskScore = typeof event.riskScore === "number" ? event.riskScore : 0;
  const rawFindings = Array.isArray(event.detectionEvidence)
    ? event.detectionEvidence
    : (Array.isArray(event.findings) ? event.findings : []);
  const threatFindings = rawFindings.filter(f => f.isThreat || f.severity === "CRITICAL" || f.severity === "HIGH");
  const threatCount = typeof event.threatCount === "number" ? event.threatCount : threatFindings.length;
  
  const vt = event.virusTotalSummary || event.virusTotal || {};
  const vtMalicious = vt.malicious || 0;
  const vtSuspicious = vt.suspicious || 0;
  const vtThreats = vtMalicious + vtSuspicious;

  // 1. Fatigue Prevention: Safe scans and inconclusive scans with 0 threats produce NO alert
  if (verdict === "SAFE" && threatCount === 0 && vtMalicious === 0 && riskScore < 25) {
    return {
      shouldAlert: false,
      alertData: null,
      reason: "Target is classified as SAFE with zero threat findings. Suppressing alert."
    };
  }

  if (verdict === "INCONCLUSIVE" && threatCount === 0 && vtMalicious === 0 && riskScore < 25) {
    return {
      shouldAlert: false,
      alertData: null,
      reason: "Scan is INCONCLUSIVE with zero threat findings. Suppressing alert."
    };
  }

  // 2. Alert Trigger Criteria:
  // Must be MALICIOUS, or SUSPICIOUS with threats/risk >= 25, or have positive threat findings / VT positives
  const hasSubstantiveRisk = verdict === "MALICIOUS" ||
    verdict === "SUSPICIOUS" ||
    riskScore >= 25 ||
    threatCount > 0 ||
    vtMalicious > 0;

  if (!hasSubstantiveRisk) {
    return {
      shouldAlert: false,
      alertData: null,
      reason: "Risk indicators do not meet the minimum alert threshold."
    };
  }

  // 3. Determine Severity & Priority
  let severity = "MEDIUM";
  let priority = "P3_MEDIUM";

  const hasCriticalFinding = threatFindings.some(f => f.severity === "CRITICAL" || (f.scoreContribution || 0) >= 30);
  const hasHighFinding = threatFindings.some(f => f.severity === "HIGH" || (f.scoreContribution || 0) >= 15);

  if (verdict === "MALICIOUS" || riskScore >= 70 || vtMalicious >= 3 || hasCriticalFinding) {
    severity = "CRITICAL";
    priority = "P1_CRITICAL";
  } else if (riskScore >= 45 || hasHighFinding || vtMalicious >= 1 || vtSuspicious >= 3 || event.severity === "HIGH") {
    severity = "HIGH";
    priority = "P2_HIGH";
  } else if (riskScore >= 20 || threatCount > 0 || vtSuspicious >= 1 || event.severity === "MEDIUM") {
    severity = "MEDIUM";
    priority = "P3_MEDIUM";
  } else {
    severity = "LOW";
    priority = "P4_LOW";
  }

  // 4. Determine Detection Source
  let detectionSource = "STATIC_HEURISTICS";
  if (vtMalicious > 0 || vtSuspicious > 0) {
    if (threatFindings.length > 0) {
      detectionSource = "HYBRID (STATIC + VIRUSTOTAL)";
    } else {
      detectionSource = "VIRUSTOTAL_THREAT_INTEL";
    }
  } else if (threatFindings.length > 0) {
    detectionSource = "STATIC_HEURISTICS";
  } else {
    detectionSource = "ANOMALY_HEURISTICS";
  }

  // 5. Construct Title & Description
  const targetHost = extractTargetHost(event.target);
  let title = "";
  let description = "";

  // Sort threat findings by severity / score contribution to find primary driver
  const sortedThreats = [...threatFindings].sort((a, b) => {
    const scoreA = (a.scoreContribution || 0);
    const scoreB = (b.scoreContribution || 0);
    return scoreB - scoreA;
  });

  const primaryThreat = sortedThreats[0];

  if (severity === "CRITICAL") {
    if (vtMalicious >= 3) {
      title = `Critical Malicious Host Confirmed: ${targetHost} (${vtMalicious} Security Engines)`;
      description = `Target ${event.target} confirmed malicious by ${vtMalicious} threat intelligence engines. Immediate SOC containment recommended.`;
    } else if (primaryThreat) {
      title = `Critical Threat Detected: ${primaryThreat.name} on ${targetHost}`;
      description = primaryThreat.explanation || `Severe threat indicators detected on ${event.target}. Immediate analyst triage required.`;
    } else {
      title = `Critical Security Risk: High Threat Score (${riskScore}/100) on ${targetHost}`;
      description = `Target ${event.target} reached a critical risk threshold with compound malicious indicators.`;
    }
  } else if (severity === "HIGH") {
    if (primaryThreat) {
      title = `High Risk: ${primaryThreat.name} on ${targetHost}`;
      description = primaryThreat.explanation || `Suspicious activity and high-confidence threat signals detected on ${event.target}.`;
    } else if (vtMalicious > 0) {
      title = `Threat Intelligence Warning: ${targetHost} flagged by VirusTotal`;
      description = `Target ${event.target} was flagged as malicious or suspicious by reputation engines.`;
    } else {
      title = `Suspicious Activity Detected on ${targetHost} (Score: ${riskScore}/100)`;
      description = `Automated analysis detected elevated anomalies requiring security review.`;
    }
  } else if (severity === "MEDIUM") {
    if (primaryThreat) {
      title = `Suspicious Finding: ${primaryThreat.name} on ${targetHost}`;
      description = primaryThreat.explanation || `Medium severity security anomaly detected on ${event.target}.`;
    } else {
      title = `Elevated Risk Activity on ${targetHost}`;
      description = `Target exhibited atypical attributes during static inspection.`;
    }
  } else {
    title = `Low Risk Security Alert: Informational Findings on ${targetHost}`;
    description = `Minor security findings recorded for target ${event.target}.`;
  }

  // 6. Format Evidence Items
  const evidenceList = threatFindings.map(f => ({
    id: f.id || "threat_" + Math.random().toString(36).substring(2, 8),
    name: f.name || "Detected Threat",
    category: f.category || "General Threat",
    severity: f.severity || severity,
    scoreContribution: f.scoreContribution || 0,
    explanation: f.explanation || "",
    evidence: f.evidence || ""
  }));

  // Append VirusTotal evidence if applicable
  if (vtMalicious > 0 || vtSuspicious > 0) {
    evidenceList.push({
      id: "vt_threat_intel",
      name: "VirusTotal Threat Intelligence",
      category: "External Threat Intelligence",
      severity: vtMalicious >= 3 ? "CRITICAL" : (vtMalicious >= 1 ? "HIGH" : "MEDIUM"),
      scoreContribution: Math.min(vtMalicious * 10 + vtSuspicious * 5, 40),
      explanation: `${vtMalicious} engines flagged as malicious, ${vtSuspicious} engines flagged as suspicious.`,
      evidence: vt.message || `Engines detected: ${vtMalicious} malicious / ${vt.totalEngines || 0} total.`
    });
  }

  const alertData = {
    eventId: event.eventId,
    scanReference: event.scanReference,
    target: event.target,
    targetType: event.targetType || "URL",
    title,
    description,
    severity,
    priority,
    status: "NEW",
    detectionSource,
    verdict,
    riskScore,
    threatCount: Math.max(threatCount, evidenceList.length),
    evidence: evidenceList
  };

  return {
    shouldAlert: true,
    alertData,
    reason: `Event qualified for alert with severity ${severity} (${priority}).`
  };
}

module.exports = {
  extractTargetHost,
  evaluateAlertRules
};
