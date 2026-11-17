/**
 * SecuNexis — SOC Incident Correlation Engine (Phase 2)
 *
 * Implements defensible, deterministic incident correlation:
 * - Alerts are correlated based on concrete relationships (host matching, exfiltration endpoints, campaign vectors).
 * - NEVER groups merely by severity similarity.
 * - Dynamically escalates incident severity/priority when a more severe alert correlates.
 */

const url = require("url");

const SEVERITY_RANKS = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4
};

const PRIORITY_RANKS = {
  P4_LOW: 1,
  P3_MEDIUM: 2,
  P2_HIGH: 3,
  P1_CRITICAL: 4
};

/**
 * Normalizes host from a target string
 * @param {string} target 
 * @returns {string}
 */
function extractHostname(target) {
  if (!target || typeof target !== "string") return "";
  try {
    if (target.startsWith("http://") || target.startsWith("https://")) {
      const parsed = new url.URL(target);
      return (parsed.hostname || target).toLowerCase();
    }
    return target.toLowerCase();
  } catch {
    return target.toLowerCase();
  }
}

/**
 * Derives root domain for campaign correlation (e.g., "auth.example.com" -> "example.com")
 * @param {string} hostname 
 * @returns {string}
 */
function extractRootDomain(hostname) {
  if (!hostname) return "";
  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join(".");
}

/**
 * Determines primary attack vector from alert attributes and evidence
 * @param {object} alert 
 * @returns {string}
 */
function determineAttackVector(alert) {
  const title = (alert.title || "").toLowerCase();
  const description = (alert.description || "").toLowerCase();
  const evidenceText = Array.isArray(alert.evidence)
    ? alert.evidence.map(e => `${e.name} ${e.category} ${e.explanation} ${e.evidence}`).join(" ").toLowerCase()
    : "";
  const combined = `${title} ${description} ${evidenceText}`;

  if (combined.includes("credential") || combined.includes("login") || combined.includes("password") || combined.includes("phish")) {
    return "CREDENTIAL_HARVESTING";
  }
  if (combined.includes("virustotal") || (alert.detectionSource && alert.detectionSource.includes("VIRUSTOTAL"))) {
    return "MALICIOUS_REPUTATION";
  }
  if (combined.includes("obfuscat") || combined.includes("eval(") || combined.includes("payload") || combined.includes("downloader")) {
    return "SUSPICIOUS_OBFUSCATION";
  }
  if (combined.includes("hidden iframe") || combined.includes("hidden element") || combined.includes("overlay")) {
    return "HIDDEN_ELEMENT_EXPLOIT";
  }
  if (combined.includes("drive-by") || combined.includes("binary") || combined.includes("executable")) {
    return "DRIVE_BY_DOWNLOAD";
  }
  return "ANOMALY_UNKNOWN";
}

/**
 * Extracts exfiltration endpoints or form actions from alert evidence
 * @param {object} alert 
 * @returns {string[]}
 */
function extractExfiltrationEndpoints(alert) {
  const endpoints = new Set();
  if (Array.isArray(alert.evidence)) {
    for (const item of alert.evidence) {
      const text = `${item.evidence || ""} ${item.explanation || ""}`;
      const urlMatches = text.match(/https?:\/\/[^\s"',;<>]+/g);
      if (urlMatches) {
        urlMatches.forEach(u => endpoints.add(u.toLowerCase()));
      }
      const ipMatches = text.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b/g);
      if (ipMatches) {
        ipMatches.forEach(ip => endpoints.add(ip));
      }
    }
  }
  return Array.from(endpoints);
}

/**
 * Evaluates whether an alert correlates with any active incident.
 * Criteria strictly enforced:
 * 1. Target Host Match: alert target host equals an affected target host in the incident.
 * 2. Exfiltration Endpoint Match: alert exfiltration URL/IP matches an incident exfiltration endpoint.
 * 3. Campaign Root Domain & Attack Vector: alert domain root matches incident target root AND shares attack vector.
 * 
 * Never groups purely by severity!
 * 
 * @param {object} alert - Normalized alert object
 * @param {Array<object>} activeIncidents - List of OPEN or INVESTIGATING incidents
 * @returns {{ matchedIncident: object|null, reason: string|null }}
 */
function findCorrelatedIncident(alert, activeIncidents = []) {
  if (!alert || !Array.isArray(activeIncidents) || activeIncidents.length === 0) {
    return { matchedIncident: null, reason: null };
  }

  const alertHost = extractHostname(alert.target);
  const alertRootDomain = extractRootDomain(alertHost);
  const alertVector = determineAttackVector(alert);
  const alertEndpoints = extractExfiltrationEndpoints(alert);

  for (const incident of activeIncidents) {
    if (incident.status === "RESOLVED" || incident.status === "CLOSED") {
      continue;
    }

    const incidentHosts = (incident.affectedTargets || []).map(t => extractHostname(t));

    // 1. Direct Target / Host Match
    if (incidentHosts.includes(alertHost)) {
      return {
        matchedIncident: incident,
        reason: `Target host match: '${alertHost}' is already an affected target of incident ${incident.incidentId}.`
      };
    }

    // 2. Exfiltration Endpoint Match
    if (alertEndpoints.length > 0 && Array.isArray(incident.exfiltrationEndpoints) && incident.exfiltrationEndpoints.length > 0) {
      const sharedEndpoint = alertEndpoints.find(ep => incident.exfiltrationEndpoints.includes(ep));
      if (sharedEndpoint) {
        return {
          matchedIncident: incident,
          reason: `Exfiltration endpoint match: Shared data destination '${sharedEndpoint}' across targets.`
        };
      }
    }

    // 3. Campaign Root Domain & Vector Match
    if (alertRootDomain && alertVector !== "ANOMALY_UNKNOWN" && incident.attackVector === alertVector) {
      const matchesRoot = incidentHosts.some(h => extractRootDomain(h) === alertRootDomain);
      if (matchesRoot) {
        return {
          matchedIncident: incident,
          reason: `Campaign domain match: Shared root '${alertRootDomain}' and attack vector '${alertVector}'.`
        };
      }
    }
  }

  return { matchedIncident: null, reason: null };
}

/**
 * Returns the higher of two severities
 * @param {string} sev1 
 * @param {string} sev2 
 * @returns {string}
 */
function elevateSeverity(sev1, sev2) {
  const rank1 = SEVERITY_RANKS[sev1] || 1;
  const rank2 = SEVERITY_RANKS[sev2] || 1;
  return rank1 >= rank2 ? sev1 : sev2;
}

/**
 * Returns the higher of two priorities
 * @param {string} prio1 
 * @param {string} prio2 
 * @returns {string}
 */
function elevatePriority(prio1, prio2) {
  const rank1 = PRIORITY_RANKS[prio1] || 1;
  const rank2 = PRIORITY_RANKS[prio2] || 1;
  return rank1 >= rank2 ? prio1 : prio2;
}

module.exports = {
  extractHostname,
  extractRootDomain,
  determineAttackVector,
  extractExfiltrationEndpoints,
  findCorrelatedIncident,
  elevateSeverity,
  elevatePriority
};
