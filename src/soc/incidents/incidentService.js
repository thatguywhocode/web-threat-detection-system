/**
 * SecuNexis — SOC Incident Service (Hardened Phase 2.5)
 *
 * Implements full incident lifecycle management:
 * - Concurrency-safe alert correlation & incident grouping (serialized mutex prevents race duplicates)
 * - Automatic escalation of CRITICAL/HIGH alerts to dedicated incidents
 * - Sanitized multi-criteria search (regex-escaped), filtering, and pagination
 * - Interactive analyst investigation notes log with verified actor attribution
 * - Immutable audit logging for creation, status, assignment, remediation, and notes
 */

const { getSecurityIncidentModel } = require("./incidentModel");
const { getSecurityAlertModel } = require("../alerts/alertModel");
const {
  extractHostname,
  determineAttackVector,
  extractExfiltrationEndpoints,
  findCorrelatedIncident,
  elevateSeverity,
  elevatePriority
} = require("./incidentCorrelation");
const { escapeRegex, sanitizeRemediation, sanitizeString } = require("../security/securityMiddleware");
const { recordAuditEvent } = require("../audit/auditService");

// Async serialization queue prevents race-condition duplicate incident creation under concurrent scans
let correlationQueue = Promise.resolve();

function generateRemediationForVector(attackVector, targetHost) {
  switch (attackVector) {
    case "CREDENTIAL_HARVESTING":
      return {
        summary: `Isolate and blacklist credential phishing host '${targetHost}'. Invalidate exposed credentials.`,
        steps: [
          `Add ${targetHost} to perimeter DNS and firewall blacklists.`,
          "Identify internal users who navigated to or submitted credentials to the target.",
          "Force immediate password resets and terminate active sessions for affected accounts.",
          "Submit phishing report to web hosting provider and registrar."
        ],
        completed: false
      };
    case "MALICIOUS_REPUTATION":
      return {
        summary: `Block verified malicious domain '${targetHost}' across web proxies and DNS resolvers.`,
        steps: [
          `Enforce enterprise proxy block for ${targetHost}.`,
          "Inspect firewall logs for outbound connections from endpoints to this host.",
          "Quarantine endpoints exhibiting outbound beaconing to the malicious target.",
          "Update threat intelligence feeds with observed indicators of compromise (IoCs)."
        ],
        completed: false
      };
    case "SUSPICIOUS_OBFUSCATION":
    case "HIDDEN_ELEMENT_EXPLOIT":
    case "DRIVE_BY_DOWNLOAD":
      return {
        summary: `Inspect client workstations that loaded obfuscated scripts or hidden elements on '${targetHost}'.`,
        steps: [
          `Block URL/domain on endpoint protection and gateway.`,
          "Run full EDR memory and disk malware scans on affected client endpoints.",
          "Inspect browser download caches for unauthorized file downloads.",
          "Review web proxy logs for related domains in the same hosting ASN."
        ],
        completed: false
      };
    default:
      return {
        summary: `Perform in-depth SOC investigation on suspicious target '${targetHost}'.`,
        steps: [
          "Validate target intent and inspect underlying payload scripts.",
          "Review network perimeter telemetry for repeated hits.",
          "Document findings and update incident resolution status."
        ],
        completed: false
      };
  }
}

/**
 * Creates a new Security Incident and logs immutable audit record when manually created
 */
async function createIncident(data, actor = null, req = null) {
  const IncidentModel = getSecurityIncidentModel();
  const affectedTargets = Array.isArray(data.affectedTargets)
    ? data.affectedTargets.filter(t => typeof t === "string" && t.trim()).map(t => t.trim().slice(0, 500)).slice(0, 50)
    : [];

  const host = affectedTargets[0] ? extractHostname(affectedTargets[0]) : "Unspecified Target";
  const attackVector = data.attackVector || "ANOMALY_UNKNOWN";
  const defaultTitle = `Security Incident: ${attackVector.replace(/_/g, " ")} on ${host}`;

  const cleanRemediation = data.remediation
    ? (sanitizeRemediation(data.remediation) || generateRemediationForVector(attackVector, host))
    : generateRemediationForVector(attackVector, host);

  const actorObj = actor && typeof actor === "object"
    ? actor
    : { userId: "system", username: "SecuNexis Automation", role: "SYSTEM" };

  const incidentDoc = new IncidentModel({
    title: sanitizeString(data.title || defaultTitle, 200) || defaultTitle,
    description: sanitizeString(data.description || `Incident raised for detected threats on ${host}.`, 2000),
    severity: data.severity || "MEDIUM",
    priority: data.priority || "P3_MEDIUM",
    status: data.status || "OPEN",
    associatedAlertIds: Array.isArray(data.associatedAlertIds) ? data.associatedAlertIds.filter(id => typeof id === "string").slice(0, 100) : [],
    affectedTargets,
    attackVector,
    exfiltrationEndpoints: Array.isArray(data.exfiltrationEndpoints) ? data.exfiltrationEndpoints.filter(e => typeof e === "string").slice(0, 50) : [],
    assignedTo: sanitizeString(data.assignedTo || "Unassigned", 80) || "Unassigned",
    remediation: cleanRemediation,
    rootCause: sanitizeString(data.rootCause || "", 1500),
    investigationNotes: Array.isArray(data.investigationNotes) && data.investigationNotes.length > 0
      ? data.investigationNotes.map(n => ({
          text: sanitizeString(n.text || "", 2000),
          author: sanitizeString(n.author || actorObj.username || "SecuNexis Automation", 80),
          timestamp: n.timestamp ? new Date(n.timestamp) : new Date()
        })).filter(n => n.text)
      : [{
          text: `Incident initialized by ${actorObj.username}. Initial severity: ${data.severity || "MEDIUM"}.`,
          author: actorObj.username,
          timestamp: new Date()
        }]
  });

  const saved = await incidentDoc.save();
  const result = typeof saved.toObject === "function" ? saved.toObject() : saved;

  if (actor) {
    await recordAuditEvent({
      actor: actorObj,
      req,
      action: "INCIDENT_CREATED",
      entityType: "INCIDENT",
      entityId: result.incidentId,
      outcome: "SUCCESS",
      details: `Created incident '${result.title}' (${result.severity}, assigned to ${result.assignedTo}).`,
      newState: {
        status: result.status,
        severity: result.severity,
        priority: result.priority,
        assignedTo: result.assignedTo
      }
    }).catch(() => {});
  }

  return result;
}

/**
 * Concurrency-safe alert correlation into an active incident or automatic incident creation.
 * Serialized via `correlationQueue` to prevent duplicate incident creation under simultaneous scans.
 */
function correlateAlertToIncident(alert) {
  const executeCorrelation = async () => {
    if (!alert) {
      return { correlated: false, incident: null, action: "NO_ALERT" };
    }

    const IncidentModel = getSecurityIncidentModel();
    const AlertModel = getSecurityAlertModel();

    const activeIncidents = await IncidentModel.find({
      status: { $in: ["OPEN", "INVESTIGATING"] }
    }).sort({ createdAt: -1 }).lean();

    // 1. Check for defensible correlation (host match, exfiltration match, campaign domain + vector)
    const { matchedIncident, reason } = findCorrelatedIncident(alert, activeIncidents);

    if (matchedIncident) {
      const newSeverity = elevateSeverity(matchedIncident.severity, alert.severity);
      const newPriority = elevatePriority(matchedIncident.priority, alert.priority);

      const updateOps = {
        $set: {
          severity: newSeverity,
          priority: newPriority,
          updatedAt: new Date()
        },
        $addToSet: {
          associatedAlertIds: alert.alertId,
          affectedTargets: alert.target
        },
        $push: {
          investigationNotes: {
            text: `Correlated Alert '${alert.alertId}' (${alert.title}). Reason: ${reason}`,
            author: "Correlation Engine",
            timestamp: new Date()
          }
        }
      };

      const updatedIncident = await IncidentModel.findOneAndUpdate(
        { incidentId: matchedIncident.incidentId },
        updateOps,
        { new: true }
      );

      await AlertModel.findOneAndUpdate(
        { alertId: alert.alertId },
        {
          $set: {
            incidentId: matchedIncident.incidentId,
            status: "ESCALATED_TO_INCIDENT"
          }
        }
      );

      return {
        correlated: true,
        incident: typeof updatedIncident.toObject === "function" ? updatedIncident.toObject() : updatedIncident,
        action: "MERGED_INTO_EXISTING"
      };
    }

    // 2. Automatically escalate CRITICAL or HIGH severity alerts into a NEW incident
    if (alert.severity === "CRITICAL" || alert.severity === "HIGH") {
      const vector = determineAttackVector(alert);
      const endpoints = extractExfiltrationEndpoints(alert);
      const host = extractHostname(alert.target);

      const newIncident = await createIncident({
        title: `${alert.severity} Incident: ${alert.title}`,
        description: alert.description || `High-risk alert triggered dedicated security incident on ${host}.`,
        severity: alert.severity,
        priority: alert.priority,
        status: "OPEN",
        associatedAlertIds: [alert.alertId],
        affectedTargets: [alert.target],
        attackVector: vector,
        exfiltrationEndpoints: endpoints,
        assignedTo: "Unassigned",
        investigationNotes: [
          {
            text: `Incident established automatically from ${alert.severity} alert '${alert.alertId}'.`,
            author: "Escalation Engine",
            timestamp: new Date()
          }
        ]
      });

      await AlertModel.findOneAndUpdate(
        { alertId: alert.alertId },
        {
          $set: {
            incidentId: newIncident.incidentId,
            status: "ESCALATED_TO_INCIDENT"
          }
        }
      );

      return {
        correlated: true,
        incident: newIncident,
        action: "CREATED_NEW_INCIDENT"
      };
    }

    return {
      correlated: false,
      incident: null,
      action: "STANDALONE_ALERT"
    };
  };

  const resultPromise = correlationQueue.then(executeCorrelation, executeCorrelation);
  correlationQueue = resultPromise.catch(() => {});
  return resultPromise;
}

/**
 * Retrieves incidents with sanitized filtering, regex-escaped search, and pagination
 */
async function getIncidents(query = {}) {
  const IncidentModel = getSecurityIncidentModel();

  const page = Math.max(1, parseInt(query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit, 10) || 20));
  const skip = (page - 1) * limit;

  const filter = {};

  if (query.status && typeof query.status === "string") {
    const st = query.status.trim().toUpperCase();
    if (["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"].includes(st)) {
      filter.status = st;
    }
  }

  if (query.severity && typeof query.severity === "string") {
    const sev = query.severity.trim().toUpperCase();
    if (["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(sev)) {
      filter.severity = sev;
    }
  }

  if (query.priority && typeof query.priority === "string") {
    const prio = query.priority.trim().toUpperCase();
    if (["P1_CRITICAL", "P2_HIGH", "P3_MEDIUM", "P4_LOW"].includes(prio)) {
      filter.priority = prio;
    }
  }

  if (query.attackVector && typeof query.attackVector === "string") {
    filter.attackVector = query.attackVector.trim().toUpperCase();
  }

  if (query.assignedTo && typeof query.assignedTo === "string" && query.assignedTo.trim()) {
    filter.assignedTo = { $regex: escapeRegex(query.assignedTo.trim(), 80), $options: "i" };
  }

  if (query.target && typeof query.target === "string" && query.target.trim()) {
    filter.affectedTargets = { $regex: escapeRegex(query.target.trim(), 150), $options: "i" };
  }

  if (query.startDate || query.endDate) {
    const dateRange = {};
    if (query.startDate) {
      const d = new Date(query.startDate);
      if (!isNaN(d.getTime())) dateRange.$gte = d;
    }
    if (query.endDate) {
      const d = new Date(query.endDate);
      if (!isNaN(d.getTime())) dateRange.$lte = d;
    }
    if (Object.keys(dateRange).length > 0) {
      filter.createdAt = dateRange;
    }
  }

  const [incidents, total] = await Promise.all([
    IncidentModel.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    IncidentModel.countDocuments(filter)
  ]);

  return {
    incidents: incidents.map(i => (typeof i.toObject === "function" ? i.toObject() : i)),
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
      hasNext: page * limit < total,
      hasPrev: page > 1
    }
  };
}

/**
 * Retrieves a single incident by its incidentId
 */
async function getIncidentById(id) {
  if (!id || typeof id !== "string") return null;
  const IncidentModel = getSecurityIncidentModel();
  const incident = await IncidentModel.findOne({ incidentId: id.trim() });
  if (!incident) return null;
  return typeof incident.toObject === "function" ? incident.toObject() : incident;
}

/**
 * Updates an incident's lifecycle status, assignment, remediation, or root cause.
 * Records immutable audit logs for every security-relevant transition.
 */
async function updateIncident(id, updates = {}, actor = "SOC Analyst", req = null) {
  if (!id || typeof id !== "string") return null;
  const IncidentModel = getSecurityIncidentModel();

  const existing = await IncidentModel.findOne({ incidentId: id.trim() });
  if (!existing) return null;
  const prevObj = typeof existing.toObject === "function" ? existing.toObject() : existing;

  const actorObj = typeof actor === "object" && actor !== null
    ? actor
    : { userId: "system", username: String(actor || "SOC Analyst"), role: "SYSTEM" };
  const authorLabel = actorObj.username || "SOC Analyst";

  const allowedUpdates = {};
  const notesToAdd = [];

  if (updates.status && typeof updates.status === "string") {
    const statusUpper = updates.status.trim().toUpperCase();
    allowedUpdates.status = statusUpper;
    if (statusUpper === "RESOLVED" || statusUpper === "CLOSED") {
      allowedUpdates.resolvedAt = new Date();
    } else {
      allowedUpdates.resolvedAt = null;
    }
    if (statusUpper !== prevObj.status) {
      notesToAdd.push({
        text: `Status changed from ${prevObj.status} to ${statusUpper}.`,
        author: authorLabel,
        timestamp: new Date()
      });
    }
  }

  if (updates.severity && typeof updates.severity === "string") {
    allowedUpdates.severity = updates.severity.trim().toUpperCase();
  }

  if (updates.priority && typeof updates.priority === "string") {
    allowedUpdates.priority = updates.priority.trim().toUpperCase();
  }

  if (updates.assignedTo !== undefined && typeof updates.assignedTo === "string") {
    const cleanAssignee = sanitizeString(updates.assignedTo, 80) || "Unassigned";
    allowedUpdates.assignedTo = cleanAssignee;
    if (cleanAssignee !== prevObj.assignedTo) {
      notesToAdd.push({
        text: `Assigned to ${cleanAssignee}.`,
        author: authorLabel,
        timestamp: new Date()
      });
    }
  }

  if (updates.rootCause !== undefined && typeof updates.rootCause === "string") {
    allowedUpdates.rootCause = sanitizeString(updates.rootCause, 1500);
  }

  if (updates.title && typeof updates.title === "string") {
    allowedUpdates.title = sanitizeString(updates.title, 200);
  }

  if (updates.description !== undefined && typeof updates.description === "string") {
    allowedUpdates.description = sanitizeString(updates.description, 2000);
  }

  let remediationUpdated = false;
  if (updates.remediation !== undefined) {
    const cleanRem = sanitizeRemediation(updates.remediation);
    if (cleanRem) {
      allowedUpdates.remediation = cleanRem;
      remediationUpdated = true;
      notesToAdd.push({
        text: `Remediation updated (completed: ${cleanRem.completed ? "Yes" : "No"}).`,
        author: authorLabel,
        timestamp: new Date()
      });
    }
  }

  if (Object.keys(allowedUpdates).length === 0) {
    return prevObj;
  }

  const updateOp = { $set: allowedUpdates };
  if (notesToAdd.length > 0) {
    updateOp.$push = { investigationNotes: { $each: notesToAdd } };
  }

  const updated = await IncidentModel.findOneAndUpdate(
    { incidentId: id.trim() },
    updateOp,
    { new: true }
  );

  if (!updated) return null;
  const result = typeof updated.toObject === "function" ? updated.toObject() : updated;

  // Immutable Audit Trail
  if (allowedUpdates.status && allowedUpdates.status !== prevObj.status) {
    await recordAuditEvent({
      actor: actorObj,
      req,
      action: "INCIDENT_STATUS_CHANGED",
      entityType: "INCIDENT",
      entityId: prevObj.incidentId,
      outcome: "SUCCESS",
      details: `Incident status changed from '${prevObj.status}' to '${allowedUpdates.status}'.`,
      previousState: { status: prevObj.status },
      newState: { status: result.status, resolvedAt: result.resolvedAt }
    }).catch(() => {});
  }

  if (allowedUpdates.assignedTo && allowedUpdates.assignedTo !== prevObj.assignedTo) {
    await recordAuditEvent({
      actor: actorObj,
      req,
      action: "INCIDENT_ASSIGNED",
      entityType: "INCIDENT",
      entityId: prevObj.incidentId,
      outcome: "SUCCESS",
      details: `Incident assignment changed from '${prevObj.assignedTo}' to '${allowedUpdates.assignedTo}'.`,
      previousState: { assignedTo: prevObj.assignedTo },
      newState: { assignedTo: result.assignedTo }
    }).catch(() => {});
  }

  if (remediationUpdated) {
    await recordAuditEvent({
      actor: actorObj,
      req,
      action: "INCIDENT_REMEDIATION_UPDATED",
      entityType: "INCIDENT",
      entityId: prevObj.incidentId,
      outcome: "SUCCESS",
      details: `Incident remediation guidance/status updated (completed: ${result.remediation?.completed}).`,
      previousState: { remediation: prevObj.remediation },
      newState: { remediation: result.remediation }
    }).catch(() => {});
  }

  return result;
}

/**
 * Appends an interactive analyst investigation note to an incident with verified actor attribution
 */
async function addInvestigationNote(id, noteData = {}, actor = null, req = null) {
  if (!id || typeof id !== "string" || !noteData.text || typeof noteData.text !== "string") return null;
  const IncidentModel = getSecurityIncidentModel();

  const cleanText = sanitizeString(noteData.text, 2000);
  if (!cleanText) return null;

  const actorObj = actor && typeof actor === "object"
    ? actor
    : { userId: "system", username: sanitizeString(noteData.author || "SOC Analyst", 80), role: "SYSTEM" };

  const newNote = {
    text: cleanText,
    author: actorObj.username || "SOC Analyst",
    timestamp: new Date()
  };

  const updated = await IncidentModel.findOneAndUpdate(
    { incidentId: id.trim() },
    {
      $push: { investigationNotes: newNote },
      $set: { updatedAt: new Date() }
    },
    { new: true }
  );

  if (!updated) return null;
  const result = typeof updated.toObject === "function" ? updated.toObject() : updated;

  await recordAuditEvent({
    actor: actorObj,
    req,
    action: "INCIDENT_NOTE_ADDED",
    entityType: "INCIDENT",
    entityId: result.incidentId,
    outcome: "SUCCESS",
    details: `Investigation note added to incident '${result.incidentId}'.`,
    newState: { notePreview: cleanText.slice(0, 200) }
  }).catch(() => {});

  return result;
}

/**
 * Aggregates incident statistics across statuses, severities, and attack vectors
 */
async function getIncidentStats() {
  const IncidentModel = getSecurityIncidentModel();
  const incidents = await IncidentModel.find({}).lean();

  const stats = {
    totalIncidents: incidents.length,
    activeIncidents: 0,
    byStatus: {
      OPEN: 0,
      INVESTIGATING: 0,
      RESOLVED: 0,
      CLOSED: 0
    },
    bySeverity: {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0
    },
    byAttackVector: {}
  };

  incidents.forEach(inc => {
    if (stats.byStatus[inc.status] !== undefined) stats.byStatus[inc.status]++;
    if (inc.status === "OPEN" || inc.status === "INVESTIGATING") stats.activeIncidents++;
    if (stats.bySeverity[inc.severity] !== undefined) stats.bySeverity[inc.severity]++;
    const vector = inc.attackVector || "ANOMALY_UNKNOWN";
    stats.byAttackVector[vector] = (stats.byAttackVector[vector] || 0) + 1;
  });

  return stats;
}

module.exports = {
  createIncident,
  correlateAlertToIncident,
  getIncidents,
  getIncidentById,
  updateIncident,
  addInvestigationNote,
  getIncidentStats
};
