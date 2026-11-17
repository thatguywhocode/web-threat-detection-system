/**
 * SecuNexis — SOC Alert Service (Hardened Phase 2.5)
 *
 * Provides enterprise business logic for SecurityAlert management:
 * - Concurrency-safe, idempotent alert generation from SecurityEvents with deduplication
 * - Sanitized multi-criteria filtering (regex-escaped), search, and pagination
 * - Alert lifecycle status transitions with immutable audit logging
 * - Aggregate security statistics across priorities, severities, and statuses
 */

const { getSecurityAlertModel } = require("./alertModel");
const { evaluateAlertRules } = require("./alertRules");
const { escapeRegex, sanitizeString } = require("../security/securityMiddleware");
const { recordAuditEvent } = require("../audit/auditService");

// In-flight deduplication map prevents concurrent race conditions on identical scanReferences
const inFlightAlerts = new Map();

/**
 * Creates an alert from a SecurityEvent if it satisfies alert criteria.
 * Idempotent & concurrency-safe: duplicate scanReferences/eventIds are suppressed.
 */
async function generateAlertFromEvent(event) {
  if (!event) {
    return { created: false, alert: null, reason: "No event supplied" };
  }

  const dedupKey = event.scanReference || event.eventId;
  if (dedupKey && inFlightAlerts.has(dedupKey)) {
    const existing = await inFlightAlerts.get(dedupKey);
    return {
      created: false,
      alert: existing?.alert || null,
      reason: "Concurrent alert creation deduplicated."
    };
  }

  const task = (async () => {
    const AlertModel = getSecurityAlertModel();

    const existingAlert = await AlertModel.findOne({
      $or: [
        { scanReference: event.scanReference },
        { eventId: event.eventId }
      ]
    });

    if (existingAlert) {
      return {
        created: false,
        alert: typeof existingAlert.toObject === "function" ? existingAlert.toObject() : existingAlert,
        reason: "Alert already exists for this scan reference (idempotent)."
      };
    }

    const evaluation = evaluateAlertRules(event);
    if (!evaluation.shouldAlert || !evaluation.alertData) {
      return {
        created: false,
        alert: null,
        reason: evaluation.reason
      };
    }

    try {
      const alertInstance = new AlertModel(evaluation.alertData);
      const saved = await alertInstance.save();
      return {
        created: true,
        alert: typeof saved.toObject === "function" ? saved.toObject() : saved,
        reason: "Alert created successfully."
      };
    } catch (err) {
      if (err.code === 11000 || (err.message && err.message.includes("duplicate key"))) {
        const existing = await AlertModel.findOne({ scanReference: event.scanReference });
        return {
          created: false,
          alert: existing && typeof existing.toObject === "function" ? existing.toObject() : existing,
          reason: "Concurrent alert creation prevented by unique constraint."
        };
      }
      throw err;
    }
  })();

  if (dedupKey) {
    inFlightAlerts.set(dedupKey, task);
  }
  try {
    return await task;
  } finally {
    if (dedupKey) {
      inFlightAlerts.delete(dedupKey);
    }
  }
}

/**
 * Retrieves alerts with sanitized multi-dimensional filtering and pagination
 */
async function getAlerts(query = {}) {
  const AlertModel = getSecurityAlertModel();

  const page = Math.max(1, parseInt(query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit, 10) || 20));
  const skip = (page - 1) * limit;

  const filter = {};

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

  if (query.status && typeof query.status === "string") {
    const st = query.status.trim().toUpperCase();
    if (["NEW", "ACKNOWLEDGED", "IN_TRIAGE", "DISMISSED", "ESCALATED_TO_INCIDENT"].includes(st)) {
      filter.status = st;
    }
  }

  if (query.verdict && typeof query.verdict === "string") {
    const v = query.verdict.trim().toUpperCase();
    if (["SAFE", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE"].includes(v)) {
      filter.verdict = v;
    }
  }

  if (query.target && typeof query.target === "string" && query.target.trim()) {
    filter.target = { $regex: escapeRegex(query.target.trim(), 150), $options: "i" };
  }

  if (query.incidentId !== undefined && typeof query.incidentId === "string") {
    if (query.incidentId === "none" || query.incidentId === "null" || query.incidentId === "") {
      filter.incidentId = null;
    } else {
      filter.incidentId = query.incidentId.trim();
    }
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

  const [alerts, total] = await Promise.all([
    AlertModel.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    AlertModel.countDocuments(filter)
  ]);

  return {
    alerts: alerts.map(a => (typeof a.toObject === "function" ? a.toObject() : a)),
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
 * Retrieves a single alert by its alertId
 */
async function getAlertById(id) {
  if (!id || typeof id !== "string") return null;
  const AlertModel = getSecurityAlertModel();
  const alert = await AlertModel.findOne({ alertId: id.trim() });
  if (!alert) return null;
  return typeof alert.toObject === "function" ? alert.toObject() : alert;
}

/**
 * Updates an alert's status, priority, incident association, or appends analyst notes.
 * Records immutable audit logs attributing the verified authenticated actor.
 *
 * @param {string} id - alertId
 * @param {object} updates - fields to update
 * @param {object|string} [actor] - authenticated req.user object (or string fallback for internal calls)
 * @param {object} [req] - Express request for IP/UA audit capture
 */
async function updateAlert(id, updates = {}, actor = "System Analyst", req = null) {
  if (!id || typeof id !== "string") return null;
  const AlertModel = getSecurityAlertModel();

  const existing = await AlertModel.findOne({ alertId: id.trim() });
  if (!existing) return null;
  const prevObj = typeof existing.toObject === "function" ? existing.toObject() : existing;

  const actorObj = typeof actor === "object" && actor !== null
    ? actor
    : { userId: "system", username: String(actor || "System Analyst"), role: "SYSTEM" };
  const authorLabel = actorObj.username || "SOC Analyst";

  const allowedUpdates = {};
  if (updates.status && typeof updates.status === "string") {
    allowedUpdates.status = updates.status.trim().toUpperCase();
  }
  if (updates.priority && typeof updates.priority === "string") {
    allowedUpdates.priority = updates.priority.trim().toUpperCase();
  }
  if (updates.severity && typeof updates.severity === "string") {
    allowedUpdates.severity = updates.severity.trim().toUpperCase();
  }
  if (updates.incidentId !== undefined) {
    allowedUpdates.incidentId = updates.incidentId ? sanitizeString(String(updates.incidentId), 80) : null;
  }

  const updateOp = {};
  if (Object.keys(allowedUpdates).length > 0) {
    updateOp.$set = allowedUpdates;
  }

  const cleanNote = typeof updates.note === "string" ? sanitizeString(updates.note, 2000) : "";
  if (cleanNote) {
    updateOp.$push = {
      analystNotes: {
        note: cleanNote,
        author: authorLabel,
        timestamp: new Date()
      }
    };
  }

  if (Object.keys(updateOp).length === 0) {
    return prevObj;
  }

  const updated = await AlertModel.findOneAndUpdate(
    { alertId: id.trim() },
    updateOp,
    { new: true }
  );

  if (!updated) return null;
  const result = typeof updated.toObject === "function" ? updated.toObject() : updated;

  // Record immutable audit trail
  if (allowedUpdates.status && allowedUpdates.status !== prevObj.status) {
    await recordAuditEvent({
      actor: actorObj,
      req,
      action: "ALERT_STATUS_CHANGED",
      entityType: "ALERT",
      entityId: prevObj.alertId,
      outcome: "SUCCESS",
      details: `Alert status changed from '${prevObj.status}' to '${allowedUpdates.status}'.`,
      previousState: { status: prevObj.status, priority: prevObj.priority, incidentId: prevObj.incidentId },
      newState: { status: result.status, priority: result.priority, incidentId: result.incidentId }
    }).catch(() => {});
  } else if (Object.keys(allowedUpdates).length > 0) {
    await recordAuditEvent({
      actor: actorObj,
      req,
      action: "ALERT_UPDATED",
      entityType: "ALERT",
      entityId: prevObj.alertId,
      outcome: "SUCCESS",
      details: `Alert fields updated (${Object.keys(allowedUpdates).join(", ")}).`,
      previousState: { status: prevObj.status, priority: prevObj.priority, incidentId: prevObj.incidentId },
      newState: { status: result.status, priority: result.priority, incidentId: result.incidentId }
    }).catch(() => {});
  }

  if (cleanNote) {
    await recordAuditEvent({
      actor: actorObj,
      req,
      action: "ALERT_NOTE_ADDED",
      entityType: "ALERT",
      entityId: prevObj.alertId,
      outcome: "SUCCESS",
      details: `Analyst note appended to alert '${prevObj.alertId}'.`,
      newState: { notePreview: cleanNote.slice(0, 200) }
    }).catch(() => {});
  }

  return result;
}

/**
 * Aggregates alert metrics across severities, priorities, and workflow statuses
 */
async function getAlertStats() {
  const AlertModel = getSecurityAlertModel();
  const alerts = await AlertModel.find({}).lean();

  const stats = {
    totalAlerts: alerts.length,
    bySeverity: {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0
    },
    byPriority: {
      P1_CRITICAL: 0,
      P2_HIGH: 0,
      P3_MEDIUM: 0,
      P4_LOW: 0
    },
    byStatus: {
      NEW: 0,
      ACKNOWLEDGED: 0,
      IN_TRIAGE: 0,
      DISMISSED: 0,
      ESCALATED_TO_INCIDENT: 0
    },
    unassignedCount: 0,
    openHighSeverityCount: 0
  };

  alerts.forEach(a => {
    if (stats.bySeverity[a.severity] !== undefined) stats.bySeverity[a.severity]++;
    if (stats.byPriority[a.priority] !== undefined) stats.byPriority[a.priority]++;
    if (stats.byStatus[a.status] !== undefined) stats.byStatus[a.status]++;
    if (!a.incidentId) stats.unassignedCount++;
    if ((a.severity === "CRITICAL" || a.severity === "HIGH") && a.status !== "DISMISSED") {
      stats.openHighSeverityCount++;
    }
  });

  return stats;
}

module.exports = {
  generateAlertFromEvent,
  getAlerts,
  getAlertById,
  updateAlert,
  getAlertStats
};
