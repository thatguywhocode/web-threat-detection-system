/**
 * SecuNexis — Immutable Audit Log Service (Phase 2.5)
 *
 * Manages append-only recording, querying, filtering, and integrity verification
 * of SOC security audit records. Uses a write serialization queue to preserve
 * SHA-256 hash chain ordering under concurrent requests.
 */

const crypto = require("crypto");
const { getAuditLogModel, computeAuditHash } = require("./auditModel");
const { escapeRegex } = require("../security/securityMiddleware");

// Serializes audit appends to preserve deterministic previousHash chaining
let auditWriteQueue = Promise.resolve();

/**
 * Normalizes an actor object from req.user / request context
 */
function normalizeActor(actor = {}, req = null) {
  return {
    userId: String(actor?.userId || req?.user?.userId || "system"),
    username: String(actor?.username || req?.user?.username || "system"),
    role: String(actor?.role || req?.user?.role || "SYSTEM"),
    ipAddress: String(actor?.ipAddress || req?.ip || req?.socket?.remoteAddress || ""),
    userAgent: String(actor?.userAgent || req?.headers?.["user-agent"] || "").slice(0, 200)
  };
}

/**
 * Appends a new immutable audit record with cryptographic hash chaining.
 * Never throws out to caller unless critical; returns the created record.
 */
function recordAuditEvent({
  actor = {},
  req = null,
  action,
  entityType = "SYSTEM",
  entityId = "",
  outcome = "SUCCESS",
  details = "",
  previousState = null,
  newState = null
}) {
  const executeAppend = async () => {
    const AuditModel = getAuditLogModel();
    const resolvedActor = normalizeActor(actor, req);

    // Fetch latest hash for tamper-evident chain
    let previousHash = "GENESIS";
    if (typeof AuditModel.getLatestHash === "function") {
      previousHash = await AuditModel.getLatestHash();
    } else {
      const latest = await AuditModel.findOne({}).sort({ timestamp: -1 }).lean();
      if (latest && latest.integrityHash) {
        previousHash = latest.integrityHash;
      }
    }

    const recordDraft = {
      auditId: "aud_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16),
      actor: resolvedActor,
      action: String(action || "UNKNOWN_ACTION").toUpperCase(),
      entityType: String(entityType || "SYSTEM").toUpperCase(),
      entityId: String(entityId || ""),
      outcome: ["SUCCESS", "FAILURE", "DENIED"].includes(String(outcome).toUpperCase())
        ? String(outcome).toUpperCase()
        : "SUCCESS",
      details: String(details || "").slice(0, 1000),
      previousState: previousState !== undefined ? previousState : null,
      newState: newState !== undefined ? newState : null,
      previousHash,
      timestamp: new Date()
    };

    recordDraft.integrityHash = computeAuditHash(recordDraft, previousHash);

    const created = await AuditModel.create(recordDraft);
    return typeof created.toObject === "function" ? created.toObject() : created;
  };

  const resultPromise = auditWriteQueue.then(executeAppend, executeAppend);
  auditWriteQueue = resultPromise.catch(() => {});
  return resultPromise;
}

/**
 * Queries immutable audit logs with sanitized filtering and pagination
 */
async function getAuditLogs(query = {}) {
  const AuditModel = getAuditLogModel();

  const page = Math.max(1, parseInt(query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit, 10) || 25));
  const skip = (page - 1) * limit;

  const filter = {};

  if (query.action && typeof query.action === "string") {
    filter.action = { $regex: escapeRegex(query.action.trim(), 80), $options: "i" };
  }

  if (query.entityType && typeof query.entityType === "string") {
    filter.entityType = query.entityType.trim().toUpperCase();
  }

  if (query.entityId && typeof query.entityId === "string") {
    filter.entityId = query.entityId.trim();
  }

  if (query.username && typeof query.username === "string") {
    filter["actor.username"] = { $regex: escapeRegex(query.username.trim(), 80), $options: "i" };
  }

  if (query.outcome && typeof query.outcome === "string") {
    const out = query.outcome.trim().toUpperCase();
    if (["SUCCESS", "FAILURE", "DENIED"].includes(out)) {
      filter.outcome = out;
    }
  }

  if (query.startDate || query.endDate) {
    filter.timestamp = {};
    if (query.startDate) {
      const d = new Date(query.startDate);
      if (!isNaN(d.getTime())) filter.timestamp.$gte = d;
    }
    if (query.endDate) {
      const d = new Date(query.endDate);
      if (!isNaN(d.getTime())) filter.timestamp.$lte = d;
    }
    if (Object.keys(filter.timestamp).length === 0) delete filter.timestamp;
  }

  const [logs, total] = await Promise.all([
    AuditModel.find(filter).sort({ timestamp: -1 }).skip(skip).limit(limit).lean(),
    AuditModel.countDocuments(filter)
  ]);

  return {
    logs: logs.map(l => (typeof l.toObject === "function" ? l.toObject() : l)),
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
 * Verifies the cryptographic SHA-256 hash chain across all stored audit records
 * to detect any unauthorized tampering or deletion.
 */
async function verifyAuditChain() {
  const AuditModel = getAuditLogModel();
  const records = await AuditModel.find({}).sort({ timestamp: 1 }).lean();

  let expectedPrevHash = "GENESIS";
  let validCount = 0;
  const tamperedIds = [];

  for (const rec of records) {
    const recomputed = computeAuditHash(rec, rec.previousHash);
    const hashValid = recomputed === rec.integrityHash;
    const linkValid = rec.previousHash === expectedPrevHash;

    if (hashValid && linkValid) {
      validCount++;
    } else {
      tamperedIds.push({
        auditId: rec.auditId,
        hashValid,
        linkValid
      });
    }
    expectedPrevHash = rec.integrityHash;
  }

  return {
    verified: tamperedIds.length === 0,
    totalRecords: records.length,
    validRecords: validCount,
    tamperedRecords: tamperedIds
  };
}

module.exports = {
  recordAuditEvent,
  getAuditLogs,
  verifyAuditChain,
  normalizeActor
};
