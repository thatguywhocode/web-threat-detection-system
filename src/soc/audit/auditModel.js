/**
 * SecuNexis — Immutable Audit Log Model (Phase 2.5)
 *
 * Implements append-only, tamper-evident SOC audit logging:
 * - Captures actor identity, action, entity reference, state deltas, outcome, and timestamp
 * - Computes SHA-256 integrity hash chaining each record to its predecessor
 * - Enforces schema-level immutability blocking all updates and deletes
 * - Dual-mode persistence: MongoDB Atlas (`secunexis_audit_logs`) with frozen in-memory fallback
 */

const crypto = require("crypto");
const mongoose = require("mongoose");
const { isMongoConnected } = require("../db/connectionManager");

/* ================= 1. TAMPER-EVIDENT HASHING ================= */
function computeAuditHash(record, previousHash = "GENESIS") {
  const canonical = JSON.stringify({
    auditId: record.auditId,
    timestamp: new Date(record.timestamp).toISOString(),
    actor: record.actor,
    action: record.action,
    entityType: record.entityType,
    entityId: record.entityId,
    outcome: record.outcome,
    details: record.details,
    previousState: record.previousState || null,
    newState: record.newState || null,
    previousHash
  });
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

/* ================= 2. MONGOOSE SCHEMA (APPEND-ONLY) ================= */
const AuditActorSchema = new mongoose.Schema({
  userId: { type: String, default: "anonymous" },
  username: { type: String, default: "anonymous" },
  role: { type: String, default: "NONE" },
  ipAddress: { type: String, default: "" },
  userAgent: { type: String, default: "" }
}, { _id: false });

const AuditLogSchema = new mongoose.Schema({
  auditId: {
    type: String,
    required: true,
    unique: true,
    immutable: true,
    index: true,
    default: () => "aud_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16)
  },
  actor: {
    type: AuditActorSchema,
    required: true,
    immutable: true
  },
  action: {
    type: String,
    required: true,
    immutable: true,
    index: true
  },
  entityType: {
    type: String,
    required: true,
    immutable: true,
    index: true
  },
  entityId: {
    type: String,
    default: "",
    immutable: true,
    index: true
  },
  outcome: {
    type: String,
    enum: ["SUCCESS", "FAILURE", "DENIED"],
    default: "SUCCESS",
    immutable: true,
    index: true
  },
  details: {
    type: String,
    default: "",
    immutable: true
  },
  previousState: {
    type: mongoose.Schema.Types.Mixed,
    default: null,
    immutable: true
  },
  newState: {
    type: mongoose.Schema.Types.Mixed,
    default: null,
    immutable: true
  },
  previousHash: {
    type: String,
    default: "GENESIS",
    immutable: true
  },
  integrityHash: {
    type: String,
    required: true,
    immutable: true
  },
  timestamp: {
    type: Date,
    default: Date.now,
    immutable: true,
    index: true
  }
}, {
  timestamps: false,
  collection: "secunexis_audit_logs"
});

AuditLogSchema.index({ action: 1, timestamp: -1 });
AuditLogSchema.index({ "actor.username": 1, timestamp: -1 });
AuditLogSchema.index({ entityType: 1, entityId: 1, timestamp: -1 });

// Enforce strict immutability at the Mongoose middleware layer
const IMMUTABLE_ERROR = () => new Error("AuditLog records are strictly immutable and cannot be modified or deleted.");

const blockedHooks = [
  "updateOne",
  "updateMany",
  "findOneAndUpdate",
  "findByIdAndUpdate",
  "replaceOne",
  "deleteOne",
  "deleteMany",
  "findOneAndDelete",
  "findByIdAndDelete",
  "findOneAndRemove"
];

blockedHooks.forEach(hook => {
  AuditLogSchema.pre(hook, function (next) {
    next(IMMUTABLE_ERROR());
  });
});

let MongooseAuditLog;
try {
  MongooseAuditLog = mongoose.model("AuditLog", AuditLogSchema);
} catch {
  MongooseAuditLog = mongoose.models.AuditLog;
}

/* ================= 3. IMMUTABLE IN-MEMORY FALLBACK STORE ================= */
class MemoryAuditStore {
  constructor() {
    this._records = [];
  }

  _clone(item) {
    return item ? JSON.parse(JSON.stringify(item)) : null;
  }

  _getValByPath(obj, path) {
    return path.split(".").reduce((acc, part) => (acc && acc[part] !== undefined ? acc[part] : undefined), obj);
  }

  _matchesFilter(item, filter = {}) {
    if (!filter || Object.keys(filter).length === 0) return true;
    if (filter.$and && !filter.$and.every(sub => this._matchesFilter(item, sub))) return false;
    if (filter.$or && !filter.$or.some(sub => this._matchesFilter(item, sub))) return false;

    for (const [key, value] of Object.entries(filter)) {
      if (key === "$and" || key === "$or") continue;
      const itemVal = this._getValByPath(item, key);

      if (value && typeof value === "object" && !(value instanceof Date) && !(value instanceof RegExp)) {
        if (value.$regex !== undefined) {
          const reg = new RegExp(value.$regex, value.$options || "");
          if (!reg.test(String(itemVal || ""))) return false;
          continue;
        }
        if (value.$in && Array.isArray(value.$in)) {
          if (!value.$in.includes(itemVal)) return false;
          continue;
        }
        if (value.$gte !== undefined) {
          const t = new Date(itemVal).getTime();
          const cmp = new Date(value.$gte).getTime();
          if (isNaN(t) || t < cmp) return false;
          continue;
        }
        if (value.$lte !== undefined) {
          const t = new Date(itemVal).getTime();
          const cmp = new Date(value.$lte).getTime();
          if (isNaN(t) || t > cmp) return false;
          continue;
        }
      }

      if (itemVal !== value) return false;
    }
    return true;
  }

  async getLatestHash() {
    if (this._records.length === 0) return "GENESIS";
    return this._records[this._records.length - 1].integrityHash;
  }

  async create(data) {
    const previousHash = data.previousHash || (await this.getLatestHash());
    const record = {
      auditId: data.auditId || ("aud_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16)),
      actor: {
        userId: data.actor?.userId || "anonymous",
        username: data.actor?.username || "anonymous",
        role: data.actor?.role || "NONE",
        ipAddress: data.actor?.ipAddress || "",
        userAgent: data.actor?.userAgent || ""
      },
      action: String(data.action),
      entityType: String(data.entityType || "SYSTEM"),
      entityId: String(data.entityId || ""),
      outcome: data.outcome || "SUCCESS",
      details: String(data.details || ""),
      previousState: data.previousState !== undefined ? JSON.parse(JSON.stringify(data.previousState)) : null,
      newState: data.newState !== undefined ? JSON.parse(JSON.stringify(data.newState)) : null,
      previousHash,
      timestamp: data.timestamp ? new Date(data.timestamp) : new Date()
    };

    record.integrityHash = data.integrityHash || computeAuditHash(record, previousHash);

    // Deep-freeze top-level and nested actor to prevent runtime mutation
    Object.freeze(record.actor);
    Object.freeze(record);

    this._records.push(record);
    return this._clone(record);
  }

  find(filter = {}) {
    const matched = this._records.filter(r => this._matchesFilter(r, filter));
    const chain = {
      _sortCriteria: { timestamp: -1 },
      _skipCount: 0,
      _limitCount: null,

      sort(criteria) {
        chain._sortCriteria = criteria;
        return chain;
      },
      skip(n) {
        chain._skipCount = n;
        return chain;
      },
      limit(n) {
        chain._limitCount = n;
        return chain;
      },
      lean() {
        return chain.then();
      },
      then(resolve) {
        let arr = [...matched];
        if (chain._sortCriteria) {
          arr.sort((a, b) => {
            for (const [k, dir] of Object.entries(chain._sortCriteria)) {
              const va = k === "timestamp" ? new Date(a[k]).getTime() : a[k];
              const vb = k === "timestamp" ? new Date(b[k]).getTime() : b[k];
              if (va < vb) return dir === -1 ? 1 : -1;
              if (va > vb) return dir === -1 ? -1 : 1;
            }
            return 0;
          });
        }
        if (chain._skipCount) arr = arr.slice(chain._skipCount);
        if (chain._limitCount !== null) arr = arr.slice(0, chain._limitCount);
        const cloned = arr.map(r => JSON.parse(JSON.stringify(r)));
        return resolve ? resolve(cloned) : Promise.resolve(cloned);
      }
    };
    return chain;
  }

  async findOne(filter = {}) {
    const item = this._records.find(r => this._matchesFilter(r, filter));
    return this._clone(item);
  }

  async countDocuments(filter = {}) {
    return this._records.filter(r => this._matchesFilter(r, filter)).length;
  }

  // Explicitly throw on any attempt to mutate or delete audit logs
  async updateOne() { throw IMMUTABLE_ERROR(); }
  async updateMany() { throw IMMUTABLE_ERROR(); }
  async findOneAndUpdate() { throw IMMUTABLE_ERROR(); }
  async deleteOne() { throw IMMUTABLE_ERROR(); }
  async deleteMany() { throw IMMUTABLE_ERROR(); }

  // Internal test-only reset (only callable directly in test suites when NODE_ENV !== 'production')
  _clearForTests() {
    if (process.env.NODE_ENV === "production") {
      throw IMMUTABLE_ERROR();
    }
    this._records = [];
  }
}

const memoryAuditStore = new MemoryAuditStore();

function getAuditLogModel() {
  if (isMongoConnected()) {
    return MongooseAuditLog;
  }
  return memoryAuditStore;
}

module.exports = {
  AuditLogSchema,
  MongooseAuditLog,
  memoryAuditStore,
  getAuditLogModel,
  computeAuditHash
};
