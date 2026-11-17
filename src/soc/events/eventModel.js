/**
 * SentinelCore — Enterprise SOC SecurityEvent Model (v1.0)
 *
 * Implements a normalized MongoDB/Mongoose SecurityEvent schema with:
 * - Deterministic scan reference for idempotency and duplicate elimination
 * - Strictly validated security verdict, severity, and risk scores
 * - Structured detection evidence findings and reputation summaries
 * - Dual-mode persistence: native MongoDB with automatic resilient fallback
 */

const crypto = require("crypto");
const mongoose = require("mongoose");

/* ================= 1. MONGOOSE SUB-SCHEMAS ================= */
const EvidenceFindingSchema = new mongoose.Schema({
  id: { type: String, required: true },
  name: { type: String, required: true },
  category: { type: String, required: true, default: "Other detected anomalies" },
  severity: { type: String, enum: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], default: "INFO" },
  source: { type: String, default: "STATIC_HEURISTICS" },
  scoreContribution: { type: Number, default: 0 },
  explanation: { type: String, default: "" },
  evidence: { type: String, default: "" },
  whyItMatters: { type: String, default: "" },
  recommendedAction: { type: String, default: "" },
  isThreat: { type: Boolean, default: false }
}, { _id: false });

const VirusTotalSummarySchema = new mongoose.Schema({
  available: { type: Boolean, default: false },
  status: { type: String, default: "unavailable" },
  malicious: { type: Number, default: 0 },
  suspicious: { type: Number, default: 0 },
  harmless: { type: Number, default: 0 },
  undetected: { type: Number, default: 0 },
  totalEngines: { type: Number, default: 0 },
  reputation: { type: Number, default: 0 },
  message: { type: String, default: "" }
}, { _id: false });

const StaticMetricsSchema = new mongoose.Schema({
  totalScripts: { type: Number, default: 0 },
  totalIframes: { type: Number, default: 0 },
  hiddenElementsDetected: { type: Boolean, default: false },
  suspiciousHiddenCount: { type: Number, default: 0 },
  suspiciousIframesCount: { type: Number, default: 0 },
  jsThreatsCount: { type: Number, default: 0 },
  phishingThreatsCount: { type: Number, default: 0 },
  rawHtmlLength: { type: Number, default: 0 }
}, { _id: false });

const RemediationSummarySchema = new mongoose.Schema({
  priority: { type: String, default: "BASELINE" },
  summary: { type: String, default: "" },
  steps: [{ type: String }]
}, { _id: false });

/* ================= 2. PRIMARY SECURITY EVENT SCHEMA ================= */
const SecurityEventSchema = new mongoose.Schema({
  eventId: {
    type: String,
    required: true,
    unique: true,
    index: true,
    default: () => "sec_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16)
  },
  scanReference: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  target: {
    type: String,
    required: true,
    index: true,
    trim: true
  },
  targetType: {
    type: String,
    enum: ["URL", "HTML"],
    default: "URL"
  },
  verdict: {
    type: String,
    enum: ["SAFE", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE"],
    required: true,
    index: true
  },
  severity: {
    type: String,
    enum: ["LOW", "MEDIUM", "HIGH"],
    required: true,
    index: true
  },
  riskScore: {
    type: Number,
    required: true,
    min: 0,
    max: 100,
    index: true
  },
  scanCoverage: {
    type: String,
    enum: ["FULL", "STATIC_ONLY", "INSUFFICIENT"],
    default: "FULL"
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  threatCount: {
    type: Number,
    default: 0
  },
  infoCount: {
    type: Number,
    default: 0
  },
  detectionEvidence: [EvidenceFindingSchema],
  virusTotal: VirusTotalSummarySchema,
  staticMetrics: StaticMetricsSchema,
  remediation: RemediationSummarySchema,
  rawInputPreview: {
    type: String,
    default: ""
  },
  metadata: {
    source: { type: String, default: "WEB_SCANNER" },
    clientIp: { type: String, default: "127.0.0.1" },
    userAgent: { type: String, default: "" }
  }
}, {
  timestamps: true,
  collection: "security_events"
});

// Composite indexes for common SOC filtering and time-series aggregation
SecurityEventSchema.index({ verdict: 1, timestamp: -1 });
SecurityEventSchema.index({ severity: 1, timestamp: -1 });
SecurityEventSchema.index({ target: 1, timestamp: -1 });

const MongooseSecurityEvent = mongoose.models.SecurityEvent || mongoose.model("SecurityEvent", SecurityEventSchema);

/* ================= 3. RESILIENT IN-MEMORY / MONGO-COMPATIBLE FALLBACK ================= */
/**
 * In environments where a standalone MongoDB daemon is offline or unconfigured,
 * this store implements the exact Mongoose Query API contract for zero-downtime operation.
 */
class MemorySecurityEventStore {
  constructor() {
    this.events = [];
  }

  _clone(doc) {
    if (!doc) return null;
    return JSON.parse(JSON.stringify(doc));
  }

  _matchesFilter(event, filter = {}) {
    for (const key of Object.keys(filter)) {
      const condition = filter[key];

      if (key === "$and" && Array.isArray(condition)) {
        if (!condition.every(sub => this._matchesFilter(event, sub))) return false;
        continue;
      }
      if (key === "$or" && Array.isArray(condition)) {
        if (!condition.some(sub => this._matchesFilter(event, sub))) return false;
        continue;
      }

      const val = event[key];

      if (condition instanceof RegExp) {
        if (typeof val !== "string" || !condition.test(val)) return false;
      } else if (condition && typeof condition === "object") {
        if (condition.$regex) {
          const re = new RegExp(condition.$regex, condition.$options || "");
          if (typeof val !== "string" || !re.test(val)) return false;
        }
        if (condition.$in && Array.isArray(condition.$in)) {
          if (!condition.$in.includes(val)) return false;
        }
        if (condition.$gte !== undefined) {
          const targetVal = key === "timestamp" ? new Date(val).getTime() : val;
          const cmpVal = key === "timestamp" ? new Date(condition.$gte).getTime() : condition.$gte;
          if (targetVal < cmpVal) return false;
        }
        if (condition.$lte !== undefined) {
          const targetVal = key === "timestamp" ? new Date(val).getTime() : val;
          const cmpVal = key === "timestamp" ? new Date(condition.$lte).getTime() : condition.$lte;
          if (targetVal > cmpVal) return false;
        }
        if (condition.$gt !== undefined) {
          const targetVal = key === "timestamp" ? new Date(val).getTime() : val;
          const cmpVal = key === "timestamp" ? new Date(condition.$gt).getTime() : condition.$gt;
          if (targetVal <= cmpVal) return false;
        }
        if (condition.$lt !== undefined) {
          const targetVal = key === "timestamp" ? new Date(val).getTime() : val;
          const cmpVal = key === "timestamp" ? new Date(condition.$lt).getTime() : condition.$lt;
          if (targetVal >= cmpVal) return false;
        }
      } else if (val !== condition) {
        return false;
      }
    }
    return true;
  }

  async findOne(filter = {}) {
    const found = this.events.find(e => this._matchesFilter(e, filter));
    return this._clone(found);
  }

  find(filter = {}) {
    const matched = this.events.filter(e => this._matchesFilter(e, filter));
    let result = [...matched];

    const query = {
      _sort: null,
      _skip: 0,
      _limit: null,
      sort(s) {
        this._sort = s;
        return this;
      },
      skip(n) {
        this._skip = Number(n) || 0;
        return this;
      },
      limit(n) {
        this._limit = Number(n);
        return this;
      },
      lean() {
        return this;
      },
      exec: async () => {
        let rows = [...result];
        if (query._sort) {
          const sortField = typeof query._sort === "string" ? query._sort.replace(/^-/, "") : Object.keys(query._sort)[0];
          const desc = typeof query._sort === "string" ? query._sort.startsWith("-") : query._sort[sortField] === -1;
          rows.sort((a, b) => {
            const vA = a[sortField];
            const vB = b[sortField];
            if (vA < vB) return desc ? 1 : -1;
            if (vA > vB) return desc ? -1 : 1;
            return 0;
          });
        }
        if (query._skip > 0) {
          rows = rows.slice(query._skip);
        }
        if (typeof query._limit === "number" && query._limit > 0) {
          rows = rows.slice(0, query._limit);
        }
        return JSON.parse(JSON.stringify(rows));
      },
      then(resolve, reject) {
        return this.exec().then(resolve, reject);
      }
    };

    return query;
  }

  async countDocuments(filter = {}) {
    return this.events.filter(e => this._matchesFilter(e, filter)).length;
  }

  async create(doc) {
    if (this.events.some(e => e.scanReference === doc.scanReference)) {
      const err = new Error(`E11000 duplicate key error collection: security_events index: scanReference_1 dup key: { scanReference: "${doc.scanReference}" }`);
      err.code = 11000;
      throw err;
    }

    const newDoc = {
      ...JSON.parse(JSON.stringify(doc)),
      eventId: doc.eventId || "sec_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16),
      timestamp: doc.timestamp ? new Date(doc.timestamp) : new Date(),
      createdAt: new Date(),
      updatedAt: new Date()
    };

    this.events.unshift(newDoc);
    return this._clone(newDoc);
  }

  async distinct(field, filter = {}) {
    const matched = this.events.filter(e => this._matchesFilter(e, filter));
    const set = new Set(matched.map(e => e[field]).filter(Boolean));
    return Array.from(set);
  }

  async deleteMany(filter = {}) {
    const before = this.events.length;
    this.events = this.events.filter(e => !this._matchesFilter(e, filter));
    return { deletedCount: before - this.events.length };
  }
}

const memoryStore = new MemorySecurityEventStore();

/* ================= 4. UNIFIED DUAL-MODE CONNECTION MANAGER ================= */
const { initDb, disconnectDb, isMongoConnected, getDbHealth } = require("../db/connectionManager");

function getActiveModel() {
  if (isMongoConnected()) {
    return MongooseSecurityEvent;
  }
  return memoryStore;
}

module.exports = {
  SecurityEventSchema,
  MongooseSecurityEvent,
  initDb,
  disconnectDb,
  isMongoConnected,
  getDbHealth,
  getSecurityEventModel: getActiveModel,
  memoryStore
};
