/**
 * SecuNexis — Enterprise SOC SecurityAlert Model (Phase 2)
 *
 * Implements a normalized MongoDB/Mongoose SecurityAlert schema with:
 * - Deterministic event and scanReference links for idempotent alert generation
 * - Enterprise severity (LOW, MEDIUM, HIGH, CRITICAL) and priority (P1-P4) mappings
 * - Lifecycle status tracking (NEW, ACKNOWLEDGED, IN_TRIAGE, DISMISSED, ESCALATED_TO_INCIDENT)
 * - Structured threat evidence breakdown
 * - Resilient dual-mode persistence: native MongoDB Atlas with automatic in-memory fallback
 */

const crypto = require("crypto");
const mongoose = require("mongoose");
const { isMongoConnected } = require("../events/eventModel");

/* ================= 1. MONGOOSE SCHEMA ================= */
const AlertEvidenceSchema = new mongoose.Schema({
  id: { type: String, required: true },
  name: { type: String, required: true },
  category: { type: String, default: "Other detected anomalies" },
  severity: { type: String, default: "HIGH" },
  scoreContribution: { type: Number, default: 0 },
  explanation: { type: String, default: "" },
  evidence: { type: String, default: "" }
}, { _id: false });

const SecurityAlertSchema = new mongoose.Schema({
  alertId: {
    type: String,
    required: true,
    unique: true,
    index: true,
    default: () => "alt_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16)
  },
  eventId: {
    type: String,
    required: true,
    index: true
  },
  scanReference: {
    type: String,
    required: true,
    index: true
  },
  target: {
    type: String,
    required: true,
    trim: true,
    index: true
  },
  targetType: {
    type: String,
    enum: ["URL", "HTML"],
    default: "URL"
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    default: ""
  },
  severity: {
    type: String,
    enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    required: true,
    index: true
  },
  priority: {
    type: String,
    enum: ["P1_CRITICAL", "P2_HIGH", "P3_MEDIUM", "P4_LOW"],
    required: true,
    index: true
  },
  status: {
    type: String,
    enum: ["NEW", "ACKNOWLEDGED", "IN_TRIAGE", "DISMISSED", "ESCALATED_TO_INCIDENT"],
    default: "NEW",
    index: true
  },
  detectionSource: {
    type: String,
    default: "STATIC_HEURISTICS"
  },
  verdict: {
    type: String,
    enum: ["SAFE", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE"],
    default: "SUSPICIOUS",
    index: true
  },
  riskScore: {
    type: Number,
    required: true,
    min: 0,
    max: 100
  },
  threatCount: {
    type: Number,
    default: 0
  },
  evidence: [AlertEvidenceSchema],
  incidentId: {
    type: String,
    default: null,
    index: true
  },
  analystNotes: [{
    note: { type: String, required: true },
    author: { type: String, default: "SOC Analyst" },
    timestamp: { type: Date, default: Date.now }
  }],
  assignedTo: {
    type: String,
    default: "Unassigned"
  }
}, {
  timestamps: true,
  collection: "secunexis_alerts"
});

SecurityAlertSchema.index({ status: 1, severity: 1, createdAt: -1 });
SecurityAlertSchema.index({ incidentId: 1, createdAt: -1 });
SecurityAlertSchema.index({ scanReference: 1 }, { unique: true });

let MongooseSecurityAlert;
try {
  MongooseSecurityAlert = mongoose.model("SecurityAlert", SecurityAlertSchema);
} catch {
  MongooseSecurityAlert = mongoose.models.SecurityAlert;
}

/* ================= 2. IN-MEMORY RESILIENT STORE ================= */
class MemoryAlertStore {
  constructor() {
    this.alerts = [];
  }

  _clone(item) {
    return item ? JSON.parse(JSON.stringify(item)) : null;
  }

  _matchesFilter(item, filter = {}) {
    if (!filter || Object.keys(filter).length === 0) return true;

    if (filter.$or && Array.isArray(filter.$or)) {
      const orMatched = filter.$or.some(subFilter => this._matchesFilter(item, subFilter));
      if (!orMatched) return false;
    }

    if (filter.$and && Array.isArray(filter.$and)) {
      const andMatched = filter.$and.every(subFilter => this._matchesFilter(item, subFilter));
      if (!andMatched) return false;
    }

    for (const [key, value] of Object.entries(filter)) {
      if (key === "$or" || key === "$and") continue;

      const itemVal = item[key];

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
          const target = itemVal instanceof Date ? itemVal.getTime() : new Date(itemVal).getTime();
          const threshold = value.$gte instanceof Date ? value.$gte.getTime() : new Date(value.$gte).getTime();
          if (isNaN(target) || target < threshold) return false;
          continue;
        }
        if (value.$lte !== undefined) {
          const target = itemVal instanceof Date ? itemVal.getTime() : new Date(itemVal).getTime();
          const threshold = value.$lte instanceof Date ? value.$lte.getTime() : new Date(value.$lte).getTime();
          if (isNaN(target) || target > threshold) return false;
          continue;
        }
      }

      if (itemVal !== value) return false;
    }
    return true;
  }

  find(filter = {}) {
    let results = this.alerts.filter(item => this._matchesFilter(item, filter));

    const chain = {
      _sortCriteria: null,
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
      then(resolve, reject) {
        let finalResults = [...results];

        if (chain._sortCriteria) {
          finalResults.sort((a, b) => {
            for (const [k, direction] of Object.entries(chain._sortCriteria)) {
              let valA = a[k];
              let valB = b[k];
              if (valA instanceof Date) valA = valA.getTime();
              if (valB instanceof Date) valB = valB.getTime();
              if (typeof valA === "string" && (k === "createdAt" || k === "updatedAt")) {
                valA = new Date(valA).getTime();
                valB = new Date(valB).getTime();
              }
              if (valA < valB) return direction === -1 ? 1 : -1;
              if (valA > valB) return direction === -1 ? -1 : 1;
            }
            return 0;
          });
        }

        if (chain._skipCount) {
          finalResults = finalResults.slice(chain._skipCount);
        }

        if (chain._limitCount !== null) {
          finalResults = finalResults.slice(0, chain._limitCount);
        }

        const cloned = finalResults.map(item => JSON.parse(JSON.stringify(item)));
        if (resolve) return resolve(cloned);
        return Promise.resolve(cloned);
      }
    };

    return chain;
  }

  async findOne(filter = {}) {
    const item = this.alerts.find(a => this._matchesFilter(a, filter));
    return this._clone(item);
  }

  async countDocuments(filter = {}) {
    return this.alerts.filter(a => this._matchesFilter(a, filter)).length;
  }

  createInstance(data) {
    const store = this;
    const now = new Date();
    const doc = {
      alertId: data.alertId || ("alt_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16)),
      eventId: data.eventId,
      scanReference: data.scanReference,
      target: data.target,
      targetType: data.targetType || "URL",
      title: data.title,
      description: data.description || "",
      severity: data.severity || "MEDIUM",
      priority: data.priority || "P3_MEDIUM",
      status: data.status || "NEW",
      detectionSource: data.detectionSource || "STATIC_HEURISTICS",
      verdict: data.verdict || "SUSPICIOUS",
      riskScore: typeof data.riskScore === "number" ? data.riskScore : 0,
      threatCount: typeof data.threatCount === "number" ? data.threatCount : 0,
      evidence: Array.isArray(data.evidence) ? [...data.evidence] : [],
      incidentId: data.incidentId || null,
      analystNotes: Array.isArray(data.analystNotes) ? [...data.analystNotes] : [],
      assignedTo: data.assignedTo || "Unassigned",
      createdAt: data.createdAt ? new Date(data.createdAt) : now,
      updatedAt: data.updatedAt ? new Date(data.updatedAt) : now,
      _id: "mem_alt_" + crypto.randomUUID().replace(/-/g, "").slice(0, 12),
      toObject() {
        return store._clone(this);
      },
      async save() {
        const exists = store.alerts.find(a => a.scanReference === this.scanReference && a.alertId !== this.alertId);
        if (exists) {
          const err = new Error("E11000 duplicate key error collection: secunexis_alerts index: scanReference_1");
          err.code = 11000;
          throw err;
        }
        store.alerts.unshift(this);
        return this;
      }
    };
    return doc;
  }

  async create(data) {
    const instance = this.createInstance(data);
    return await instance.save();
  }

  async findOneAndUpdate(filter, update, options = { new: true }) {
    const idx = this.alerts.findIndex(a => this._matchesFilter(a, filter));
    if (idx === -1) return null;

    const item = this.alerts[idx];
    if (update.$set) {
      Object.assign(item, update.$set);
    }
    if (update.$push && update.$push.analystNotes) {
      item.analystNotes = item.analystNotes || [];
      if (update.$push.analystNotes.$each && Array.isArray(update.$push.analystNotes.$each)) {
        item.analystNotes.push(...update.$push.analystNotes.$each);
      } else {
        item.analystNotes.push(update.$push.analystNotes);
      }
    }
    item.updatedAt = new Date();
    return this._clone(item);
  }

  async findByIdAndUpdate(id, update, options = { new: true }) {
    return this.findOneAndUpdate({ $or: [{ alertId: id }, { _id: id }] }, update, options);
  }

  async deleteMany(filter = {}) {
    const before = this.alerts.length;
    this.alerts = this.alerts.filter(a => !this._matchesFilter(a, filter));
    return { deletedCount: before - this.alerts.length };
  }
}

const memoryAlertStore = new MemoryAlertStore();

function getSecurityAlertModel() {
  if (isMongoConnected() && mongoose.connection.readyState === 1) {
    return MongooseSecurityAlert;
  }

  function AlertModelConstructor(data) {
    return memoryAlertStore.createInstance(data);
  }
  Object.setPrototypeOf(AlertModelConstructor, memoryAlertStore);
  AlertModelConstructor.find = memoryAlertStore.find.bind(memoryAlertStore);
  AlertModelConstructor.findOne = memoryAlertStore.findOne.bind(memoryAlertStore);
  AlertModelConstructor.findOneAndUpdate = memoryAlertStore.findOneAndUpdate.bind(memoryAlertStore);
  AlertModelConstructor.countDocuments = memoryAlertStore.countDocuments.bind(memoryAlertStore);
  AlertModelConstructor.deleteMany = memoryAlertStore.deleteMany.bind(memoryAlertStore);
  AlertModelConstructor.create = memoryAlertStore.create.bind(memoryAlertStore);

  return AlertModelConstructor;
}

module.exports = {
  SecurityAlertSchema,
  MongooseSecurityAlert,
  getSecurityAlertModel,
  memoryAlertStore
};
