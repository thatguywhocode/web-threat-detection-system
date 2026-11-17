/**
 * SecuNexis — Enterprise SOC SecurityIncident Model (Phase 2)
 *
 * Implements a normalized MongoDB/Mongoose SecurityIncident schema with:
 * - Multi-alert correlation linkage (`associatedAlertIds`)
 * - Affected targets tracking (`affectedTargets`)
 * - Threat classification & attack vector attribution (`attackVector`)
 * - Incident lifecycle state tracking: OPEN -> INVESTIGATING -> RESOLVED -> CLOSED
 * - Interactive analyst investigation notes log
 * - Remediation guidance and root cause analysis
 * - Dual-mode persistence: native MongoDB Atlas with automatic in-memory fallback
 */

const crypto = require("crypto");
const mongoose = require("mongoose");
const { isMongoConnected } = require("../events/eventModel");

/* ================= 1. MONGOOSE SCHEMA ================= */
const InvestigationNoteSchema = new mongoose.Schema({
  noteId: {
    type: String,
    default: () => "note_" + crypto.randomUUID().replace(/-/g, "").slice(0, 12)
  },
  text: {
    type: String,
    required: true,
    trim: true
  },
  author: {
    type: String,
    default: "SOC Analyst",
    trim: true
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
}, { _id: false });

const IncidentRemediationSchema = new mongoose.Schema({
  summary: { type: String, default: "" },
  steps: [{ type: String }],
  completed: { type: Boolean, default: false }
}, { _id: false });

const SecurityIncidentSchema = new mongoose.Schema({
  incidentId: {
    type: String,
    required: true,
    unique: true,
    index: true,
    default: () => "inc_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16)
  },
  title: {
    type: String,
    required: true,
    trim: true,
    index: true
  },
  description: {
    type: String,
    default: ""
  },
  severity: {
    type: String,
    enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    required: true,
    default: "MEDIUM",
    index: true
  },
  priority: {
    type: String,
    enum: ["P1_CRITICAL", "P2_HIGH", "P3_MEDIUM", "P4_LOW"],
    required: true,
    default: "P3_MEDIUM",
    index: true
  },
  status: {
    type: String,
    enum: ["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"],
    default: "OPEN",
    index: true
  },
  associatedAlertIds: [{
    type: String,
    index: true
  }],
  affectedTargets: [{
    type: String,
    trim: true,
    index: true
  }],
  attackVector: {
    type: String,
    enum: [
      "CREDENTIAL_HARVESTING",
      "DRIVE_BY_DOWNLOAD",
      "MALICIOUS_REPUTATION",
      "SUSPICIOUS_OBFUSCATION",
      "HIDDEN_ELEMENT_EXPLOIT",
      "PHISHING_CAMPAIGN",
      "ANOMALY_UNKNOWN"
    ],
    default: "ANOMALY_UNKNOWN",
    index: true
  },
  exfiltrationEndpoints: [{
    type: String,
    trim: true
  }],
  investigationNotes: [InvestigationNoteSchema],
  assignedTo: {
    type: String,
    default: "Unassigned",
    trim: true
  },
  remediation: {
    type: IncidentRemediationSchema,
    default: () => ({ summary: "", steps: [], completed: false })
  },
  rootCause: {
    type: String,
    default: ""
  },
  resolvedAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true,
  collection: "secunexis_incidents"
});

SecurityIncidentSchema.index({ status: 1, severity: 1, createdAt: -1 });
SecurityIncidentSchema.index({ affectedTargets: 1, createdAt: -1 });

let MongooseSecurityIncident;
try {
  MongooseSecurityIncident = mongoose.model("SecurityIncident", SecurityIncidentSchema);
} catch {
  MongooseSecurityIncident = mongoose.models.SecurityIncident;
}

/* ================= 2. IN-MEMORY RESILIENT STORE ================= */
class MemoryIncidentStore {
  constructor() {
    this.incidents = [];
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
          if (Array.isArray(itemVal)) {
            const hasCommon = itemVal.some(v => value.$in.includes(v));
            if (!hasCommon) return false;
          } else {
            if (!value.$in.includes(itemVal)) return false;
          }
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

      if (Array.isArray(itemVal)) {
        if (!itemVal.includes(value)) return false;
      } else {
        if (itemVal !== value) return false;
      }
    }
    return true;
  }

  find(filter = {}) {
    let results = this.incidents.filter(item => this._matchesFilter(item, filter));

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
    const item = this.incidents.find(i => this._matchesFilter(i, filter));
    return this._clone(item);
  }

  async countDocuments(filter = {}) {
    return this.incidents.filter(item => this._matchesFilter(item, filter)).length;
  }

  createInstance(data) {
    const store = this;
    const now = new Date();
    const doc = {
      incidentId: data.incidentId || ("inc_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16)),
      title: data.title,
      description: data.description || "",
      severity: data.severity || "MEDIUM",
      priority: data.priority || "P3_MEDIUM",
      status: data.status || "OPEN",
      associatedAlertIds: Array.isArray(data.associatedAlertIds) ? [...data.associatedAlertIds] : [],
      affectedTargets: Array.isArray(data.affectedTargets) ? [...data.affectedTargets] : [],
      attackVector: data.attackVector || "ANOMALY_UNKNOWN",
      exfiltrationEndpoints: Array.isArray(data.exfiltrationEndpoints) ? [...data.exfiltrationEndpoints] : [],
      investigationNotes: Array.isArray(data.investigationNotes) ? [...data.investigationNotes] : [],
      assignedTo: data.assignedTo || "Unassigned",
      remediation: data.remediation || { summary: "", steps: [], completed: false },
      rootCause: data.rootCause || "",
      resolvedAt: data.resolvedAt || null,
      createdAt: now,
      updatedAt: now,
      _id: "mem_inc_" + crypto.randomUUID().replace(/-/g, "").slice(0, 12),
      toObject() {
        return store._clone(this);
      },
      async save() {
        store.incidents.unshift(this);
        return this;
      }
    };
    return doc;
  }

  async findOneAndUpdate(filter, update, options = { new: true }) {
    const idx = this.incidents.findIndex(item => this._matchesFilter(item, filter));
    if (idx === -1) return null;

    const item = this.incidents[idx];

    if (update.$set) {
      Object.assign(item, update.$set);
    }

    if (update.$addToSet) {
      for (const [key, val] of Object.entries(update.$addToSet)) {
        if (!Array.isArray(item[key])) item[key] = [];
        if (val && val.$each && Array.isArray(val.$each)) {
          val.$each.forEach(elem => {
            if (!item[key].includes(elem)) item[key].push(elem);
          });
        } else {
          if (!item[key].includes(val)) item[key].push(val);
        }
      }
    }

    if (update.$push) {
      for (const [key, val] of Object.entries(update.$push)) {
        if (!Array.isArray(item[key])) item[key] = [];
        if (val && val.$each && Array.isArray(val.$each)) {
          item[key].push(...val.$each);
        } else {
          item[key].push(val);
        }
      }
    }

    item.updatedAt = new Date();
    return this._clone(item);
  }

  async deleteMany(filter = {}) {
    const before = this.incidents.length;
    this.incidents = this.incidents.filter(i => !this._matchesFilter(i, filter));
    return { deletedCount: before - this.incidents.length };
  }
}

const memoryIncidentStore = new MemoryIncidentStore();

function getSecurityIncidentModel() {
  if (isMongoConnected() && mongoose.connection.readyState === 1) {
    return MongooseSecurityIncident;
  }

  function ModelConstructor(data) {
    return memoryIncidentStore.createInstance(data);
  }
  Object.setPrototypeOf(ModelConstructor, memoryIncidentStore);
  ModelConstructor.find = memoryIncidentStore.find.bind(memoryIncidentStore);
  ModelConstructor.findOne = memoryIncidentStore.findOne.bind(memoryIncidentStore);
  ModelConstructor.findOneAndUpdate = memoryIncidentStore.findOneAndUpdate.bind(memoryIncidentStore);
  ModelConstructor.countDocuments = memoryIncidentStore.countDocuments.bind(memoryIncidentStore);
  ModelConstructor.deleteMany = memoryIncidentStore.deleteMany.bind(memoryIncidentStore);

  return ModelConstructor;
}

module.exports = {
  SecurityIncidentSchema,
  MongooseSecurityIncident,
  getSecurityIncidentModel,
  memoryIncidentStore
};
