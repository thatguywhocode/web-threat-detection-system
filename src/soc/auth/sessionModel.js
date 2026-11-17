/**
 * SecuNexis — Secure Session Store Model (Phase 2.5)
 *
 * Stores server-side sessions with:
 * - SHA-256 hashed session token (`tokenHash`) — raw cookie tokens are NEVER persisted in the DB
 * - Per-session cryptographically random CSRF token (`csrfToken`)
 * - Automatic MongoDB TTL index (`expiresAt`) for server-side expiry cleanup
 * - Instant logout invalidation & per-user revocation (`revokeAllForUser`)
 * - Dual-mode persistence: MongoDB Atlas (`secunexis_sessions`) with in-memory fallback
 */

const crypto = require("crypto");
const mongoose = require("mongoose");
const { isMongoConnected } = require("../db/connectionManager");

/* ================= 1. MONGOOSE SCHEMA ================= */
const SessionSchema = new mongoose.Schema({
  sessionId: {
    type: String,
    required: true,
    unique: true,
    index: true,
    default: () => "ses_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16)
  },
  tokenHash: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  csrfToken: {
    type: String,
    required: true
  },
  userId: {
    type: String,
    required: true,
    index: true
  },
  username: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ["ADMIN", "ANALYST", "VIEWER"],
    required: true
  },
  ipAddress: {
    type: String,
    default: ""
  },
  userAgent: {
    type: String,
    default: ""
  },
  revoked: {
    type: Boolean,
    default: false,
    index: true
  },
  expiresAt: {
    type: Date,
    required: true
  },
  lastActivityAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true,
  collection: "secunexis_sessions"
});

// MongoDB TTL index automatically purges expired sessions
SessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
SessionSchema.index({ userId: 1, revoked: 1 });

let MongooseSession;
try {
  MongooseSession = mongoose.model("SocSession", SessionSchema);
} catch {
  MongooseSession = mongoose.models.SocSession;
}

/* ================= 2. IN-MEMORY FALLBACK STORE ================= */
class MemorySessionStore {
  constructor() {
    this.sessions = [];
  }

  _clone(item) {
    return item ? JSON.parse(JSON.stringify(item)) : null;
  }

  _matchesFilter(item, filter = {}) {
    for (const [k, v] of Object.entries(filter)) {
      if (item[k] !== v) return false;
    }
    return true;
  }

  async create(data) {
    const now = new Date();
    const doc = {
      _id: "mem_ses_" + crypto.randomUUID().replace(/-/g, "").slice(0, 12),
      sessionId: data.sessionId || ("ses_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16)),
      tokenHash: data.tokenHash,
      csrfToken: data.csrfToken,
      userId: data.userId,
      username: data.username,
      role: data.role,
      ipAddress: data.ipAddress || "",
      userAgent: data.userAgent || "",
      revoked: Boolean(data.revoked),
      expiresAt: new Date(data.expiresAt),
      lastActivityAt: data.lastActivityAt ? new Date(data.lastActivityAt) : now,
      createdAt: now,
      updatedAt: now
    };
    this.sessions.push(doc);
    return this._clone(doc);
  }

  async findOne(filter = {}) {
    const item = this.sessions.find(s => this._matchesFilter(s, filter));
    return this._clone(item);
  }

  async findOneAndUpdate(filter, update) {
    const idx = this.sessions.findIndex(s => this._matchesFilter(s, filter));
    if (idx === -1) return null;
    if (update.$set) {
      Object.assign(this.sessions[idx], update.$set);
    }
    this.sessions[idx].updatedAt = new Date();
    return this._clone(this.sessions[idx]);
  }

  async updateMany(filter, update) {
    let modified = 0;
    this.sessions.forEach(s => {
      if (this._matchesFilter(s, filter)) {
        if (update.$set) Object.assign(s, update.$set);
        s.updatedAt = new Date();
        modified++;
      }
    });
    return { modifiedCount: modified };
  }

  async deleteOne(filter) {
    const idx = this.sessions.findIndex(s => this._matchesFilter(s, filter));
    if (idx === -1) return { deletedCount: 0 };
    this.sessions.splice(idx, 1);
    return { deletedCount: 1 };
  }

  async deleteMany(filter = {}) {
    const before = this.sessions.length;
    this.sessions = this.sessions.filter(s => !this._matchesFilter(s, filter));
    return { deletedCount: before - this.sessions.length };
  }
}

const memorySessionStore = new MemorySessionStore();

function getSessionModel() {
  if (isMongoConnected()) {
    return MongooseSession;
  }
  return memorySessionStore;
}

module.exports = {
  SessionSchema,
  MongooseSession,
  memorySessionStore,
  getSessionModel
};
