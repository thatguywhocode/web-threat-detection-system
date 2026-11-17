/**
 * SecuNexis — Enterprise SOC User Model (Phase 2.5)
 *
 * Manages SOC user accounts with Role-Based Access Control (ADMIN, ANALYST, VIEWER),
 * bcrypt password hashes (never returned in sanitized outputs), and brute-force lockout fields.
 * Supports MongoDB Atlas (`secunexis_users`) with automatic in-memory fallback.
 */

const crypto = require("crypto");
const mongoose = require("mongoose");
const { isMongoConnected } = require("../db/connectionManager");

const VALID_ROLES = ["ADMIN", "ANALYST", "VIEWER"];

/* ================= 1. MONGOOSE SCHEMA ================= */
const UserSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
    unique: true,
    index: true,
    default: () => "usr_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16)
  },
  username: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    minlength: 3,
    maxlength: 50,
    index: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    maxlength: 120,
    index: true
  },
  displayName: {
    type: String,
    default: "",
    trim: true,
    maxlength: 80
  },
  passwordHash: {
    type: String,
    required: true,
    select: false
  },
  role: {
    type: String,
    enum: VALID_ROLES,
    required: true,
    default: "VIEWER",
    index: true
  },
  active: {
    type: Boolean,
    default: true,
    index: true
  },
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  },
  lastLoginAt: {
    type: Date,
    default: null
  },
  createdBy: {
    type: String,
    default: "system"
  }
}, {
  timestamps: true,
  collection: "secunexis_users"
});

UserSchema.index({ role: 1, active: 1 });

let MongooseUser;
try {
  MongooseUser = mongoose.model("SocUser", UserSchema);
} catch {
  MongooseUser = mongoose.models.SocUser;
}

/**
 * Strips sensitive fields (passwordHash, __v, internal _id) before exposing user data
 */
function sanitizeUser(user) {
  if (!user) return null;
  const obj = typeof user.toObject === "function" ? user.toObject() : user;
  return {
    userId: obj.userId,
    username: obj.username,
    email: obj.email,
    displayName: obj.displayName || obj.username,
    role: obj.role,
    active: Boolean(obj.active),
    failedLoginAttempts: obj.failedLoginAttempts || 0,
    lockUntil: obj.lockUntil || null,
    lastLoginAt: obj.lastLoginAt || null,
    createdBy: obj.createdBy || "system",
    createdAt: obj.createdAt || null,
    updatedAt: obj.updatedAt || null
  };
}

/* ================= 2. IN-MEMORY FALLBACK STORE ================= */
class MemoryUserStore {
  constructor() {
    this.users = [];
  }

  _clone(item, includePassword = false) {
    if (!item) return null;
    const copy = JSON.parse(JSON.stringify(item));
    if (!includePassword) {
      delete copy.passwordHash;
    }
    return copy;
  }

  _matchesFilter(item, filter = {}) {
    if (!filter || Object.keys(filter).length === 0) return true;
    if (filter.$or && !filter.$or.some(sub => this._matchesFilter(item, sub))) return false;
    if (filter.$and && !filter.$and.every(sub => this._matchesFilter(item, sub))) return false;

    for (const [key, val] of Object.entries(filter)) {
      if (key === "$or" || key === "$and") continue;
      if (val && typeof val === "object" && val.$ne !== undefined) {
        if (item[key] === val.$ne) return false;
        continue;
      }
      if (item[key] !== val) return false;
    }
    return true;
  }

  findOne(filter = {}) {
    const store = this;
    let includePassword = false;
    const chain = {
      select(fields) {
        if (typeof fields === "string" && fields.includes("+passwordHash")) {
          includePassword = true;
        }
        return chain;
      },
      lean() {
        return chain.then();
      },
      then(resolve) {
        const found = store.users.find(u => store._matchesFilter(u, filter));
        const res = store._clone(found, includePassword);
        return resolve ? resolve(res) : Promise.resolve(res);
      }
    };
    return chain;
  }

  find(filter = {}) {
    const store = this;
    const chain = {
      _sort: null,
      sort(criteria) {
        chain._sort = criteria;
        return chain;
      },
      lean() {
        return chain.then();
      },
      then(resolve) {
        const matched = store.users.filter(u => store._matchesFilter(u, filter));
        const res = matched.map(u => store._clone(u, false));
        return resolve ? resolve(res) : Promise.resolve(res);
      }
    };
    return chain;
  }

  async countDocuments(filter = {}) {
    return this.users.filter(u => this._matchesFilter(u, filter)).length;
  }

  async create(data) {
    const username = String(data.username || "").trim().toLowerCase();
    const email = String(data.email || "").trim().toLowerCase();

    if (this.users.some(u => u.username === username || u.email === email)) {
      const err = new Error("E11000 duplicate key error: username or email already exists");
      err.code = 11000;
      throw err;
    }

    const now = new Date();
    const doc = {
      _id: "mem_usr_" + crypto.randomUUID().replace(/-/g, "").slice(0, 12),
      userId: data.userId || ("usr_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16)),
      username,
      email,
      displayName: data.displayName || username,
      passwordHash: data.passwordHash,
      role: VALID_ROLES.includes(data.role) ? data.role : "VIEWER",
      active: data.active !== undefined ? Boolean(data.active) : true,
      failedLoginAttempts: data.failedLoginAttempts || 0,
      lockUntil: data.lockUntil || null,
      lastLoginAt: data.lastLoginAt || null,
      createdBy: data.createdBy || "system",
      createdAt: now,
      updatedAt: now
    };

    this.users.push(doc);
    return this._clone(doc, false);
  }

  async findOneAndUpdate(filter, update, options = { new: true }) {
    const idx = this.users.findIndex(u => this._matchesFilter(u, filter));
    if (idx === -1) return null;

    const item = this.users[idx];
    if (update.$set) {
      Object.assign(item, update.$set);
    }
    if (update.$inc) {
      for (const [k, v] of Object.entries(update.$inc)) {
        item[k] = (item[k] || 0) + v;
      }
    }
    item.updatedAt = new Date();
    return this._clone(item, false);
  }

  async deleteOne(filter) {
    const idx = this.users.findIndex(u => this._matchesFilter(u, filter));
    if (idx === -1) return { deletedCount: 0 };
    this.users.splice(idx, 1);
    return { deletedCount: 1 };
  }

  async deleteMany(filter = {}) {
    const before = this.users.length;
    this.users = this.users.filter(u => !this._matchesFilter(u, filter));
    return { deletedCount: before - this.users.length };
  }
}

const memoryUserStore = new MemoryUserStore();

function getUserModel() {
  if (isMongoConnected()) {
    return MongooseUser;
  }
  return memoryUserStore;
}

module.exports = {
  VALID_ROLES,
  UserSchema,
  MongooseUser,
  memoryUserStore,
  getUserModel,
  sanitizeUser
};
