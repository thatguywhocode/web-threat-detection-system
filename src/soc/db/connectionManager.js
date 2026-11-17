/**
 * SecuNexis — Production MongoDB Connection & Reliability Manager (Phase 2.5)
 *
 * Provides resilient database lifecycle management:
 * - Tracks live Mongoose connection state via event listeners (connected, disconnected, error, reconnected)
 * - Automatic exponential backoff reconnection when MongoDB Atlas experiences transient failures
 * - Safe production configuration (`REQUIRE_MONGODB=true` fail-closed mode)
 * - Clean shutdown & health telemetry reporting (`getDbHealth()`)
 */

const mongoose = require("mongoose");

let isConnected = false;
let lastError = null;
let reconnectAttempts = 0;
let reconnectTimer = null;
let listenersAttached = false;
let activeUri = null;
let isShuttingDown = false;

const MAX_BACKOFF_MS = 30000;
const BASE_BACKOFF_MS = 1000;

function attachConnectionListeners() {
  if (listenersAttached) return;
  listenersAttached = true;

  mongoose.connection.on("connected", () => {
    isConnected = true;
    lastError = null;
    reconnectAttempts = 0;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  });

  mongoose.connection.on("reconnected", () => {
    isConnected = true;
    lastError = null;
    reconnectAttempts = 0;
    console.log("[SecuNexis DB] Reconnected to MongoDB.");
  });

  mongoose.connection.on("disconnected", () => {
    isConnected = false;
    if (!isShuttingDown && activeUri) {
      console.warn("[SecuNexis DB] MongoDB disconnected. Scheduling automatic reconnection...");
      scheduleReconnect();
    }
  });

  mongoose.connection.on("error", (err) => {
    isConnected = false;
    lastError = err ? err.message : "Unknown MongoDB error";
    console.warn("[SecuNexis DB] MongoDB connection error:", lastError);
  });
}

function scheduleReconnect() {
  if (reconnectTimer || isShuttingDown || !activeUri) return;

  reconnectAttempts++;
  const delay = Math.min(BASE_BACKOFF_MS * Math.pow(2, reconnectAttempts - 1), MAX_BACKOFF_MS);

  reconnectTimer = setTimeout(async () => {
    reconnectTimer = null;
    if (isShuttingDown || mongoose.connection.readyState === 1 || mongoose.connection.readyState === 2) {
      return;
    }
    try {
      await mongoose.connect(activeUri, getConnectionOptions());
    } catch (err) {
      lastError = err.message;
      scheduleReconnect();
    }
  }, delay);

  if (typeof reconnectTimer.unref === "function") {
    reconnectTimer.unref();
  }
}

function getConnectionOptions() {
  return {
    serverSelectionTimeoutMS: parseInt(process.env.MONGO_SERVER_SELECTION_TIMEOUT_MS, 10) || 5000,
    connectTimeoutMS: parseInt(process.env.MONGO_CONNECT_TIMEOUT_MS, 10) || 5000,
    socketTimeoutMS: parseInt(process.env.MONGO_SOCKET_TIMEOUT_MS, 10) || 45000,
    maxPoolSize: parseInt(process.env.MONGO_MAX_POOL_SIZE, 10) || 15,
    minPoolSize: 1,
    retryWrites: true
  };
}

/**
 * Initializes the MongoDB connection with production resilience.
 * Falls back gracefully to in-memory stores unless REQUIRE_MONGODB=true.
 */
async function initDb(uri = process.env.MONGODB_URI) {
  attachConnectionListeners();

  if (isConnected && mongoose.connection.readyState === 1) {
    return true;
  }

  const targetUri = uri || process.env.MONGODB_URI;
  if (!targetUri) {
    if (process.env.REQUIRE_MONGODB === "true") {
      throw new Error("MONGODB_URI is required when REQUIRE_MONGODB=true");
    }
    return false;
  }

  activeUri = targetUri;
  isShuttingDown = false;

  try {
    await mongoose.connect(targetUri, getConnectionOptions());
    isConnected = mongoose.connection.readyState === 1;
    lastError = null;
    reconnectAttempts = 0;
    console.log("[SecuNexis DB] Connected to MongoDB for persistent SOC operations.");
    return true;
  } catch (err) {
    isConnected = false;
    lastError = err.message;
    console.warn("[SecuNexis DB] MongoDB unavailable; operating with resilient fallback:", err.message);

    if (process.env.REQUIRE_MONGODB === "true") {
      throw err;
    }

    scheduleReconnect();
    return false;
  }
}

/**
 * Cleanly closes MongoDB connection (used during graceful shutdown or restart tests)
 */
async function disconnectDb() {
  isShuttingDown = true;
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  isConnected = false;
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
  }
}

/**
 * Checks whether MongoDB is actively connected and ready for queries
 */
function isMongoConnected() {
  return isConnected && mongoose.connection.readyState === 1;
}

/**
 * Returns sanitized database health diagnostics (never exposes URI or credentials)
 */
function getDbHealth() {
  const readyStates = {
    0: "disconnected",
    1: "connected",
    2: "connecting",
    3: "disconnecting"
  };
  const connected = isMongoConnected();
  return {
    connected,
    mode: connected ? "mongodb" : "memory_fallback",
    readyState: readyStates[mongoose.connection.readyState] || "unknown",
    reconnectAttempts,
    configured: Boolean(activeUri || process.env.MONGODB_URI),
    requireMongo: process.env.REQUIRE_MONGODB === "true",
    lastError: connected ? null : lastError
  };
}

module.exports = {
  initDb,
  disconnectDb,
  isMongoConnected,
  getDbHealth,
  getConnectionOptions
};
