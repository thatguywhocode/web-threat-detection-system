/**
 * SentinelCore — SOC Event Management Module (v1.0)
 *
 * Central export for SecurityEvent models, scan result adapter,
 * query service, and Express API routes.
 */

const {
  SecurityEventSchema,
  MongooseSecurityEvent,
  initDb,
  isMongoConnected,
  getSecurityEventModel,
  memoryStore
} = require("./eventModel");

const {
  adaptScanResult,
  generateScanReference,
  categorizeFinding,
  sanitizeRawInputPreview
} = require("./eventAdapter");

const {
  recordScanEvent,
  getEvents,
  getEventById,
  getEventStats,
  parseAndSanitizeFilters,
  clearAllEvents
} = require("./eventService");

const eventRoutes = require("./eventRoutes");

module.exports = {
  // Model & DB
  SecurityEventSchema,
  MongooseSecurityEvent,
  initDb,
  isMongoConnected,
  getSecurityEventModel,
  memoryStore,

  // Adapter
  adaptScanResult,
  generateScanReference,
  categorizeFinding,
  sanitizeRawInputPreview,

  // Service
  recordScanEvent,
  consumeScanResult: recordScanEvent,
  getEvents,
  getEventById,
  getEventStats,
  parseAndSanitizeFilters,
  clearAllEvents,

  // Express Routes
  eventRoutes,
  socEventRouter: eventRoutes
};
