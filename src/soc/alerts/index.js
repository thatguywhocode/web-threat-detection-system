/**
 * SecuNexis — SOC Alert Module Entry Point (Phase 2)
 */

const {
  SecurityAlertSchema,
  MongooseSecurityAlert,
  getSecurityAlertModel,
  memoryAlertStore
} = require("./alertModel");

const {
  extractTargetHost,
  evaluateAlertRules
} = require("./alertRules");

const {
  generateAlertFromEvent,
  getAlerts,
  getAlertById,
  updateAlert,
  getAlertStats
} = require("./alertService");

const alertRouter = require("./alertRoutes");

module.exports = {
  // Model
  SecurityAlertSchema,
  MongooseSecurityAlert,
  getSecurityAlertModel,
  memoryAlertStore,

  // Rules
  extractTargetHost,
  evaluateAlertRules,

  // Service
  generateAlertFromEvent,
  getAlerts,
  getAlertById,
  updateAlert,
  getAlertStats,

  // Express Router
  alertRouter
};
