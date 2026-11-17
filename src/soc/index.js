/**
 * SecuNexis — Central Enterprise SOC Subsystem (Phase 2.5 Hardened)
 *
 * Exposes all SOC modules:
 * - Database Reliability: connectionManager (MongoDB Atlas + reconnect + health)
 * - API Security: NoSQL guard, regex escaping, security headers, safe errors
 * - Phase 2.5 Authentication & RBAC: bcrypt, opaque sessions, CSRF, ADMIN/ANALYST/VIEWER
 * - Phase 2.5 Immutable Audit Logs: append-only SHA-256 chained audit records
 * - Phase 1 SecurityEvent Management
 * - Phase 2 SecurityAlert & SecurityIncident Management
 */

const db = require("./db/connectionManager");
const security = require("./security/securityMiddleware");
const audit = require("./audit");
const auth = require("./auth");
const events = require("./events");
const alerts = require("./alerts");
const incidents = require("./incidents");

module.exports = {
  // Subsystems
  db,
  security,
  audit,
  auth,
  events,
  alerts,
  incidents,

  // DB Lifecycle
  initDb: db.initDb,
  disconnectDb: db.disconnectDb,
  isMongoConnected: db.isMongoConnected,
  getDbHealth: db.getDbHealth,

  // Security & Auth Middleware
  nosqlInjectionGuard: security.nosqlInjectionGuard,
  securityHeadersMiddleware: security.securityHeadersMiddleware,
  attachAuthContext: auth.attachAuthContext,
  requireAuth: auth.requireAuth,
  requireRole: auth.requireRole,
  verifyCsrf: auth.verifyCsrf,
  bootstrapInitialAdminFromEnv: auth.bootstrapInitialAdminFromEnv,

  // Routers
  authRouter: auth.authRouter,
  auditRouter: audit.auditRouter,
  socEventRouter: events.socEventRouter || events.eventRoutes,
  eventRouter: events.socEventRouter || events.eventRoutes,
  socAlertRouter: alerts.alertRouter,
  alertRouter: alerts.alertRouter,
  socIncidentRouter: incidents.incidentRouter,
  incidentRouter: incidents.incidentRouter,

  // Event exports
  recordScanEvent: events.recordScanEvent,
  getEvents: events.getEvents,
  getEventById: events.getEventById,
  getEventStats: events.getEventStats,

  // Alert exports
  generateAlertFromEvent: alerts.generateAlertFromEvent,
  getAlerts: alerts.getAlerts,
  getAlertById: alerts.getAlertById,
  updateAlert: alerts.updateAlert,
  getAlertStats: alerts.getAlertStats,

  // Incident exports
  createIncident: incidents.createIncident,
  correlateAlertToIncident: incidents.correlateAlertToIncident,
  getIncidents: incidents.getIncidents,
  getIncidentById: incidents.getIncidentById,
  updateIncident: incidents.updateIncident,
  addInvestigationNote: incidents.addInvestigationNote,
  getIncidentStats: incidents.getIncidentStats,

  // Audit exports
  recordAuditEvent: audit.recordAuditEvent,
  getAuditLogs: audit.getAuditLogs,
  verifyAuditChain: audit.verifyAuditChain
};
