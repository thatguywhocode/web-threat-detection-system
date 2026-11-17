/**
 * SecuNexis — SOC Incident Module Entry Point (Phase 2)
 */

const {
  SecurityIncidentSchema,
  MongooseSecurityIncident,
  getSecurityIncidentModel,
  memoryIncidentStore
} = require("./incidentModel");

const {
  extractHostname,
  extractRootDomain,
  determineAttackVector,
  extractExfiltrationEndpoints,
  findCorrelatedIncident,
  elevateSeverity,
  elevatePriority
} = require("./incidentCorrelation");

const {
  createIncident,
  correlateAlertToIncident,
  getIncidents,
  getIncidentById,
  updateIncident,
  addInvestigationNote,
  getIncidentStats
} = require("./incidentService");

const incidentRouter = require("./incidentRoutes");

module.exports = {
  // Model
  SecurityIncidentSchema,
  MongooseSecurityIncident,
  getSecurityIncidentModel,
  memoryIncidentStore,

  // Correlation
  extractHostname,
  extractRootDomain,
  determineAttackVector,
  extractExfiltrationEndpoints,
  findCorrelatedIncident,
  elevateSeverity,
  elevatePriority,

  // Service
  createIncident,
  correlateAlertToIncident,
  getIncidents,
  getIncidentById,
  updateIncident,
  addInvestigationNote,
  getIncidentStats,

  // Router
  incidentRouter
};
