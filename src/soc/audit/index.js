/**
 * SecuNexis — Immutable Audit Log Module Entry Point (Phase 2.5)
 */

const auditModel = require("./auditModel");
const auditService = require("./auditService");
const auditRouter = require("./auditRoutes");

module.exports = {
  ...auditModel,
  ...auditService,
  auditRouter
};
