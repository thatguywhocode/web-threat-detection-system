/**
 * SecuNexis — Authentication & RBAC Module Entry Point (Phase 2.5)
 */

const userModel = require("./userModel");
const sessionModel = require("./sessionModel");
const passwordUtils = require("./passwordUtils");
const authService = require("./authService");
const authMiddleware = require("./authMiddleware");
const authRouter = require("./authRoutes");

module.exports = {
  ...userModel,
  ...sessionModel,
  ...passwordUtils,
  ...authService,
  ...authMiddleware,
  authRouter
};
