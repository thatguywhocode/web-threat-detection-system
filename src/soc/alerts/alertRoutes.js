/**
 * SecuNexis — SOC Alert REST API Routes (Hardened Phase 2.5)
 *
 * Enforces authentication, RBAC, CSRF protection, entity ID validation,
 * verified actor attribution, and safe error handling:
 * - GET   /api/soc/alerts       (ADMIN, ANALYST, VIEWER)
 * - GET   /api/soc/alerts/stats (ADMIN, ANALYST, VIEWER)
 * - GET   /api/soc/alerts/:id   (ADMIN, ANALYST, VIEWER)
 * - PATCH /api/soc/alerts/:id   (ADMIN, ANALYST + CSRF)
 */

const express = require("express");
const { getAlerts, getAlertById, updateAlert, getAlertStats } = require("./alertService");
const { requireAuth, requireRole, verifyCsrf } = require("../auth/authMiddleware");
const { isValidEntityId, sendSafeError } = require("../security/securityMiddleware");

const router = express.Router();

// Require authentication on all SOC alert routes
router.use(requireAuth);

router.get("/stats", requireRole("ADMIN", "ANALYST", "VIEWER"), async (req, res) => {
  try {
    const stats = await getAlertStats();
    return res.status(200).json({
      success: true,
      data: stats
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to retrieve alert statistics", err);
  }
});

router.get("/", requireRole("ADMIN", "ANALYST", "VIEWER"), async (req, res) => {
  try {
    const result = await getAlerts(req.query);
    return res.status(200).json({
      success: true,
      data: result.alerts,
      pagination: result.pagination
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to retrieve alerts", err);
  }
});

router.get("/:id", requireRole("ADMIN", "ANALYST", "VIEWER"), async (req, res) => {
  try {
    if (!isValidEntityId(req.params.id)) {
      return res.status(400).json({
        success: false,
        error: "Invalid alert ID format"
      });
    }

    const alert = await getAlertById(req.params.id);
    if (!alert) {
      return res.status(404).json({
        success: false,
        error: "Alert not found"
      });
    }

    return res.status(200).json({
      success: true,
      data: alert
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to retrieve alert", err);
  }
});

router.patch("/:id", requireRole("ADMIN", "ANALYST"), verifyCsrf, async (req, res) => {
  try {
    if (!isValidEntityId(req.params.id)) {
      return res.status(400).json({
        success: false,
        error: "Invalid alert ID format"
      });
    }

    const validStatuses = ["NEW", "ACKNOWLEDGED", "IN_TRIAGE", "DISMISSED", "ESCALATED_TO_INCIDENT"];
    const validPriorities = ["P1_CRITICAL", "P2_HIGH", "P3_MEDIUM", "P4_LOW"];

    const updates = {};
    if (req.body.status !== undefined) {
      if (typeof req.body.status !== "string") {
        return res.status(400).json({ success: false, error: "Invalid status type." });
      }
      const statusUpper = req.body.status.trim().toUpperCase();
      if (!validStatuses.includes(statusUpper)) {
        return res.status(400).json({
          success: false,
          error: `Invalid status. Must be one of: ${validStatuses.join(", ")}`
        });
      }
      updates.status = statusUpper;
    }

    if (req.body.priority !== undefined) {
      if (typeof req.body.priority !== "string") {
        return res.status(400).json({ success: false, error: "Invalid priority type." });
      }
      const priorityUpper = req.body.priority.trim().toUpperCase();
      if (!validPriorities.includes(priorityUpper)) {
        return res.status(400).json({
          success: false,
          error: `Invalid priority. Must be one of: ${validPriorities.join(", ")}`
        });
      }
      updates.priority = priorityUpper;
    }

    if (req.body.incidentId !== undefined) {
      if (req.body.incidentId !== null && !isValidEntityId(req.body.incidentId)) {
        return res.status(400).json({ success: false, error: "Invalid incidentId format." });
      }
      updates.incidentId = req.body.incidentId;
    }

    if (req.body.note !== undefined) {
      if (typeof req.body.note !== "string" || !req.body.note.trim()) {
        return res.status(400).json({ success: false, error: "Note must be a non-empty string." });
      }
      updates.note = req.body.note.trim();
    }

    // Actor is strictly derived from authenticated req.user (prevents spoofing)
    const updated = await updateAlert(req.params.id, updates, req.user, req);

    if (!updated) {
      return res.status(404).json({
        success: false,
        error: "Alert not found"
      });
    }

    return res.status(200).json({
      success: true,
      message: "Alert updated successfully",
      data: updated
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to update alert", err);
  }
});

module.exports = router;
