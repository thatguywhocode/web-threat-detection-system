/**
 * SecuNexis — SOC Incident REST API Routes (Hardened Phase 2.5)
 *
 * Enforces authentication, RBAC, CSRF protection, entity ID validation,
 * verified actor attribution, and safe error handling:
 * - GET  /api/soc/incidents           (ADMIN, ANALYST, VIEWER)
 * - GET  /api/soc/incidents/stats     (ADMIN, ANALYST, VIEWER)
 * - GET  /api/soc/incidents/:id       (ADMIN, ANALYST, VIEWER)
 * - POST /api/soc/incidents           (ADMIN, ANALYST + CSRF)
 * - PATCH /api/soc/incidents/:id      (ADMIN, ANALYST + CSRF)
 * - POST /api/soc/incidents/:id/notes (ADMIN, ANALYST + CSRF)
 */

const express = require("express");
const {
  createIncident,
  getIncidents,
  getIncidentById,
  updateIncident,
  addInvestigationNote,
  getIncidentStats
} = require("./incidentService");
const { requireAuth, requireRole, verifyCsrf } = require("../auth/authMiddleware");
const { isValidEntityId, sendSafeError } = require("../security/securityMiddleware");

const router = express.Router();

// Require authentication on all SOC incident routes
router.use(requireAuth);

router.get("/stats", requireRole("ADMIN", "ANALYST", "VIEWER"), async (req, res) => {
  try {
    const stats = await getIncidentStats();
    return res.status(200).json({
      success: true,
      data: stats
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to retrieve incident statistics", err);
  }
});

router.get("/", requireRole("ADMIN", "ANALYST", "VIEWER"), async (req, res) => {
  try {
    const result = await getIncidents(req.query);
    return res.status(200).json({
      success: true,
      data: result.incidents,
      pagination: result.pagination
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to retrieve incidents", err);
  }
});

router.post("/", requireRole("ADMIN", "ANALYST"), verifyCsrf, async (req, res) => {
  try {
    if (!req.body || typeof req.body.title !== "string" || !req.body.title.trim()) {
      return res.status(400).json({
        success: false,
        error: "Missing required field: title"
      });
    }

    const validSeverities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    const validPriorities = ["P1_CRITICAL", "P2_HIGH", "P3_MEDIUM", "P4_LOW"];
    const validVectors = [
      "CREDENTIAL_HARVESTING",
      "DRIVE_BY_DOWNLOAD",
      "MALICIOUS_REPUTATION",
      "SUSPICIOUS_OBFUSCATION",
      "HIDDEN_ELEMENT_EXPLOIT",
      "PHISHING_CAMPAIGN",
      "ANOMALY_UNKNOWN"
    ];

    if (req.body.severity && !validSeverities.includes(String(req.body.severity).toUpperCase())) {
      return res.status(400).json({ success: false, error: `Invalid severity.` });
    }
    if (req.body.priority && !validPriorities.includes(String(req.body.priority).toUpperCase())) {
      return res.status(400).json({ success: false, error: `Invalid priority.` });
    }
    if (req.body.attackVector && !validVectors.includes(String(req.body.attackVector).toUpperCase())) {
      return res.status(400).json({ success: false, error: `Invalid attackVector.` });
    }

    const incident = await createIncident(req.body, req.user, req);
    return res.status(201).json({
      success: true,
      message: "Incident created successfully",
      data: incident
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to create incident", err);
  }
});

router.get("/:id", requireRole("ADMIN", "ANALYST", "VIEWER"), async (req, res) => {
  try {
    if (!isValidEntityId(req.params.id)) {
      return res.status(400).json({
        success: false,
        error: "Invalid incident ID format"
      });
    }

    const incident = await getIncidentById(req.params.id);
    if (!incident) {
      return res.status(404).json({
        success: false,
        error: "Incident not found"
      });
    }

    return res.status(200).json({
      success: true,
      data: incident
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to retrieve incident", err);
  }
});

router.patch("/:id", requireRole("ADMIN", "ANALYST"), verifyCsrf, async (req, res) => {
  try {
    if (!isValidEntityId(req.params.id)) {
      return res.status(400).json({
        success: false,
        error: "Invalid incident ID format"
      });
    }

    const validStatuses = ["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"];
    const validSeverities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    const validPriorities = ["P1_CRITICAL", "P2_HIGH", "P3_MEDIUM", "P4_LOW"];

    if (req.body.status !== undefined) {
      if (typeof req.body.status !== "string" || !validStatuses.includes(req.body.status.trim().toUpperCase())) {
        return res.status(400).json({
          success: false,
          error: `Invalid status. Must be one of: ${validStatuses.join(", ")}`
        });
      }
    }

    if (req.body.severity !== undefined) {
      if (typeof req.body.severity !== "string" || !validSeverities.includes(req.body.severity.trim().toUpperCase())) {
        return res.status(400).json({
          success: false,
          error: `Invalid severity. Must be one of: ${validSeverities.join(", ")}`
        });
      }
    }

    if (req.body.priority !== undefined) {
      if (typeof req.body.priority !== "string" || !validPriorities.includes(req.body.priority.trim().toUpperCase())) {
        return res.status(400).json({
          success: false,
          error: `Invalid priority. Must be one of: ${validPriorities.join(", ")}`
        });
      }
    }

    // Actor is strictly derived from authenticated req.user
    const updated = await updateIncident(req.params.id, req.body || {}, req.user, req);

    if (!updated) {
      return res.status(404).json({
        success: false,
        error: "Incident not found"
      });
    }

    return res.status(200).json({
      success: true,
      message: "Incident updated successfully",
      data: updated
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to update incident", err);
  }
});

router.post("/:id/notes", requireRole("ADMIN", "ANALYST"), verifyCsrf, async (req, res) => {
  try {
    if (!isValidEntityId(req.params.id)) {
      return res.status(400).json({
        success: false,
        error: "Invalid incident ID format"
      });
    }

    if (!req.body || typeof req.body.text !== "string" || !req.body.text.trim()) {
      return res.status(400).json({
        success: false,
        error: "Missing required field: text (investigation note cannot be empty)"
      });
    }

    // Actor is strictly derived from authenticated req.user (prevents spoofing)
    const updated = await addInvestigationNote(
      req.params.id,
      { text: req.body.text },
      req.user,
      req
    );

    if (!updated) {
      return res.status(404).json({
        success: false,
        error: "Incident not found"
      });
    }

    return res.status(201).json({
      success: true,
      message: "Investigation note added successfully",
      data: updated
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to add investigation note", err);
  }
});

module.exports = router;
