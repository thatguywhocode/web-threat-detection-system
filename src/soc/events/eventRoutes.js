/**
 * SentinelCore / SecuNexis — SOC Event Management Express Routes (Hardened Phase 2.5)
 *
 * Implements RBAC-protected SOC Event Management API endpoints:
 * - GET  /api/soc/events       (ADMIN, ANALYST, VIEWER) Filtered, paginated SOC security event feed
 * - GET  /api/soc/events/stats (ADMIN, ANALYST, VIEWER) Aggregate SOC event telemetry
 * - GET  /api/soc/events/:id   (ADMIN, ANALYST, VIEWER) Individual SOC security event inspection
 * - POST /api/soc/events       (ADMIN, ANALYST + CSRF)  Additive event ingestion endpoint
 */

const express = require("express");
const { getEvents, getEventById, getEventStats, recordScanEvent } = require("./eventService");
const { requireAuth, requireRole, verifyCsrf } = require("../auth/authMiddleware");
const { isValidEntityId, sendSafeError } = require("../security/securityMiddleware");

const router = express.Router();

// Protect all SOC event routes behind authentication
router.use(requireAuth);

/* ================= 1. GET /api/soc/events ================= */
router.get("/", requireRole("ADMIN", "ANALYST", "VIEWER"), async (req, res) => {
  try {
    const result = await getEvents(req.query);
    return res.status(200).json(result);
  } catch (err) {
    return sendSafeError(res, 500, "Internal SOC event query failure", err);
  }
});

/* ================= 2. GET /api/soc/events/stats ================= */
router.get("/stats", requireRole("ADMIN", "ANALYST", "VIEWER"), async (req, res) => {
  try {
    const stats = await getEventStats();
    return res.status(200).json({
      success: true,
      stats
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to retrieve SOC telemetry statistics", err);
  }
});

/* ================= 3. GET /api/soc/events/:id ================= */
router.get("/:id", requireRole("ADMIN", "ANALYST", "VIEWER"), async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidEntityId(id)) {
      return res.status(400).json({
        success: false,
        error: "Invalid event ID format"
      });
    }

    const event = await getEventById(id);
    if (!event) {
      return res.status(404).json({
        success: false,
        error: "Security event not found"
      });
    }

    return res.status(200).json({
      success: true,
      event
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to retrieve security event", err);
  }
});

/* ================= 4. POST /api/soc/events (Additive Ingestion) ================= */
router.post("/", requireRole("ADMIN", "ANALYST"), verifyCsrf, async (req, res) => {
  try {
    const { scanInput, scanResult, target, url, html } = req.body || {};

    const resolvedInput = scanInput || { target: target || url, url, html };
    const resolvedResult = scanResult || req.body;

    if (!resolvedInput.target && !resolvedInput.url && !resolvedInput.html) {
      return res.status(400).json({
        success: false,
        error: "Missing scan target or payload in request body"
      });
    }

    const { event, isDuplicate } = await recordScanEvent(
      resolvedInput,
      resolvedResult,
      {
        clientIp: req.ip || req.socket?.remoteAddress || "127.0.0.1",
        userAgent: req.headers["user-agent"] || "",
        source: `API_INGESTION:${req.user.username}`
      }
    );

    return res.status(isDuplicate ? 200 : 201).json({
      success: true,
      isDuplicate,
      event
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to ingest SOC security event", err);
  }
});

module.exports = router;
