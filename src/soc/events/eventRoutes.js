/**
 * SentinelCore — SOC Event Management Express Routes (v1.0)
 *
 * Implements additive SOC Event Management API endpoints:
 * - GET  /api/soc/events       (Filtered, paginated SOC security event feed)
 * - GET  /api/soc/events/stats (Aggregate SOC event telemetry)
 * - GET  /api/soc/events/:id   (Individual SOC security event inspection)
 * - POST /api/soc/events       (Additive event ingestion endpoint)
 */

const express = require("express");
const { getEvents, getEventById, getEventStats, recordScanEvent } = require("./eventService");

const router = express.Router();

/* ================= 1. GET /api/soc/events ================= */
/**
 * Query filters:
 * - verdict:   "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "INCONCLUSIVE" (or comma-separated)
 * - severity:  "LOW" | "MEDIUM" | "HIGH"
 * - target:    partial substring search (sanitized)
 * - from / to: ISO date strings (e.g. 2026-11-01T00:00:00Z)
 * - page:      integer >= 1 (default 1)
 * - limit:     integer 1-100 (default 20)
 * - sort:      "newest" | "oldest" | "score_desc" | "score_asc"
 */
router.get("/", async (req, res) => {
  try {
    const result = await getEvents(req.query);
    return res.status(200).json(result);
  } catch (err) {
    console.error("SOC events query error:", err.message);
    return res.status(500).json({
      success: false,
      error: "Internal SOC event query failure"
    });
  }
});

/* ================= 2. GET /api/soc/events/stats ================= */
router.get("/stats", async (req, res) => {
  try {
    const stats = await getEventStats();
    return res.status(200).json({
      success: true,
      stats
    });
  } catch (err) {
    console.error("SOC events stats error:", err.message);
    return res.status(500).json({
      success: false,
      error: "Failed to retrieve SOC telemetry statistics"
    });
  }
});

/* ================= 3. GET /api/soc/events/:id ================= */
router.get("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!id || typeof id !== "string" || id.length > 80) {
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
    console.error("SOC event lookup error:", err.message);
    return res.status(500).json({
      success: false,
      error: "Failed to retrieve security event"
    });
  }
});

/* ================= 4. POST /api/soc/events (Additive Ingestion) ================= */
router.post("/", async (req, res) => {
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
        source: "API_INGESTION"
      }
    );

    return res.status(isDuplicate ? 200 : 201).json({
      success: true,
      isDuplicate,
      event
    });
  } catch (err) {
    console.error("SOC event ingestion error:", err.message);
    return res.status(500).json({
      success: false,
      error: "Failed to ingest SOC security event"
    });
  }
});

module.exports = router;
