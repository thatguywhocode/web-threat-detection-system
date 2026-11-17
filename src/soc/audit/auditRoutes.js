/**
 * SecuNexis — Immutable Audit Log REST API Routes (Phase 2.5)
 *
 * Exposes read-only audit log endpoints:
 * - GET /api/soc/audit         Paginated, filtered audit trail (ADMIN, ANALYST)
 * - GET /api/soc/audit/verify  Cryptographic hash-chain integrity check (ADMIN only)
 *
 * Explicitly denies all mutating HTTP verbs (POST, PUT, PATCH, DELETE) with 403 Forbidden
 * to guarantee audit record immutability for all users.
 */

const express = require("express");
const { getAuditLogs, verifyAuditChain, recordAuditEvent } = require("./auditService");
const { requireAuth, requireRole } = require("../auth/authMiddleware");
const { sendSafeError } = require("../security/securityMiddleware");

const router = express.Router();

// All audit log endpoints require authentication
router.use(requireAuth);

/**
 * GET /api/soc/audit/verify
 * Verifies SHA-256 cryptographic hash chain integrity (ADMIN only)
 */
router.get("/verify", requireRole("ADMIN"), async (req, res) => {
  try {
    const report = await verifyAuditChain();
    return res.status(200).json({
      success: true,
      data: report
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to verify audit log integrity", err);
  }
});

/**
 * GET /api/soc/audit
 * Queries immutable audit logs (ADMIN & ANALYST read-only access; VIEWER denied)
 */
router.get("/", requireRole("ADMIN", "ANALYST"), async (req, res) => {
  try {
    const result = await getAuditLogs(req.query);
    return res.status(200).json({
      success: true,
      data: result.logs,
      pagination: result.pagination
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to retrieve audit logs", err);
  }
});

/**
 * Explicitly block any attempt to modify or delete audit logs
 */
const denyMutation = async (req, res) => {
  await recordAuditEvent({
    actor: req.user,
    req,
    action: "AUDIT_TAMPER_ATTEMPT",
    entityType: "AUDIT_LOG",
    entityId: req.params?.id || "collection",
    outcome: "DENIED",
    details: `Blocked ${req.method} attempt against immutable audit log endpoint.`
  }).catch(() => {});

  return res.status(403).json({
    success: false,
    error: "Audit logs are strictly immutable and cannot be created, edited, or deleted via API.",
    code: "AUDIT_IMMUTABLE"
  });
};

router.post("/", denyMutation);
router.put("/", denyMutation);
router.patch("/", denyMutation);
router.delete("/", denyMutation);
router.put("/:id", denyMutation);
router.patch("/:id", denyMutation);
router.delete("/:id", denyMutation);

module.exports = router;
