/**
 * SecuNexis — Authentication & User Management REST API Routes (Phase 2.5)
 *
 * Public endpoints:
 * - GET  /api/auth/status    Checks if first-run admin setup is required
 * - POST /api/auth/setup     One-time first-run ADMIN creation (strictly disabled once any user exists)
 * - POST /api/auth/login     Authenticates user, sets HttpOnly/SameSite/Secure session cookie + returns CSRF token
 *
 * Authenticated endpoints:
 * - GET  /api/auth/me        Returns current user profile, role, session expiry, and CSRF token
 * - POST /api/auth/logout    Revokes session, clears cookie, requires CSRF token when cookie-authenticated
 *
 * Admin-only endpoints (RBAC: ADMIN):
 * - GET    /api/auth/users       List all SOC accounts (sanitized, no password hashes)
 * - POST   /api/auth/users       Create a new ADMIN, ANALYST, or VIEWER user
 * - PATCH  /api/auth/users/:id   Update user role, active status, unlock lockout, or reset password
 * - DELETE /api/auth/users/:id   Delete user account and revoke all active sessions
 */

const express = require("express");
const {
  isSetupRequired,
  setupInitialAdmin,
  login,
  logout,
  createUser,
  listUsers,
  updateUser,
  deleteUser
} = require("./authService");
const {
  setSessionCookie,
  clearSessionCookie,
  requireAuth,
  requireRole,
  verifyCsrf,
  loginRateLimiter
} = require("./authMiddleware");
const { isValidEntityId, sendSafeError } = require("../security/securityMiddleware");

const router = express.Router();

/**
 * GET /api/auth/status
 */
router.get("/status", async (req, res) => {
  try {
    const setupRequired = await isSetupRequired();
    return res.status(200).json({
      success: true,
      data: {
        setupRequired,
        authenticated: Boolean(req.user)
      }
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to determine authentication status", err);
  }
});

/**
 * POST /api/auth/setup
 * One-time bootstrap ONLY when 0 users exist in database
 */
router.post("/setup", loginRateLimiter, async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body || {};
    const result = await setupInitialAdmin({ username, email, password, displayName }, req);
    if (!result.success) {
      return res.status(result.statusCode || 400).json({
        success: false,
        error: result.error
      });
    }

    return res.status(201).json({
      success: true,
      message: "Initial SOC Administrator account created. You may now sign in.",
      data: { user: result.user }
    });
  } catch (err) {
    return sendSafeError(res, 500, "Initial setup failed", err);
  }
});

/**
 * POST /api/auth/login
 */
router.post("/login", loginRateLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const result = await login({ username, password }, req);

    if (!result.success) {
      return res.status(result.statusCode || 401).json({
        success: false,
        error: result.error
      });
    }

    setSessionCookie(req, res, result.rawToken, result.expiresAt);

    return res.status(200).json({
      success: true,
      data: {
        user: result.user,
        csrfToken: result.csrfToken,
        expiresAt: result.expiresAt
      }
    });
  } catch (err) {
    return sendSafeError(res, 500, "Authentication service error", err);
  }
});

/**
 * GET /api/auth/me
 */
router.get("/me", requireAuth, (req, res) => {
  return res.status(200).json({
    success: true,
    data: {
      user: req.user,
      csrfToken: req.session.csrfToken,
      expiresAt: req.session.expiresAt
    }
  });
});

/**
 * POST /api/auth/logout
 */
router.post("/logout", requireAuth, verifyCsrf, async (req, res) => {
  try {
    await logout(req.rawSessionToken, req);
    clearSessionCookie(req, res);
    return res.status(200).json({
      success: true,
      message: "Logged out successfully."
    });
  } catch (err) {
    return sendSafeError(res, 500, "Logout failed", err);
  }
});

/* ================= ADMIN USER MANAGEMENT ================= */

router.get("/users", requireAuth, requireRole("ADMIN"), async (req, res) => {
  try {
    const users = await listUsers();
    return res.status(200).json({
      success: true,
      data: users
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to retrieve users", err);
  }
});

router.post("/users", requireAuth, requireRole("ADMIN"), verifyCsrf, async (req, res) => {
  try {
    const { username, email, password, displayName, role } = req.body || {};
    const result = await createUser(
      { username, email, password, displayName, role },
      req.user,
      req
    );
    if (!result.success) {
      return res.status(result.statusCode || 400).json({
        success: false,
        error: result.error
      });
    }
    return res.status(201).json({
      success: true,
      message: "User created successfully.",
      data: result.user
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to create user", err);
  }
});

router.patch("/users/:id", requireAuth, requireRole("ADMIN"), verifyCsrf, async (req, res) => {
  try {
    if (!isValidEntityId(req.params.id)) {
      return res.status(400).json({ success: false, error: "Invalid user ID format." });
    }
    const result = await updateUser(req.params.id, req.body || {}, req.user, req);
    if (!result.success) {
      return res.status(result.statusCode || 400).json({
        success: false,
        error: result.error
      });
    }
    return res.status(200).json({
      success: true,
      message: "User updated successfully.",
      data: result.user
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to update user", err);
  }
});

router.delete("/users/:id", requireAuth, requireRole("ADMIN"), verifyCsrf, async (req, res) => {
  try {
    if (!isValidEntityId(req.params.id)) {
      return res.status(400).json({ success: false, error: "Invalid user ID format." });
    }
    const result = await deleteUser(req.params.id, req.user, req);
    if (!result.success) {
      return res.status(result.statusCode || 400).json({
        success: false,
        error: result.error
      });
    }
    return res.status(200).json({
      success: true,
      message: "User deleted successfully."
    });
  } catch (err) {
    return sendSafeError(res, 500, "Failed to delete user", err);
  }
});

module.exports = router;
