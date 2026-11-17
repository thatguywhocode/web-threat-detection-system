/**
 * SecuNexis — Enterprise SOC Authentication & RBAC Service (Phase 2.5)
 *
 * Implements:
 * - Zero hardcoded passwords or secrets (bootstrap via ENV or first-run setup only)
 * - Bcrypt password hashing with complexity validation and timing-equalized verification
 * - Brute-force account lockout (5 failed attempts -> 15-minute lockout)
 * - Server-side opaque session management with SHA-256 token hashing & per-session CSRF token
 * - Session expiration enforcement, instant logout invalidation, and role-change revocation
 * - Immutable audit logging for every authentication and user lifecycle event
 */

const crypto = require("crypto");
const { getUserModel, VALID_ROLES, sanitizeUser } = require("./userModel");
const { getSessionModel } = require("./sessionModel");
const {
  validatePasswordStrength,
  hashPassword,
  verifyPassword,
  equalizeTiming
} = require("./passwordUtils");
const { recordAuditEvent } = require("../audit/auditService");

const MAX_FAILED_ATTEMPTS = parseInt(process.env.AUTH_MAX_FAILED_ATTEMPTS, 10) || 5;
const LOCKOUT_DURATION_MS = parseInt(process.env.AUTH_LOCKOUT_DURATION_MS, 10) || (15 * 60 * 1000);
const DEFAULT_SESSION_TTL_MS = parseInt(process.env.SESSION_TTL_MS, 10) || (8 * 60 * 60 * 1000); // 8 hours

function hashToken(rawToken) {
  return crypto.createHash("sha256").update(String(rawToken)).digest("hex");
}

function generateSecureToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

function isValidUsername(username) {
  return typeof username === "string" && /^[a-zA-Z0-9._-]{3,50}$/.test(username.trim());
}

function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) && email.length <= 120;
}

/**
 * Checks whether initial first-run admin setup is required (0 users exist)
 */
async function isSetupRequired() {
  const UserModel = getUserModel();
  const count = await UserModel.countDocuments({});
  return count === 0;
}

/**
 * Bootstraps initial ADMIN account strictly from environment variables if 0 users exist.
 * Never embeds hardcoded passwords in source code.
 */
async function bootstrapInitialAdminFromEnv() {
  const username = (process.env.INITIAL_ADMIN_USERNAME || "").trim().toLowerCase();
  const email = (process.env.INITIAL_ADMIN_EMAIL || "").trim().toLowerCase() || (username ? `${username}@secunexis.local` : "");
  const password = process.env.INITIAL_ADMIN_PASSWORD || "";

  if (!username || !password) {
    return { bootstrapped: false, reason: "ENV_NOT_CONFIGURED" };
  }

  const UserModel = getUserModel();
  const existingCount = await UserModel.countDocuments({});
  if (existingCount > 0) {
    return { bootstrapped: false, reason: "USERS_ALREADY_EXIST" };
  }

  const pwCheck = validatePasswordStrength(password);
  if (!pwCheck.valid) {
    console.warn(`[SecuNexis Auth] INITIAL_ADMIN_PASSWORD does not meet complexity policy: ${pwCheck.error}`);
    return { bootstrapped: false, reason: "WEAK_ENV_PASSWORD" };
  }

  const passwordHash = await hashPassword(password);
  const created = await UserModel.create({
    username,
    email,
    displayName: "Primary SOC Administrator",
    passwordHash,
    role: "ADMIN",
    active: true,
    createdBy: "env_bootstrap"
  });

  await recordAuditEvent({
    actor: { userId: "system", username: "system", role: "SYSTEM" },
    action: "AUTH_BOOTSTRAP_ADMIN",
    entityType: "USER",
    entityId: created.userId,
    outcome: "SUCCESS",
    details: `Bootstrapped initial ADMIN account '${created.username}' from environment configuration.`
  });

  console.log(`[SecuNexis Auth] Bootstrapped initial ADMIN user '${created.username}' from environment.`);
  return { bootstrapped: true, user: sanitizeUser(created) };
}

/**
 * One-time first-run setup to create the initial ADMIN user ONLY when 0 users exist.
 */
async function setupInitialAdmin({ username, email, password, displayName }, req = null) {
  const UserModel = getUserModel();
  const count = await UserModel.countDocuments({});
  if (count > 0) {
    return {
      success: false,
      statusCode: 403,
      error: "Initial setup is disabled because at least one user account already exists."
    };
  }

  if (!isValidUsername(username)) {
    return { success: false, statusCode: 400, error: "Username must be 3-50 characters (alphanumeric, ., _, -)." };
  }
  if (!isValidEmail(email)) {
    return { success: false, statusCode: 400, error: "A valid email address is required." };
  }
  const pwCheck = validatePasswordStrength(password);
  if (!pwCheck.valid) {
    return { success: false, statusCode: 400, error: pwCheck.error };
  }

  const passwordHash = await hashPassword(password);
  const created = await UserModel.create({
    username: username.trim().toLowerCase(),
    email: email.trim().toLowerCase(),
    displayName: (displayName || username).trim().slice(0, 80),
    passwordHash,
    role: "ADMIN",
    active: true,
    createdBy: "first_run_setup"
  });

  await recordAuditEvent({
    actor: { userId: created.userId, username: created.username, role: "ADMIN" },
    req,
    action: "AUTH_SETUP_ADMIN",
    entityType: "USER",
    entityId: created.userId,
    outcome: "SUCCESS",
    details: `Initial ADMIN account '${created.username}' provisioned via first-run setup.`
  });

  return { success: true, user: sanitizeUser(created) };
}

/**
 * Authenticates a user, enforces brute-force lockout, and creates an opaque server-side session.
 */
async function login({ username, password, sessionTtlMs }, req = null) {
  const normalizedUser = typeof username === "string" ? username.trim().toLowerCase() : "";
  if (!normalizedUser || typeof password !== "string" || !password) {
    return { success: false, statusCode: 400, error: "Username and password are required." };
  }

  const UserModel = getUserModel();
  const user = await UserModel.findOne({
    $or: [{ username: normalizedUser }, { email: normalizedUser }]
  }).select("+passwordHash");

  if (!user) {
    await equalizeTiming(password);
    await recordAuditEvent({
      actor: { userId: "anonymous", username: normalizedUser, role: "NONE" },
      req,
      action: "AUTH_LOGIN_FAILED",
      entityType: "AUTH",
      entityId: normalizedUser,
      outcome: "FAILURE",
      details: "Login failed: unknown username or email."
    });
    return { success: false, statusCode: 401, error: "Invalid username or password." };
  }

  if (!user.active) {
    await equalizeTiming(password);
    await recordAuditEvent({
      actor: { userId: user.userId, username: user.username, role: user.role },
      req,
      action: "AUTH_LOGIN_FAILED",
      entityType: "USER",
      entityId: user.userId,
      outcome: "DENIED",
      details: "Login denied: account is deactivated."
    });
    return { success: false, statusCode: 401, error: "Invalid username or password." };
  }

  // Check active brute-force lockout
  if (user.lockUntil && new Date(user.lockUntil).getTime() > Date.now()) {
    await recordAuditEvent({
      actor: { userId: user.userId, username: user.username, role: user.role },
      req,
      action: "AUTH_LOGIN_FAILED",
      entityType: "USER",
      entityId: user.userId,
      outcome: "DENIED",
      details: "Login blocked: account is temporarily locked due to brute-force protection."
    });
    return {
      success: false,
      statusCode: 423,
      error: "Account temporarily locked due to repeated failed login attempts. Please try again later."
    };
  }

  const passwordValid = await verifyPassword(password, user.passwordHash);
  if (!passwordValid) {
    const nextAttempts = (user.failedLoginAttempts || 0) + 1;
    const shouldLock = nextAttempts >= MAX_FAILED_ATTEMPTS;
    const lockUntil = shouldLock ? new Date(Date.now() + LOCKOUT_DURATION_MS) : null;

    await UserModel.findOneAndUpdate(
      { userId: user.userId },
      {
        $set: {
          failedLoginAttempts: nextAttempts,
          lockUntil
        }
      },
      { new: true }
    );

    await recordAuditEvent({
      actor: { userId: user.userId, username: user.username, role: user.role },
      req,
      action: shouldLock ? "AUTH_ACCOUNT_LOCKED" : "AUTH_LOGIN_FAILED",
      entityType: "USER",
      entityId: user.userId,
      outcome: "FAILURE",
      details: shouldLock
        ? `Account locked for ${Math.round(LOCKOUT_DURATION_MS / 60000)} minutes after ${nextAttempts} consecutive failed logins.`
        : `Invalid password attempt (${nextAttempts}/${MAX_FAILED_ATTEMPTS}).`
    });

    if (shouldLock) {
      return {
        success: false,
        statusCode: 423,
        error: "Account temporarily locked due to repeated failed login attempts. Please try again later."
      };
    }

    return { success: false, statusCode: 401, error: "Invalid username or password." };
  }

  // Successful authentication: reset lockout counters & create opaque session
  await UserModel.findOneAndUpdate(
    { userId: user.userId },
    {
      $set: {
        failedLoginAttempts: 0,
        lockUntil: null,
        lastLoginAt: new Date()
      }
    },
    { new: true }
  );

  const ttl = typeof sessionTtlMs === "number" && sessionTtlMs > 0 ? sessionTtlMs : DEFAULT_SESSION_TTL_MS;
  const rawToken = generateSecureToken(32);
  const csrfToken = generateSecureToken(32);
  const expiresAt = new Date(Date.now() + ttl);

  const SessionModel = getSessionModel();
  const session = await SessionModel.create({
    tokenHash: hashToken(rawToken),
    csrfToken,
    userId: user.userId,
    username: user.username,
    role: user.role,
    ipAddress: req?.ip || req?.socket?.remoteAddress || "",
    userAgent: (req?.headers?.["user-agent"] || "").slice(0, 200),
    revoked: false,
    expiresAt,
    lastActivityAt: new Date()
  });

  const cleanUser = sanitizeUser({ ...user, failedLoginAttempts: 0, lockUntil: null, lastLoginAt: new Date() });

  await recordAuditEvent({
    actor: { userId: cleanUser.userId, username: cleanUser.username, role: cleanUser.role },
    req,
    action: "AUTH_LOGIN_SUCCESS",
    entityType: "SESSION",
    entityId: session.sessionId,
    outcome: "SUCCESS",
    details: `User '${cleanUser.username}' (${cleanUser.role}) authenticated successfully.`
  });

  return {
    success: true,
    user: cleanUser,
    rawToken,
    csrfToken,
    sessionId: session.sessionId,
    expiresAt
  };
}

/**
 * Validates an opaque session token against the server-side session store.
 */
async function validateSession(rawToken, req = null) {
  if (!rawToken || typeof rawToken !== "string") {
    return { valid: false, reason: "MISSING_TOKEN" };
  }

  const SessionModel = getSessionModel();
  const tokenHash = hashToken(rawToken);
  const session = await SessionModel.findOne({ tokenHash });

  if (!session) {
    return { valid: false, reason: "SESSION_NOT_FOUND" };
  }

  if (session.revoked) {
    return { valid: false, reason: "SESSION_REVOKED" };
  }

  if (new Date(session.expiresAt).getTime() <= Date.now()) {
    await SessionModel.findOneAndUpdate(
      { sessionId: session.sessionId },
      { $set: { revoked: true } }
    );
    await recordAuditEvent({
      actor: { userId: session.userId, username: session.username, role: session.role },
      req,
      action: "AUTH_SESSION_EXPIRED",
      entityType: "SESSION",
      entityId: session.sessionId,
      outcome: "DENIED",
      details: `Session '${session.sessionId}' expired and was invalidated.`
    });
    return { valid: false, reason: "SESSION_EXPIRED" };
  }

  // Re-verify live user state and role from User store
  const UserModel = getUserModel();
  const user = await UserModel.findOne({ userId: session.userId });
  if (!user || !user.active) {
    await SessionModel.findOneAndUpdate(
      { sessionId: session.sessionId },
      { $set: { revoked: true } }
    );
    return { valid: false, reason: "USER_INACTIVE" };
  }

  await SessionModel.findOneAndUpdate(
    { sessionId: session.sessionId },
    { $set: { lastActivityAt: new Date(), role: user.role } }
  );

  return {
    valid: true,
    user: sanitizeUser(user),
    session: {
      sessionId: session.sessionId,
      csrfToken: session.csrfToken,
      expiresAt: session.expiresAt,
      userId: user.userId,
      role: user.role
    }
  };
}

/**
 * Immediately revokes and removes a session on logout
 */
async function logout(rawToken, req = null) {
  if (!rawToken) return { success: true };

  const SessionModel = getSessionModel();
  const tokenHash = hashToken(rawToken);
  const session = await SessionModel.findOne({ tokenHash });

  if (session) {
    await SessionModel.findOneAndUpdate(
      { sessionId: session.sessionId },
      { $set: { revoked: true } }
    );
    await SessionModel.deleteOne({ sessionId: session.sessionId });

    await recordAuditEvent({
      actor: { userId: session.userId, username: session.username, role: session.role },
      req,
      action: "AUTH_LOGOUT",
      entityType: "SESSION",
      entityId: session.sessionId,
      outcome: "SUCCESS",
      details: `User '${session.username}' logged out and session was invalidated.`
    });
  }

  return { success: true };
}

/**
 * Revokes all active sessions for a given userId (on role change, deactivation, or password reset)
 */
async function revokeAllUserSessions(userId) {
  const SessionModel = getSessionModel();
  await SessionModel.updateMany({ userId }, { $set: { revoked: true } });
  await SessionModel.deleteMany({ userId });
}

/* ================= USER MANAGEMENT (ADMIN ONLY) ================= */

async function createUser({ username, email, password, displayName, role = "VIEWER" }, actor = {}, req = null) {
  if (!isValidUsername(username)) {
    return { success: false, statusCode: 400, error: "Username must be 3-50 characters (alphanumeric, ., _, -)." };
  }
  if (!isValidEmail(email)) {
    return { success: false, statusCode: 400, error: "A valid email address is required." };
  }
  const normalizedRole = String(role || "VIEWER").toUpperCase();
  if (!VALID_ROLES.includes(normalizedRole)) {
    return { success: false, statusCode: 400, error: `Role must be one of: ${VALID_ROLES.join(", ")}` };
  }
  const pwCheck = validatePasswordStrength(password);
  if (!pwCheck.valid) {
    return { success: false, statusCode: 400, error: pwCheck.error };
  }

  const UserModel = getUserModel();
  const passwordHash = await hashPassword(password);

  try {
    const created = await UserModel.create({
      username: username.trim().toLowerCase(),
      email: email.trim().toLowerCase(),
      displayName: (displayName || username).trim().slice(0, 80),
      passwordHash,
      role: normalizedRole,
      active: true,
      createdBy: actor?.username || "admin"
    });

    const clean = sanitizeUser(created);
    await recordAuditEvent({
      actor,
      req,
      action: "USER_CREATED",
      entityType: "USER",
      entityId: clean.userId,
      outcome: "SUCCESS",
      details: `Created user '${clean.username}' with role '${clean.role}'.`,
      newState: { username: clean.username, email: clean.email, role: clean.role, active: clean.active }
    });

    return { success: true, user: clean };
  } catch (err) {
    if (err.code === 11000) {
      return { success: false, statusCode: 409, error: "A user with that username or email already exists." };
    }
    throw err;
  }
}

async function listUsers() {
  const UserModel = getUserModel();
  const users = await UserModel.find({}).sort({ createdAt: -1 }).lean();
  return users.map(sanitizeUser);
}

async function updateUser(userId, updates = {}, actor = {}, req = null) {
  const UserModel = getUserModel();
  const existing = await UserModel.findOne({ userId });
  if (!existing) {
    return { success: false, statusCode: 404, error: "User not found." };
  }

  const patch = {};
  let mustRevokeSessions = false;

  if (updates.role !== undefined) {
    const newRole = String(updates.role).toUpperCase();
    if (!VALID_ROLES.includes(newRole)) {
      return { success: false, statusCode: 400, error: `Invalid role. Must be one of: ${VALID_ROLES.join(", ")}` };
    }
    // Prevent demoting the last active ADMIN
    if (existing.role === "ADMIN" && newRole !== "ADMIN") {
      const adminCount = await UserModel.countDocuments({ role: "ADMIN", active: true });
      if (adminCount <= 1) {
        return { success: false, statusCode: 400, error: "Cannot demote the last active ADMIN account." };
      }
    }
    if (newRole !== existing.role) {
      patch.role = newRole;
      mustRevokeSessions = true;
    }
  }

  if (updates.active !== undefined) {
    const nextActive = Boolean(updates.active);
    if (existing.role === "ADMIN" && existing.active && !nextActive) {
      const adminCount = await UserModel.countDocuments({ role: "ADMIN", active: true });
      if (adminCount <= 1) {
        return { success: false, statusCode: 400, error: "Cannot deactivate the last active ADMIN account." };
      }
    }
    if (actor?.userId && actor.userId === existing.userId && !nextActive) {
      return { success: false, statusCode: 400, error: "Administrators cannot deactivate their own account." };
    }
    patch.active = nextActive;
    if (!nextActive) mustRevokeSessions = true;
  }

  if (updates.displayName !== undefined && typeof updates.displayName === "string") {
    patch.displayName = updates.displayName.trim().slice(0, 80);
  }

  if (updates.unlock === true) {
    patch.failedLoginAttempts = 0;
    patch.lockUntil = null;
  }

  if (updates.password !== undefined && updates.password !== "") {
    const pwCheck = validatePasswordStrength(updates.password);
    if (!pwCheck.valid) {
      return { success: false, statusCode: 400, error: pwCheck.error };
    }
    patch.passwordHash = await hashPassword(updates.password);
    patch.failedLoginAttempts = 0;
    patch.lockUntil = null;
    mustRevokeSessions = true;
  }

  const updated = await UserModel.findOneAndUpdate(
    { userId },
    { $set: patch },
    { new: true }
  );

  if (mustRevokeSessions) {
    await revokeAllUserSessions(userId);
  }

  const clean = sanitizeUser(updated);
  await recordAuditEvent({
    actor,
    req,
    action: "USER_UPDATED",
    entityType: "USER",
    entityId: userId,
    outcome: "SUCCESS",
    details: `Updated user '${existing.username}'.`,
    previousState: { role: existing.role, active: existing.active, displayName: existing.displayName },
    newState: { role: clean.role, active: clean.active, displayName: clean.displayName, passwordReset: Boolean(patch.passwordHash) }
  });

  return { success: true, user: clean };
}

async function deleteUser(userId, actor = {}, req = null) {
  const UserModel = getUserModel();
  const existing = await UserModel.findOne({ userId });
  if (!existing) {
    return { success: false, statusCode: 404, error: "User not found." };
  }

  if (actor?.userId && actor.userId === existing.userId) {
    return { success: false, statusCode: 400, error: "Administrators cannot delete their own account." };
  }

  if (existing.role === "ADMIN" && existing.active) {
    const adminCount = await UserModel.countDocuments({ role: "ADMIN", active: true });
    if (adminCount <= 1) {
      return { success: false, statusCode: 400, error: "Cannot delete the last active ADMIN account." };
    }
  }

  await revokeAllUserSessions(userId);
  await UserModel.deleteOne({ userId });

  await recordAuditEvent({
    actor,
    req,
    action: "USER_DELETED",
    entityType: "USER",
    entityId: userId,
    outcome: "SUCCESS",
    details: `Deleted user '${existing.username}' (${existing.role}).`,
    previousState: { username: existing.username, email: existing.email, role: existing.role }
  });

  return { success: true };
}

module.exports = {
  MAX_FAILED_ATTEMPTS,
  LOCKOUT_DURATION_MS,
  DEFAULT_SESSION_TTL_MS,
  hashToken,
  isSetupRequired,
  bootstrapInitialAdminFromEnv,
  setupInitialAdmin,
  login,
  validateSession,
  logout,
  revokeAllUserSessions,
  createUser,
  listUsers,
  updateUser,
  deleteUser
};
