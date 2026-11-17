/**
 * SecuNexis — Authentication, RBAC, CSRF & Brute-Force Protection Middleware (Phase 2.5)
 *
 * Enforces backend security controls:
 * - Zero-dependency cookie parsing & Secure/HttpOnly/SameSite cookie configuration
 * - Server-side session verification (cookie or Bearer token)
 * - Strict Role-Based Access Control (ADMIN, ANALYST, VIEWER) with audit logging of denials
 * - Timing-safe per-session CSRF token validation on cookie-authenticated state changes
 * - Dedicated IP-based login brute-force rate limiter
 */

const crypto = require("crypto");
const { validateSession } = require("./authService");
const { recordAuditEvent } = require("../audit/auditService");

const SESSION_COOKIE_NAME = "secunexis_sid";
const SAFE_HTTP_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/* ================= 1. COOKIE UTILITIES ================= */
function parseCookies(cookieHeader = "") {
  const cookies = {};
  if (typeof cookieHeader !== "string" || !cookieHeader) return cookies;

  cookieHeader.split(";").forEach(pair => {
    const idx = pair.indexOf("=");
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (!key) return;
    try {
      cookies[key] = decodeURIComponent(val);
    } catch {
      cookies[key] = val;
    }
  });
  return cookies;
}

function buildCookieHeader(name, value, { maxAgeSeconds, httpOnly = true, secure = false, sameSite = "Strict", path = "/" } = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${path}`, `SameSite=${sameSite}`];
  if (typeof maxAgeSeconds === "number") {
    parts.push(`Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`);
  }
  if (httpOnly) parts.push("HttpOnly");
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

function isSecureRequest(req) {
  if (process.env.COOKIE_SECURE === "false") return false;
  if (process.env.NODE_ENV === "production") return true;
  if (req && (req.secure || req.headers["x-forwarded-proto"] === "https")) return true;
  return false;
}

function setSessionCookie(req, res, rawToken, expiresAt) {
  const maxAgeSeconds = Math.max(1, Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000));
  const sameSite = process.env.COOKIE_SAMESITE || "Strict";
  const cookieVal = buildCookieHeader(SESSION_COOKIE_NAME, rawToken, {
    maxAgeSeconds,
    httpOnly: true,
    secure: isSecureRequest(req),
    sameSite,
    path: "/"
  });
  res.setHeader("Set-Cookie", cookieVal);
}

function clearSessionCookie(req, res) {
  const sameSite = process.env.COOKIE_SAMESITE || "Strict";
  const cookieVal = buildCookieHeader(SESSION_COOKIE_NAME, "", {
    maxAgeSeconds: 0,
    httpOnly: true,
    secure: isSecureRequest(req),
    sameSite,
    path: "/"
  });
  res.setHeader("Set-Cookie", cookieVal);
}

/* ================= 2. SESSION EXTRACTION & VERIFICATION ================= */
function extractSessionToken(req) {
  const cookies = parseCookies(req.headers?.cookie || "");
  if (cookies[SESSION_COOKIE_NAME]) {
    return { token: cookies[SESSION_COOKIE_NAME], method: "cookie" };
  }

  const authHeader = req.headers?.authorization || "";
  if (typeof authHeader === "string" && authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice(7).trim();
    if (token) return { token, method: "bearer" };
  }

  return { token: null, method: null };
}

/**
 * Attaches authenticated user & session context if a valid token is present.
 * Does not block unauthenticated requests on its own.
 */
async function attachAuthContext(req, res, next) {
  try {
    const { token, method } = extractSessionToken(req);
    if (!token) {
      req.user = null;
      req.session = null;
      req.authMethod = null;
      req.authFailureReason = "MISSING_TOKEN";
      return next();
    }

    const validation = await validateSession(token, req);
    if (!validation.valid) {
      req.user = null;
      req.session = null;
      req.authMethod = null;
      req.authFailureReason = validation.reason;
      if (method === "cookie") {
        clearSessionCookie(req, res);
      }
      return next();
    }

    req.user = validation.user;
    req.session = validation.session;
    req.authMethod = method;
    req.rawSessionToken = token;
    req.authFailureReason = null;
    return next();
  } catch (err) {
    console.error("[SecuNexis Auth] Session verification error:", err.message);
    req.user = null;
    req.session = null;
    return next();
  }
}

/**
 * Requires an authenticated session. Returns 401 Unauthorized otherwise.
 */
function requireAuth(req, res, next) {
  if (!req.user || !req.session) {
    const expired = req.authFailureReason === "SESSION_EXPIRED";
    return res.status(401).json({
      success: false,
      error: expired ? "Session has expired. Please log in again." : "Authentication required.",
      code: expired ? "SESSION_EXPIRED" : "AUTH_REQUIRED"
    });
  }
  return next();
}

/**
 * Enforces Role-Based Access Control on the backend.
 * Records every unauthorized access attempt to the immutable audit log.
 */
function requireRole(...allowedRoles) {
  const normalized = allowedRoles.map(r => String(r).toUpperCase());

  return async (req, res, next) => {
    if (!req.user || !req.session) {
      return res.status(401).json({
        success: false,
        error: "Authentication required.",
        code: "AUTH_REQUIRED"
      });
    }

    if (!normalized.includes(req.user.role)) {
      await recordAuditEvent({
        actor: req.user,
        req,
        action: "ACCESS_DENIED",
        entityType: "ENDPOINT",
        entityId: `${req.method} ${req.originalUrl || req.url}`,
        outcome: "DENIED",
        details: `Role '${req.user.role}' attempted restricted operation requiring one of [${normalized.join(", ")}].`
      }).catch(() => {});

      return res.status(403).json({
        success: false,
        error: "Insufficient permissions for this operation.",
        code: "FORBIDDEN"
      });
    }

    return next();
  };
}

/**
 * Timing-safe CSRF validation for cookie-authenticated state-changing requests.
 */
async function verifyCsrf(req, res, next) {
  if (SAFE_HTTP_METHODS.has(req.method)) {
    return next();
  }

  // CSRF only applies to cookie-based authentication (Bearer headers are not auto-attached by browsers)
  if (req.authMethod !== "cookie") {
    return next();
  }

  const expectedToken = req.session?.csrfToken || "";
  const providedToken = String(req.headers["x-csrf-token"] || "");

  let valid = false;
  if (expectedToken && providedToken && expectedToken.length === providedToken.length) {
    try {
      valid = crypto.timingSafeEqual(
        Buffer.from(expectedToken, "utf8"),
        Buffer.from(providedToken, "utf8")
      );
    } catch {
      valid = false;
    }
  }

  if (!valid) {
    await recordAuditEvent({
      actor: req.user || { username: "anonymous", role: "NONE" },
      req,
      action: "CSRF_REJECTED",
      entityType: "ENDPOINT",
      entityId: `${req.method} ${req.originalUrl || req.url}`,
      outcome: "DENIED",
      details: "Missing or invalid X-CSRF-Token header on cookie-authenticated state-changing request."
    }).catch(() => {});

    return res.status(403).json({
      success: false,
      error: "Invalid or missing CSRF token.",
      code: "CSRF_INVALID"
    });
  }

  return next();
}

/* ================= 3. DEDICATED LOGIN BRUTE-FORCE RATE LIMITER ================= */
const loginAttemptsByIp = new Map();
const LOGIN_WINDOW_MS = parseInt(process.env.LOGIN_RATE_WINDOW_MS, 10) || (15 * 60 * 1000);
const LOGIN_MAX_ATTEMPTS_PER_IP = parseInt(process.env.LOGIN_MAX_ATTEMPTS_PER_IP, 10) || 15;

function loginRateLimiter(req, res, next) {
  const clientIp = req.ip || req.socket?.remoteAddress || "unknown";
  const now = Date.now();
  let record = loginAttemptsByIp.get(clientIp);

  if (!record || now > record.resetTime) {
    record = { count: 1, resetTime: now + LOGIN_WINDOW_MS };
  } else {
    record.count++;
  }
  loginAttemptsByIp.set(clientIp, record);

  res.setHeader("X-Login-RateLimit-Limit", LOGIN_MAX_ATTEMPTS_PER_IP);
  res.setHeader("X-Login-RateLimit-Remaining", Math.max(0, LOGIN_MAX_ATTEMPTS_PER_IP - record.count));

  if (record.count > LOGIN_MAX_ATTEMPTS_PER_IP) {
    return res.status(429).json({
      success: false,
      error: "Too many login attempts from this network address. Please retry later.",
      code: "LOGIN_RATE_LIMITED"
    });
  }

  if (loginAttemptsByIp.size > 2000) {
    for (const [ip, item] of loginAttemptsByIp.entries()) {
      if (now > item.resetTime) loginAttemptsByIp.delete(ip);
    }
  }

  return next();
}

function resetLoginRateLimiter() {
  loginAttemptsByIp.clear();
}

module.exports = {
  SESSION_COOKIE_NAME,
  parseCookies,
  setSessionCookie,
  clearSessionCookie,
  attachAuthContext,
  requireAuth,
  requireRole,
  verifyCsrf,
  loginRateLimiter,
  resetLoginRateLimiter
};
