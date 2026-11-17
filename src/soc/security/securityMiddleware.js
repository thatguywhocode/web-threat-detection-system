/**
 * SecuNexis — API Security & Hardening Middleware (Phase 2.5)
 *
 * Implements defense-in-depth protections across all endpoints:
 * - Recursive NoSQL injection & prototype pollution guard ($ operators, __proto__, constructor)
 * - Regex metacharacter escaping to prevent ReDoS
 * - Entity identifier format validation
 * - Strict remediation object sanitization
 * - Production HTTP security headers (HSTS, CSP, Frame/MIME protection)
 * - Safe production error responses (prevents stack/DB leak)
 */

const DANGEROUS_PROTOTYPE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/**
 * Escapes all regex special characters to prevent ReDoS or regex injection
 * @param {string} input
 * @param {number} [maxLength=150]
 * @returns {string}
 */
function escapeRegex(input, maxLength = 150) {
  return String(input || "").slice(0, maxLength).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Recursively detects NoSQL injection operators ($-prefixed keys) or prototype pollution keys.
 * @param {any} value
 * @param {number} [depth=0]
 * @returns {{ dangerous: boolean, key: string|null }}
 */
function detectDangerousPayload(value, depth = 0) {
  if (depth > 12) {
    return { dangerous: true, key: "MAX_NESTING_DEPTH_EXCEEDED" };
  }
  if (value === null || value === undefined || typeof value !== "object") {
    return { dangerous: false, key: null };
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const check = detectDangerousPayload(value[i], depth + 1);
      if (check.dangerous) return check;
    }
    return { dangerous: false, key: null };
  }

  for (const key of Object.keys(value)) {
    if (DANGEROUS_PROTOTYPE_KEYS.has(key)) {
      return { dangerous: true, key };
    }
    if (key.startsWith("$") || key.includes("[$") || key.includes("\0")) {
      return { dangerous: true, key };
    }
    const check = detectDangerousPayload(value[key], depth + 1);
    if (check.dangerous) return check;
  }

  return { dangerous: false, key: null };
}

/**
 * Express middleware blocking NoSQL operator injection and prototype pollution
 * across req.body, req.query, and req.params.
 */
function nosqlInjectionGuard(req, res, next) {
  const sources = [
    { name: "body", data: req.body },
    { name: "query", data: req.query },
    { name: "params", data: req.params }
  ];

  for (const src of sources) {
    if (!src.data || typeof src.data !== "object") continue;
    const result = detectDangerousPayload(src.data);
    if (result.dangerous) {
      return res.status(400).json({
        success: false,
        error: "Invalid request payload: prohibited operator or key structure detected."
      });
    }
  }

  next();
}

/**
 * Validates entity IDs (alertId, incidentId, eventId, userId, Mongo ObjectId)
 * @param {any} id
 * @returns {boolean}
 */
function isValidEntityId(id) {
  if (typeof id !== "string") return false;
  const trimmed = id.trim();
  if (!trimmed || trimmed.length > 80) return false;
  return /^[a-zA-Z0-9_-]+$/.test(trimmed);
}

/**
 * Strictly sanitizes remediation payload to prevent unexpected nested object injection
 * @param {any} raw
 * @returns {{ summary: string, steps: string[], completed: boolean } | null}
 */
function sanitizeRemediation(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return null;
  }
  const summary = typeof raw.summary === "string" ? raw.summary.trim().slice(0, 1000) : "";
  const steps = Array.isArray(raw.steps)
    ? raw.steps
        .filter(s => typeof s === "string" && s.trim().length > 0)
        .slice(0, 25)
        .map(s => s.trim().slice(0, 500))
    : [];
  const completed = Boolean(raw.completed);

  return { summary, steps, completed };
}

/**
 * Strict security headers middleware for Render and local production deployments
 */
function securityHeadersMiddleware(req, res, next) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()");

  // Strict Transport Security in production HTTPS
  if (process.env.NODE_ENV === "production") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }

  // Content Security Policy compatible with SecuNexis Vanilla UI + CDN libraries
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net",
      "font-src 'self' https://fonts.gstatic.com data:",
      "img-src 'self' data: blob:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join("; ")
  );

  next();
}

/**
 * Returns sanitized error JSON without exposing internal stack traces or DB internals
 */
function sendSafeError(res, statusCode, publicMessage, err = null) {
  if (err) {
    console.error(`[SecuNexis Error ${statusCode}] ${publicMessage}:`, err.message);
  }
  const payload = {
    success: false,
    error: publicMessage
  };
  if (process.env.NODE_ENV !== "production" && err && statusCode < 500) {
    payload.detail = err.message;
  }
  return res.status(statusCode).json(payload);
}

/**
 * Validates that a string is a plain primitive string and within bounds
 */
function sanitizeString(val, maxLen = 500) {
  if (typeof val !== "string") return "";
  return val.trim().slice(0, maxLen);
}

module.exports = {
  escapeRegex,
  detectDangerousPayload,
  nosqlInjectionGuard,
  isValidEntityId,
  sanitizeRemediation,
  securityHeadersMiddleware,
  sendSafeError,
  sanitizeString
};
