/**
 * SecuNexis — Secure Password Hashing & Policy Utilities (Phase 2.5)
 *
 * Uses bcryptjs (bcrypt) with a minimum cost factor of 10 (default 12 in production).
 * Enforces enterprise password complexity requirements and provides timing-safe
 * dummy verification to prevent username enumeration side-channels.
 */

const bcrypt = require("bcryptjs");

const DEFAULT_ROUNDS = process.env.NODE_ENV === "production" ? 12 : 10;
const BCRYPT_ROUNDS = Math.max(10, parseInt(process.env.BCRYPT_ROUNDS, 10) || DEFAULT_ROUNDS);

// Pre-computed valid bcrypt hash format used strictly for timing equalization when user doesn't exist
const DUMMY_HASH = bcrypt.hashSync("SecuNexis!DummyEqualizer#9999", 10);

/**
 * Validates enterprise password complexity policy:
 * - Minimum 10 characters, max 128 characters
 * - At least one uppercase letter, lowercase letter, digit, and special character
 *
 * @param {string} password
 * @returns {{ valid: boolean, error: string|null }}
 */
function validatePasswordStrength(password) {
  if (typeof password !== "string") {
    return { valid: false, error: "Password must be a string." };
  }
  if (password.length < 10) {
    return { valid: false, error: "Password must be at least 10 characters long." };
  }
  if (password.length > 128) {
    return { valid: false, error: "Password must not exceed 128 characters." };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, error: "Password must contain at least one uppercase letter." };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, error: "Password must contain at least one lowercase letter." };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, error: "Password must contain at least one numeric digit." };
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return { valid: false, error: "Password must contain at least one special character." };
  }
  return { valid: true, error: null };
}

/**
 * Hashes a plaintext password using bcrypt with cryptographic random salt
 * @param {string} plainPassword
 * @returns {Promise<string>}
 */
async function hashPassword(plainPassword) {
  const salt = await bcrypt.genSalt(BCRYPT_ROUNDS);
  return bcrypt.hash(plainPassword, salt);
}

/**
 * Verifies a plaintext password against a stored bcrypt hash
 * @param {string} plainPassword
 * @param {string} storedHash
 * @returns {Promise<boolean>}
 */
async function verifyPassword(plainPassword, storedHash) {
  if (typeof plainPassword !== "string" || typeof storedHash !== "string" || !storedHash) {
    await bcrypt.compare(String(plainPassword || ""), DUMMY_HASH);
    return false;
  }
  return bcrypt.compare(plainPassword, storedHash);
}

/**
 * Runs a dummy bcrypt comparison to normalize response timing when a user is not found
 */
async function equalizeTiming(input = "") {
  await bcrypt.compare(String(input || ""), DUMMY_HASH);
}

module.exports = {
  BCRYPT_ROUNDS,
  validatePasswordStrength,
  hashPassword,
  verifyPassword,
  equalizeTiming
};
