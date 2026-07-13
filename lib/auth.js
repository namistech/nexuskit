'use strict';

/**
 * Minimal session-based auth. Deliberately not JWT: server-side sessions are
 * revocable by deleting a row (log someone out instantly, e.g. after a
 * password change or a suspected leaked cookie); a JWT is not revocable
 * without a denylist, which is extra infrastructure this MVP doesn't need.
 *
 * Passwords use Node's built-in scrypt (no new native dependency like
 * bcrypt, which can be finicky to build inside the alpine Docker image).
 */

const crypto = require('crypto');

const SCRYPT_KEYLEN = 64;
const SESSION_COOKIE_NAME = 'nexuskit_session';
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function hashPassword(plaintext) {
  const salt = crypto.randomBytes(16);
  const derivedKey = crypto.scryptSync(plaintext, salt, SCRYPT_KEYLEN);
  return `scrypt:${salt.toString('hex')}:${derivedKey.toString('hex')}`;
}

function verifyPassword(plaintext, stored) {
  if (!stored || !stored.startsWith('scrypt:')) return false;
  const parts = stored.split(':');
  if (parts.length !== 3) return false;
  const [, saltHex, hashHex] = parts;
  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(plaintext, salt, SCRYPT_KEYLEN);
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * We store only the SHA-256 hash of the session token in Postgres, never the
 * raw token — mirrors the "never store the secret itself" principle used
 * for OAuth tokens (lib/tokenCipher.js), just with a cheaper one-way hash
 * since sessions are meant to be looked up by exact match, not decrypted.
 */
function hashSessionToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (key) {
      try {
        out[key] = decodeURIComponent(val);
      } catch {
        out[key] = val;
      }
    }
  });
  return out;
}

function serializeSessionCookie(token, { maxAgeMs = SESSION_TTL_MS } = {}) {
  const parts = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${Math.floor(maxAgeMs / 1000)}`,
  ];
  if (process.env.NODE_ENV === 'production') parts.push('Secure');
  return parts.join('; ');
}

function clearSessionCookie() {
  return `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

module.exports = {
  SESSION_COOKIE_NAME,
  SESSION_TTL_MS,
  hashPassword,
  verifyPassword,
  generateSessionToken,
  hashSessionToken,
  parseCookies,
  serializeSessionCookie,
  clearSessionCookie,
};
