'use strict';

/**
 * AES-256-GCM helper for encrypting/decrypting long-lived Meta OAuth tokens
 * before they are persisted to `connected_accounts`. Nothing touching a
 * Meta access token should ever write plaintext to Postgres, logs, or disk.
 *
 * ENCRYPTION_KEY must be a 32-byte key, base64-encoded, provided via env.
 * Generate one with:
 *   node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // NIST-recommended IV length for GCM

function getKey() {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw) {
    throw new Error('ENCRYPTION_KEY is not set. Refusing to handle OAuth tokens without it.');
  }
  const key = Buffer.from(raw, 'base64');
  if (key.length !== 32) {
    throw new Error('ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256).');
  }
  return key;
}

/**
 * @param {string} plaintext - the raw Meta access token
 * @returns {{ciphertext: Buffer, iv: Buffer, authTag: Buffer}}
 */
function encryptToken(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { ciphertext, iv, authTag };
}

/**
 * @param {Buffer} ciphertext
 * @param {Buffer} iv
 * @param {Buffer} authTag
 * @returns {string} plaintext token
 */
function decryptToken(ciphertext, iv, authTag) {
  const key = getKey();
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}

/**
 * Same AES-256-GCM scheme as encryptToken/decryptToken, but packs
 * iv + authTag + ciphertext into a single Buffer (format: [12-byte iv][16-byte
 * authTag][ciphertext...]). Used for the platform_settings / users secret
 * columns (SMTP password, payment gateway keys, TOTP secret, etc.) where a
 * one-column-per-secret schema would otherwise need three BYTEA columns per
 * field. Returns/accepts null for "no value set" so callers can store
 * optional secrets without a sentinel.
 *
 * @param {string|null|undefined} plaintext
 * @returns {Buffer|null}
 */
function encryptSecret(plaintext) {
  if (plaintext === null || plaintext === undefined || plaintext === '') return null;
  const { ciphertext, iv, authTag } = encryptToken(plaintext);
  return Buffer.concat([iv, authTag, ciphertext]);
}

/**
 * @param {Buffer|null|undefined} blob
 * @returns {string|null}
 */
function decryptSecret(blob) {
  if (!blob) return null;
  const iv = blob.subarray(0, IV_LENGTH);
  const authTag = blob.subarray(IV_LENGTH, IV_LENGTH + 16);
  const ciphertext = blob.subarray(IV_LENGTH + 16);
  return decryptToken(ciphertext, iv, authTag);
}

module.exports = { encryptToken, decryptToken, encryptSecret, decryptSecret };
