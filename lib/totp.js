'use strict';

/**
 * Minimal TOTP (RFC 6238) implementation on top of Node's built-in crypto --
 * deliberately no npm dependency (otplib etc.) to avoid growing the Docker
 * build surface for something this self-contained. Compatible with Google
 * Authenticator, Authy, 1Password, etc.
 */

const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEP_SECONDS = 30;
const DIGITS = 6;

/** Generates a random 20-byte secret, base32-encoded (the standard TOTP secret format). */
function generateSecret() {
  const bytes = crypto.randomBytes(20);
  return base32Encode(bytes);
}

function base32Encode(buffer) {
  let bits = '';
  for (const byte of buffer) bits += byte.toString(2).padStart(8, '0');
  let output = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    output += BASE32_ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  }
  const remainder = bits.length % 5;
  if (remainder !== 0) {
    const lastChunk = bits.slice(bits.length - remainder).padEnd(5, '0');
    output += BASE32_ALPHABET[parseInt(lastChunk, 2)];
  }
  return output;
}

function base32Decode(input) {
  const clean = input.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const char of clean) {
    const val = BASE32_ALPHABET.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

/** @param {string} base32Secret @param {number} [counterOverride] @returns {string} 6-digit code */
function generateToken(base32Secret, counterOverride) {
  const key = base32Decode(base32Secret);
  const counter = counterOverride !== undefined ? counterOverride : Math.floor(Date.now() / 1000 / STEP_SECONDS);

  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));

  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return String(binCode % 10 ** DIGITS).padStart(DIGITS, '0');
}

/**
 * Verifies a user-entered 6-digit code, allowing ±1 time step (30s) of
 * clock drift, which is standard practice for TOTP verification.
 * @param {string} base32Secret
 * @param {string} token
 * @returns {boolean}
 */
function verifyToken(base32Secret, token) {
  if (!token || !/^\d{6}$/.test(token)) return false;
  const currentCounter = Math.floor(Date.now() / 1000 / STEP_SECONDS);
  for (const drift of [0, -1, 1]) {
    if (generateToken(base32Secret, currentCounter + drift) === token) return true;
  }
  return false;
}

/**
 * Builds an otpauth:// URI for QR-code enrollment. The dashboard renders
 * this as a QR code via an external image service (api.qrserver.com) rather
 * than pulling in a qrcode-generation dependency for one image.
 */
function buildOtpAuthUri(base32Secret, accountLabel, issuer) {
  const label = encodeURIComponent(`${issuer}:${accountLabel}`);
  const params = new URLSearchParams({
    secret: base32Secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

module.exports = { generateSecret, generateToken, verifyToken, buildOtpAuthUri };
