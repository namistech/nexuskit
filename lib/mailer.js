'use strict';

const nodemailer = require('nodemailer');
const { queryUnscoped } = require('./db');
const { decryptSecret } = require('./tokenCipher');

/**
 * Builds a fresh transporter from whatever is currently in
 * platform_settings, rather than caching one at boot -- so a credential
 * change in the admin dashboard takes effect on the very next send, with no
 * restart required. SMTP sends are low-frequency (admin-triggered), so the
 * per-send connection-setup cost is a non-issue.
 */
async function loadSmtpConfig() {
  const result = await queryUnscoped(
    `SELECT smtp_host, smtp_port, smtp_username, smtp_password_encrypted, smtp_from_email, smtp_secure
     FROM platform_settings WHERE id = 1`
  );
  if (result.rows.length === 0) return null;
  const row = result.rows[0];
  if (!row.smtp_host || !row.smtp_port || !row.smtp_from_email) return null;

  return {
    host: row.smtp_host,
    port: row.smtp_port,
    secure: row.smtp_secure,
    from: row.smtp_from_email,
    username: row.smtp_username,
    password: decryptSecret(row.smtp_password_encrypted),
  };
}

/**
 * @param {string} to
 * @param {string} subject
 * @param {string} html
 * @throws if SMTP isn't configured yet, or the send fails
 */
async function sendMail(to, subject, html) {
  const config = await loadSmtpConfig();
  if (!config) {
    const err = new Error('SMTP is not configured yet -- add server settings under Admin > Notifications first.');
    err.statusCode = 400;
    throw err;
  }

  const transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    auth: config.username ? { user: config.username, pass: config.password } : undefined,
  });

  await transporter.sendMail({ from: config.from, to, subject, html });
}

module.exports = { sendMail, loadSmtpConfig };
