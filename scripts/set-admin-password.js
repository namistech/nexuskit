'use strict';

// One-off setup script: sets a login password for an existing user and
// (optionally) flags them as a platform admin so they can see the
// cross-tenant /admin.html dashboard.
//
// Reads secrets from env -- SET_PASSWORD_EMAIL / SET_PASSWORD_VALUE /
// SET_PASSWORD_MAKE_ADMIN are only ever set as Coolify runtime env vars,
// never committed to the repo. Same pattern as scripts/seed-first-account.js.
//
// Run via: node scripts/set-admin-password.js

require('dotenv').config();

const { Client } = require('pg');
const { hashPassword } = require('../lib/auth');

async function main() {
  const email = process.env.SET_PASSWORD_EMAIL;
  const password = process.env.SET_PASSWORD_VALUE;
  const makeAdmin = process.env.SET_PASSWORD_MAKE_ADMIN === 'true';

  if (!email || !password) {
    throw new Error('SET_PASSWORD_EMAIL and SET_PASSWORD_VALUE must both be set.');
  }
  if (password.length < 8) {
    throw new Error('SET_PASSWORD_VALUE must be at least 8 characters.');
  }

  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();

  try {
    const passwordHash = hashPassword(password);

    const result = await client.query(
      `UPDATE users
       SET password_hash = $1,
           is_platform_admin = is_platform_admin OR $2
       WHERE lower(email) = lower($3)
       RETURNING id, tenant_id, email, is_platform_admin`,
      [passwordHash, makeAdmin, email]
    );

    if (result.rows.length === 0) {
      throw new Error(`No user found with email ${email}`);
    }

    console.log('Password set for', result.rows[0].email, '-- is_platform_admin =', result.rows[0].is_platform_admin);
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error('set-admin-password failed:', err);
  process.exitCode = 1;
});
