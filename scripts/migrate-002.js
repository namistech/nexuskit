'use strict';

// Applies migrations/002_auth_and_follow_gate.sql against DATABASE_URL.
// Unlike migration.sql, this file is written to be safely re-runnable
// (IF NOT EXISTS / DROP POLICY IF EXISTS + CREATE), so this script can be
// run again without harm if it partially fails.
//
// Run via: node scripts/migrate-002.js

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

async function main() {
  const sqlPath = path.join(__dirname, '..', 'migrations', '002_auth_and_follow_gate.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');

  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();

  try {
    await client.query(sql);
    console.log('Migration 002 applied successfully.');
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error('Migration 002 failed:', err);
  process.exitCode = 1;
});
