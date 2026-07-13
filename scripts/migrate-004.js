'use strict';

// Applies migrations/004_admin_settings.sql against DATABASE_URL.
// Safely re-runnable (IF NOT EXISTS / DROP ... IF EXISTS + CREATE).
//
// Run via: node scripts/migrate-004.js

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

async function main() {
  const sqlPath = path.join(__dirname, '..', 'migrations', '004_admin_settings.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');

  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();

  try {
    await client.query(sql);
    console.log('Migration 004 applied successfully.');
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error('Migration 004 failed:', err);
  process.exitCode = 1;
});
