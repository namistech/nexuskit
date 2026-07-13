'use strict';

// Applies migrations/003_follow_gate_admin_approval.sql against DATABASE_URL.
// Safely re-runnable (IF NOT EXISTS / DROP CONSTRAINT IF EXISTS + ADD).
//
// Run via: node scripts/migrate-003.js

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

async function main() {
  const sqlPath = path.join(__dirname, '..', 'migrations', '003_follow_gate_admin_approval.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');

  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();

  try {
    await client.query(sql);
    console.log('Migration 003 applied successfully.');
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error('Migration 003 failed:', err);
  process.exitCode = 1;
});
