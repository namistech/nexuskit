'use strict';

// Applies migration.sql against DATABASE_URL using the `pg` package that's
// already a dependency -- avoids needing a `psql` binary in the image.
// Run inside the deployed container via: node scripts/migrate.js

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

async function main() {
  const sqlPath = path.join(__dirname, '..', 'migration.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');

  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();

  try {
    await client.query(sql);
    console.log('Migration applied successfully.');
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error('Migration failed:', err);
  process.exitCode = 1;
});
