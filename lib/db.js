'use strict';

const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: Number(process.env.PG_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  // eslint-disable-next-line no-console
  console.error('[db] unexpected error on idle client', err);
});

/**
 * Runs `fn` inside a transaction with `app.current_tenant_id` set for the
 * duration of that transaction. Every RLS policy in migration.sql keys off
 * this setting — it is the ONLY sanctioned way application code should
 * touch tenant-scoped tables (users, connected_accounts, campaigns,
 * dm_delivery_events). Bypassing this and querying the pool directly will
 * be blocked by FORCE ROW LEVEL SECURITY (returns zero rows, not an error).
 *
 * @param {string} tenantId
 * @param {(client: import('pg').PoolClient) => Promise<any>} fn
 */
async function withTenant(tenantId, fn) {
  if (!tenantId) {
    throw new Error('withTenant() called without a tenantId — refusing to run unscoped query.');
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // set_config's third arg (is_local=true) scopes this to the transaction only,
    // so pooled connections never leak a tenant context to the next borrower.
    await client.query('SELECT set_config($1, $2, true)', ['app.current_tenant_id', tenantId]);
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Escape hatch for genuinely tenant-agnostic queries — e.g. resolving which
 * tenant/connected_account a webhook event belongs to before we know the
 * tenant_id yet. `connected_accounts` lookups by ig_business_account_id are
 * the one legitimate use case in this codebase; keep this list short.
 */
async function queryUnscoped(text, params) {
  return pool.query(text, params);
}

module.exports = { pool, withTenant, queryUnscoped };
