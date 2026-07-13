'use strict';

// One-off setup script: relaxes the fb_page_id constraint (not applicable to
// the Instagram-Login flow), then creates/updates a tenant, user, connected
// Instagram account, and a demo campaign so the webhook -> worker -> DM path
// can be tested end to end before the real dashboard/API exists.
//
// Reads secrets from env -- SEED_IG_TOKEN / SEED_IG_BUSINESS_ID /
// SEED_IG_USERNAME are only ever set as Coolify runtime env vars, never
// committed to the repo.
//
// Run via: node scripts/seed-first-account.js

require('dotenv').config();

const { Client } = require('pg');
const { encryptToken } = require('../lib/tokenCipher');

const TENANT_NAME = 'Furnotix';
const TENANT_SLUG = 'furnotix';
const OWNER_EMAIL = 'aliyan@aliyanbaig.com';
const OWNER_NAME = 'Aliyan Baig';
const DEMO_CAMPAIGN_NAME = 'Demo Test Campaign';
const DEMO_TRIGGER_KEYWORDS = ['test', 'demo'];
const DEMO_DM_MESSAGE = "Hey! Thanks for testing NexusKit \u{1F44B} This DM was sent automatically.";

async function main() {
  const igToken = process.env.SEED_IG_TOKEN;
  const igBusinessId = process.env.SEED_IG_BUSINESS_ID;
  const igUsername = process.env.SEED_IG_USERNAME;

  if (!igToken || !igBusinessId || !igUsername) {
    throw new Error('SEED_IG_TOKEN, SEED_IG_BUSINESS_ID, and SEED_IG_USERNAME must all be set.');
  }

  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();

  try {
    // fb_page_id was originally NOT NULL, assuming the classic Page-linked
    // flow. Instagram Login doesn't involve a Page, so relax it.
    await client.query('ALTER TABLE connected_accounts ALTER COLUMN fb_page_id DROP NOT NULL');

    let tenantId;
    const existingTenant = await client.query('SELECT id FROM tenants WHERE slug = $1', [TENANT_SLUG]);
    if (existingTenant.rows.length > 0) {
      tenantId = existingTenant.rows[0].id;
    } else {
      const t = await client.query(
        `INSERT INTO tenants (name, slug, billing_tier) VALUES ($1, $2, 'trial') RETURNING id`,
        [TENANT_NAME, TENANT_SLUG]
      );
      tenantId = t.rows[0].id;
    }

    let userId;
    const existingUser = await client.query(
      'SELECT id FROM users WHERE tenant_id = $1 AND lower(email) = lower($2)',
      [tenantId, OWNER_EMAIL]
    );
    if (existingUser.rows.length > 0) {
      userId = existingUser.rows[0].id;
    } else {
      const u = await client.query(
        `INSERT INTO users (tenant_id, email, password_hash, full_name, role)
         VALUES ($1, $2, 'UNSET-NO-AUTH-YET', $3, 'owner') RETURNING id`,
        [tenantId, OWNER_EMAIL, OWNER_NAME]
      );
      userId = u.rows[0].id;
    }

    const { ciphertext, iv, authTag } = encryptToken(igToken);
    let connectedAccountId;

    const existingAccount = await client.query(
      'SELECT id FROM connected_accounts WHERE tenant_id = $1 AND ig_business_account_id = $2',
      [tenantId, igBusinessId]
    );

    if (existingAccount.rows.length > 0) {
      connectedAccountId = existingAccount.rows[0].id;
      await client.query(
        `UPDATE connected_accounts
         SET access_token_encrypted = $1, access_token_iv = $2, access_token_auth_tag = $3,
             ig_username = $4, status = 'active', last_synced_at = now()
         WHERE id = $5`,
        [ciphertext, iv, authTag, igUsername, connectedAccountId]
      );
      console.log('Updated existing connected_account', connectedAccountId);
    } else {
      const inserted = await client.query(
        `INSERT INTO connected_accounts
           (tenant_id, user_id, platform, ig_business_account_id, ig_username,
            access_token_encrypted, access_token_iv, access_token_auth_tag, scopes, status)
         VALUES ($1, $2, 'instagram', $3, $4, $5, $6, $7, $8, 'active')
         RETURNING id`,
        [
          tenantId,
          userId,
          igBusinessId,
          igUsername,
          ciphertext,
          iv,
          authTag,
          ['instagram_business_basic', 'instagram_business_manage_messages', 'instagram_business_manage_comments'],
        ]
      );
      connectedAccountId = inserted.rows[0].id;
      console.log('Inserted connected_account', connectedAccountId);
    }

    const existingCampaign = await client.query(
      'SELECT id FROM campaigns WHERE connected_account_id = $1 AND name = $2',
      [connectedAccountId, DEMO_CAMPAIGN_NAME]
    );

    if (existingCampaign.rows.length === 0) {
      const campaign = await client.query(
        `INSERT INTO campaigns (tenant_id, connected_account_id, name, trigger_keywords, dm_message_text)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id`,
        [tenantId, connectedAccountId, DEMO_CAMPAIGN_NAME, DEMO_TRIGGER_KEYWORDS, DEMO_DM_MESSAGE]
      );
      console.log('Inserted demo campaign', campaign.rows[0].id, '-- triggers on:', DEMO_TRIGGER_KEYWORDS.join(', '));
    } else {
      console.log('Demo campaign already exists', existingCampaign.rows[0].id);
    }

    console.log('Seed complete. tenant_id=%s user_id=%s connected_account_id=%s', tenantId, userId, connectedAccountId);
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error('Seed failed:', err);
  process.exitCode = 1;
});
