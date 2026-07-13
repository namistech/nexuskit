'use strict';

// One-off recovery script: dm_delivery_events rows stuck in 'queued' status
// never actually made it into BullMQ, because the old jobId format
// (`${campaignId}:${igCommentId}`) violated BullMQ's "no colon in custom
// job id" rule -- every enqueueDmJob() call was throwing after the DB
// row had already been inserted. lib/queue.js is fixed now (jobId uses
// '__' instead of ':'), so this script re-enqueues anything still stuck.
//
// Run via: node scripts/requeue-stuck-events.js

require('dotenv').config();

const { Client } = require('pg');
const { enqueueDmJob } = require('../lib/queue');

async function main() {
  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();

  try {
    const stuck = await client.query(
      `SELECT e.id, e.tenant_id, e.campaign_id, e.ig_comment_id, e.ig_commenter_id,
              c.connected_account_id, c.dm_message_text, c.redirect_url
       FROM dm_delivery_events e
       JOIN campaigns c ON c.id = e.campaign_id
       WHERE e.status = 'queued'
       ORDER BY e.queued_at ASC`
    );

    if (stuck.rows.length === 0) {
      console.log('No stuck events found.');
      return;
    }

    for (const row of stuck.rows) {
      await enqueueDmJob({
        tenantId: row.tenant_id,
        campaignId: row.campaign_id,
        connectedAccountId: row.connected_account_id,
        igCommentId: row.ig_comment_id,
        igCommenterId: row.ig_commenter_id,
        dmMessageText: row.dm_message_text,
        redirectUrl: row.redirect_url,
      });
      console.log('Re-enqueued', row.id, '-> comment', row.ig_comment_id);
    }

    console.log(`Re-enqueued ${stuck.rows.length} stuck event(s).`);
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error('Requeue failed:', err);
  process.exitCode = 1;
});
