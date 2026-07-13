'use strict';

require('dotenv').config();

const { Worker, RateLimitError } = require('bullmq');
const IORedis = require('ioredis');
const { withTenant, queryUnscoped } = require('./lib/db');
const { decryptToken } = require('./lib/tokenCipher');

const connection = new IORedis(process.env.REDIS_URL || 'redis://127.0.0.1:6379', {
  maxRetriesPerRequest: null,
});

// Meta compliance requirement: pace outbound DMs to 1-2 ops/sec PER ACCOUNT.
// 700ms spacing = ~1.4 ops/sec, a safe middle of that band.
const PER_ACCOUNT_COOLDOWN_MS = Number(process.env.DM_PER_ACCOUNT_COOLDOWN_MS || 700);
const GRAPH_API_VERSION = process.env.META_GRAPH_API_VERSION || 'v20.0';

/**
 * Redis-backed token bucket, one lock per connected_account_id.
 *
 * Open-source BullMQ doesn't ship per-group rate limiting (grouped rate
 * limiters are a BullMQ Pro feature) — so the account-level cooldown is
 * implemented here directly, and worker.rateLimit() + RateLimitError is
 * used to park a job without burning one of its retry attempts when
 * another job for the same account is still inside its cooldown window.
 */
async function claimSendSlot(connectedAccountId) {
  const key = `nexuskit:ratelimit:dm:${connectedAccountId}`;
  const claimed = await connection.set(key, '1', 'PX', PER_ACCOUNT_COOLDOWN_MS, 'NX');
  return claimed === 'OK';
}

async function getConnectedAccount(connectedAccountId) {
  const result = await queryUnscoped(
    `SELECT id, tenant_id, ig_business_account_id, access_token_encrypted,
            access_token_iv, access_token_auth_tag, status
     FROM connected_accounts
     WHERE id = $1`,
    [connectedAccountId]
  );
  return result.rows[0];
}

async function sendInstagramDm({ igBusinessAccountId, recipientId, message, accessToken }) {
  const url = `https://graph.facebook.com/${GRAPH_API_VERSION}/${igBusinessAccountId}/messages`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      recipient: { id: recipientId },
      message: { text: message },
      access_token: accessToken,
    }),
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = new Error(`Meta Graph API error ${response.status}: ${JSON.stringify(payload)}`);
    err.status = response.status;
    err.graphResponse = payload;
    throw err;
  }
  return payload;
}

async function markEvent(tenantId, campaignId, igCommentId, status, errorMessage) {
  await withTenant(tenantId, async (client) => {
    await client.query(
      `UPDATE dm_delivery_events SET status = $1, error_message = $2
       WHERE campaign_id = $3 AND ig_comment_id = $4`,
      [status, errorMessage || null, campaignId, igCommentId]
    );
  });
}

const worker = new Worker(
  'dm-send',
  async (job) => {
    const {
      tenantId,
      campaignId,
      connectedAccountId,
      igCommentId,
      igCommenterId,
      dmMessageText,
      redirectUrl,
    } = job.data;

    const slotClaimed = await claimSendSlot(connectedAccountId);
    if (!slotClaimed) {
      // Another job for this account is inside its cooldown window right
      // now — park this one and retry after the cooldown elapses.
      await worker.rateLimit(PER_ACCOUNT_COOLDOWN_MS);
      throw new RateLimitError();
    }

    const account = await getConnectedAccount(connectedAccountId);
    if (!account || account.status !== 'active') {
      await markEvent(tenantId, campaignId, igCommentId, 'skipped_duplicate', 'connected_account inactive or missing');
      return;
    }

    const accessToken = decryptToken(
      account.access_token_encrypted,
      account.access_token_iv,
      account.access_token_auth_tag
    );

    const messageText = redirectUrl ? `${dmMessageText}\n\n${redirectUrl}` : dmMessageText;

    try {
      await sendInstagramDm({
        igBusinessAccountId: account.ig_business_account_id,
        recipientId: igCommenterId,
        message: messageText,
        accessToken,
      });

      await withTenant(tenantId, async (client) => {
        await client.query(
          `UPDATE dm_delivery_events SET status = 'sent', sent_at = now()
           WHERE campaign_id = $1 AND ig_comment_id = $2`,
          [campaignId, igCommentId]
        );
        await client.query(
          `UPDATE campaigns SET total_dms_sent = total_dms_sent + 1 WHERE id = $1`,
          [campaignId]
        );
      });
    } catch (err) {
      await markEvent(tenantId, campaignId, igCommentId, 'failed', err.message);
      throw err; // re-throw so BullMQ's exponential backoff (lib/queue.js) retries
    }
  },
  {
    connection,
    concurrency: Number(process.env.WORKER_CONCURRENCY || 5),
  }
);

worker.on('failed', (job, err) => {
  // eslint-disable-next-line no-console
  console.error(`[worker] job ${job && job.id} failed:`, err.message);
});

// eslint-disable-next-line no-console
console.log(
  `NexusKit DM worker started (concurrency=${process.env.WORKER_CONCURRENCY || 5}, ` +
  `per-account cooldown=${PER_ACCOUNT_COOLDOWN_MS}ms)`
);

module.exports = worker;
