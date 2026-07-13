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

/**
 * @param {object} args
 * @param {string} args.igBusinessAccountId
 * @param {string} [args.igCommentId] - use for a comment-triggered send (recipient.comment_id)
 * @param {string} [args.recipientId] - use once a messaging window is open (recipient.id)
 * @param {string} args.message
 * @param {Array<{content_type: string, title: string, payload: string}>} [args.quickReplies]
 * @param {string} args.accessToken
 */
async function sendInstagramDm({ igBusinessAccountId, igCommentId, recipientId, message, quickReplies, accessToken }) {
  // Comment-triggered sends POST to the standard /{ig-user-id}/messages
  // endpoint, but the recipient object uses `comment_id` instead of a user
  // `id`. That's what exempts the send from the standard 24h human-agent
  // messaging window (recipient: { id: <user-id> } gets rejected with error
  // code 10 / subcode 2534022, "sent outside of allowed window", unless the
  // user DM'd first). Once the user has interacted back (e.g. tapped a
  // quick-reply button), that itself opens the standard messaging window,
  // so the follow-up reward send can use recipient.id instead.
  // Using the Instagram API with Instagram Login (graph.instagram.com), not the
  // classic Facebook Page-linked flow (graph.facebook.com) -- the access token
  // is an Instagram User Access Token, not a Page Access Token.
  const url = `https://graph.instagram.com/${GRAPH_API_VERSION}/${igBusinessAccountId}/messages`;
  const recipient = igCommentId ? { comment_id: igCommentId } : { id: recipientId };
  const messagePayload = { text: message };
  if (quickReplies && quickReplies.length > 0) {
    messagePayload.quick_replies = quickReplies;
  }

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      recipient,
      message: messagePayload,
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

async function markDeliveryEvent(tenantId, campaignId, igCommentId, status, errorMessage) {
  await withTenant(tenantId, async (client) => {
    await client.query(
      `UPDATE dm_delivery_events SET status = $1, error_message = $2
       WHERE campaign_id = $3 AND ig_comment_id = $4`,
      [status, errorMessage || null, campaignId, igCommentId]
    );
  });
}

async function markGateEvent(tenantId, campaignId, igCommentId, status, errorMessage) {
  await withTenant(tenantId, async (client) => {
    await client.query(
      `UPDATE follow_gate_events SET status = $1, error_message = $2
       WHERE campaign_id = $3 AND ig_comment_id = $4`,
      [status, errorMessage || null, campaignId, igCommentId]
    );
  });
}

const worker = new Worker(
  'dm-send',
  async (job) => {
    const {
      kind, // 'direct' | 'gate' | 'reward'
      tenantId,
      campaignId,
      connectedAccountId,
      igCommentId,
      igCommenterId,
      dmMessageText,
      gateMessageText,
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
      const reason = 'connected_account inactive or missing';
      if (kind === 'gate' || kind === 'reward') {
        await markGateEvent(tenantId, campaignId, igCommentId, 'failed', reason);
      } else {
        await markDeliveryEvent(tenantId, campaignId, igCommentId, 'skipped_duplicate', reason);
      }
      return;
    }

    const accessToken = decryptToken(
      account.access_token_encrypted,
      account.access_token_iv,
      account.access_token_auth_tag
    );

    try {
      if (kind === 'gate') {
        // Ask-to-follow message, with a quick-reply button whose payload
        // encodes which campaign/comment this gate belongs to. The webhook
        // handler (server.js handleMessagingEvent) reads that payload back
        // when the button is tapped.
        await sendInstagramDm({
          igBusinessAccountId: account.ig_business_account_id,
          igCommentId,
          message: gateMessageText,
          quickReplies: [
            {
              content_type: 'text',
              title: 'I Followed ✅',
              payload: `FOLLOW_CONFIRM__${campaignId}__${igCommentId}`,
            },
          ],
          accessToken,
        });
        // follow_gate_events row was already inserted as 'gate_sent' by
        // server.js before this job was enqueued -- nothing to update here
        // on success.
      } else {
        // 'direct' (no gate configured) and 'reward' (gate already
        // confirmed) both send the same reward content; they differ only
        // in how the recipient is addressed and which tables get updated.
        const messageText = redirectUrl ? `${dmMessageText}\n\n${redirectUrl}` : dmMessageText;

        await sendInstagramDm({
          igBusinessAccountId: account.ig_business_account_id,
          igCommentId: kind === 'direct' ? igCommentId : undefined,
          recipientId: kind === 'reward' ? igCommenterId : undefined,
          message: messageText,
          accessToken,
        });

        await withTenant(tenantId, async (client) => {
          if (kind === 'reward') {
            await client.query(
              `UPDATE follow_gate_events SET status = 'reward_sent', reward_sent_at = now()
               WHERE campaign_id = $1 AND ig_comment_id = $2`,
              [campaignId, igCommentId]
            );
          }
          await client.query(
            `INSERT INTO dm_delivery_events (tenant_id, campaign_id, ig_comment_id, ig_commenter_id, status, sent_at)
             VALUES ($1, $2, $3, $4, 'sent', now())
             ON CONFLICT (campaign_id, ig_comment_id)
             DO UPDATE SET status = 'sent', sent_at = now()`,
            [tenantId, campaignId, igCommentId, igCommenterId]
          );
          await client.query(
            `UPDATE campaigns SET total_dms_sent = total_dms_sent + 1 WHERE id = $1`,
            [campaignId]
          );
        });
      }
    } catch (err) {
      if (kind === 'gate' || kind === 'reward') {
        await markGateEvent(tenantId, campaignId, igCommentId, 'failed', err.message);
      } else {
        await markDeliveryEvent(tenantId, campaignId, igCommentId, 'failed', err.message);
      }
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
