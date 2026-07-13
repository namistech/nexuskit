'use strict';

require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { queryUnscoped, withTenant } = require('./lib/db');
const { enqueueDmJob } = require('./lib/queue');

const app = express();
const PORT = process.env.PORT || 3000;

// Serves dashboard.html at "/" (and any other static assets dropped next to
// it later). This is the MVP dashboard shell — it currently renders against
// local mock data; point its fetch() calls at real /api/* routes as those
// get built.
app.use(express.static(path.join(__dirname, 'public')));
const META_VERIFY_TOKEN = process.env.META_VERIFY_TOKEN;
const META_APP_SECRET = process.env.META_APP_SECRET;

if (!META_VERIFY_TOKEN || !META_APP_SECRET) {
  throw new Error('META_VERIFY_TOKEN and META_APP_SECRET must be set before starting the server.');
}

/**
 * Meta signs every webhook POST body with the app secret. We need the exact
 * raw bytes to verify the HMAC — express.json() re-serializes the parsed
 * body, so capture the raw buffer during parsing via the `verify` hook.
 */
function captureRawBody(req, _res, buf) {
  req.rawBody = buf;
}

app.use(express.json({ verify: captureRawBody, limit: '2mb' }));

/**
 * Constant-time comparison of the X-Hub-Signature-256 header against an
 * HMAC-SHA256 of the raw request body, keyed with the Meta app secret.
 * https://developers.facebook.com/docs/graph-api/webhooks/getting-started#validate-payloads
 */
function isValidMetaSignature(req) {
  const signatureHeader = req.get('X-Hub-Signature-256');
  if (!signatureHeader || !req.rawBody) return false;

  const expected =
    'sha256=' +
    crypto.createHmac('sha256', META_APP_SECRET).update(req.rawBody).digest('hex');

  const expectedBuf = Buffer.from(expected, 'utf8');
  const givenBuf = Buffer.from(signatureHeader, 'utf8');

  if (expectedBuf.length !== givenBuf.length) return false;
  return crypto.timingSafeEqual(expectedBuf, givenBuf);
}

/**
 * STEP 1 — Meta webhook verification handshake.
 * Meta calls this once when you register/change the webhook subscription
 * in the App Dashboard. Echo back hub.challenge iff hub.verify_token matches.
 */
app.get('/webhook/meta', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === META_VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

/**
 * STEP 2 — Incoming comment events.
 * Trimmed payload shape (only the fields this route consumes):
 * {
 *   "object": "instagram",
 *   "entry": [{
 *     "id": "<ig_business_account_id>",
 *     "time": 1234567890,
 *     "changes": [{
 *       "field": "comments",
 *       "value": {
 *         "id": "<comment_id>",
 *         "text": "yes please!",
 *         "from": { "id": "<commenter_id>", "username": "..." },
 *         "media": { "id": "<media_id>" }
 *       }
 *     }]
 *   }]
 * }
 */
app.post('/webhook/meta', async (req, res) => {
  // Ack fast — Meta expects a 200 within a few seconds or it will retry and
  // eventually disable the subscription. Do the real work after replying.
  res.sendStatus(200);

  if (!isValidMetaSignature(req)) {
    // eslint-disable-next-line no-console
    console.warn('[webhook] rejected payload with invalid or missing signature');
    return;
  }

  const body = req.body;
  if (body.object !== 'instagram' || !Array.isArray(body.entry)) return;

  for (const entry of body.entry) {
    const igBusinessAccountId = entry.id;
    const changes = Array.isArray(entry.changes) ? entry.changes : [];

    for (const change of changes) {
      if (change.field !== 'comments') continue;

      const commentValue = change.value || {};
      const commentText = (commentValue.text || '').trim().toLowerCase();
      const commentId = commentValue.id;
      const commenterId = commentValue.from && commentValue.from.id;

      if (!commentText || !commentId || !commenterId) continue;

      try {
        await routeCommentToCampaign({
          igBusinessAccountId,
          commentText,
          commentId,
          commenterId,
        });
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error('[webhook] failed to route comment', {
          igBusinessAccountId,
          commentId,
          error: err.message,
        });
      }
    }
  }
});

/**
 * Resolves which tenant / connected_account / campaign a comment belongs to,
 * then enqueues a paced DM job. Two DB round-trips by design: the first is
 * unscoped (we don't know the tenant yet — that's what we're resolving);
 * the second runs inside withTenant() once we do, so RLS is enforced for
 * the actual campaign match and the write.
 */
async function routeCommentToCampaign({ igBusinessAccountId, commentText, commentId, commenterId }) {
  const accountLookup = await queryUnscoped(
    `SELECT id AS connected_account_id, tenant_id
     FROM connected_accounts
     WHERE ig_business_account_id = $1 AND status = 'active'
     LIMIT 1`,
    [igBusinessAccountId]
  );

  if (accountLookup.rows.length === 0) {
    // eslint-disable-next-line no-console
    console.warn('[webhook] no active connected_account for ig_business_account_id', igBusinessAccountId);
    return;
  }

  const { connected_account_id: connectedAccountId, tenant_id: tenantId } = accountLookup.rows[0];

  await withTenant(tenantId, async (client) => {
    // Pull every active campaign for this account and match in application
    // code rather than SQL -- match_mode ('exact' | 'contains' | 'starts_with')
    // needs per-row conditional logic that a single `= ANY(...)` equality
    // check can't express. (Earlier version of this query ignored match_mode
    // entirely and always did exact-string matching against the whole
    // comment, silently defeating campaigns left on the 'contains' default.)
    const campaignLookup = await client.query(
      `SELECT id, dm_message_text, redirect_url, match_mode, trigger_keywords
       FROM campaigns
       WHERE connected_account_id = $1
         AND is_active = TRUE
       ORDER BY created_at ASC`,
      [connectedAccountId]
    );

    const campaign = campaignLookup.rows.find((row) => {
      const keywords = (row.trigger_keywords || []).map((k) => k.toLowerCase());
      switch (row.match_mode) {
        case 'exact':
          return keywords.includes(commentText);
        case 'starts_with':
          return keywords.some((keyword) => commentText.startsWith(keyword));
        case 'contains':
        default:
          return keywords.some((keyword) => commentText.includes(keyword));
      }
    });

    if (!campaign) return;

    // Idempotent insert — the unique (campaign_id, ig_comment_id) constraint
    // means a Meta retry of the same webhook event will not double-queue.
    const inserted = await client.query(
      `INSERT INTO dm_delivery_events (tenant_id, campaign_id, ig_comment_id, ig_commenter_id, status)
       VALUES ($1, $2, $3, $4, 'queued')
       ON CONFLICT (campaign_id, ig_comment_id) DO NOTHING
       RETURNING id`,
      [tenantId, campaign.id, commentId, commenterId]
    );

    if (inserted.rows.length === 0) return; // already queued for this comment

    await client.query(
      `UPDATE campaigns SET total_triggers = total_triggers + 1 WHERE id = $1`,
      [campaign.id]
    );

    await enqueueDmJob({
      tenantId,
      campaignId: campaign.id,
      connectedAccountId,
      igCommentId: commentId,
      igCommenterId: commenterId,
      dmMessageText: campaign.dm_message_text,
      redirectUrl: campaign.redirect_url,
    });
  });
}

app.get('/healthz', (_req, res) => res.status(200).json({ status: 'ok' }));

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`NexusKit webhook service listening on :${PORT}`);
});

module.exports = app;
