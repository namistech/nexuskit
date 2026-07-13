'use strict';

require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { queryUnscoped, withTenant, withAdmin } = require('./lib/db');
const { enqueueDmJob, enqueueGateJob, enqueueRewardJob } = require('./lib/queue');
const {
  hashPassword,
  verifyPassword,
  generateSessionToken,
  hashSessionToken,
  parseCookies,
  serializeSessionCookie,
  clearSessionCookie,
  SESSION_COOKIE_NAME,
  SESSION_TTL_MS,
} = require('./lib/auth');

const app = express();
const PORT = process.env.PORT || 3000;

const DEFAULT_GATE_MESSAGE =
  "Thanks for the comment! Follow me first, then tap the button below and I'll send it right over 👇";

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

app.use((req, _res, next) => {
  req.cookies = parseCookies(req.get('cookie'));
  next();
});

// ============================================================================
// AUTH MIDDLEWARE
// ============================================================================

/**
 * Looks up the session cookie and attaches req.user if valid. Does NOT
 * reject the request on its own — routes that need auth use requireAuth /
 * requireAdmin below. Session lookups are unscoped (queryUnscoped) because
 * we don't know the tenant until we've resolved the session.
 */
async function attachUser(req, _res, next) {
  try {
    const token = req.cookies[SESSION_COOKIE_NAME];
    if (!token) return next();

    const tokenHash = hashSessionToken(token);
    const result = await queryUnscoped(
      `SELECT s.user_id, s.tenant_id, s.expires_at,
              u.email, u.full_name, u.role, u.is_platform_admin
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = $1`,
      [tokenHash]
    );

    if (result.rows.length === 0) return next();
    const row = result.rows[0];
    if (new Date(row.expires_at).getTime() < Date.now()) return next();

    req.user = {
      id: row.user_id,
      tenantId: row.tenant_id,
      email: row.email,
      fullName: row.full_name,
      role: row.role,
      isPlatformAdmin: row.is_platform_admin,
    };
    next();
  } catch (err) {
    next(err);
  }
}

app.use(attachUser);

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  if (!req.user.isPlatformAdmin) return res.status(403).json({ error: 'Admin access required' });
  next();
}

// Serves the dashboard shells (index.html, login.html, admin.html) plus
// static assets. Page-level access control happens client-side (each page
// calls GET /api/me and redirects if unauthorized) — the actual data is
// gated at the API layer below, which is the boundary that matters.
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================================
// META WEBHOOK — verification handshake + inbound events
// ============================================================================

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
 * Payload shapes this route consumes:
 *
 * Comment event (field: 'comments'):
 * { object: "instagram", entry: [{ id: "<ig_business_account_id>",
 *   changes: [{ field: "comments", value: { id, text, from: { id }, media } }] }] }
 *
 * Messaging event (quick-reply tap on the follow-gate button) — this is
 * Meta's Messenger-Platform-derived shape, carried under `entry.messaging`
 * rather than `entry.changes`. NOTE: this is our best-effort implementation
 * based on documented shape; if the "I Followed" button doesn't trigger the
 * reward send in testing, the actual payload shape is the first thing to
 * check (console.warn below logs the raw messaging event for that reason).
 * { object: "instagram", entry: [{ id: "<ig_business_account_id>",
 *   messaging: [{ sender: { id }, message: { quick_reply: { payload } } }] }] }
 *
 * Requires the 'messages' webhook field to be subscribed in the Meta App
 * Dashboard in addition to 'comments' -- comment-only subscriptions will
 * never deliver the button-tap event.
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
        await routeCommentToCampaign({ igBusinessAccountId, commentText, commentId, commenterId });
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error('[webhook] failed to route comment', {
          igBusinessAccountId,
          commentId,
          error: err.message,
        });
      }
    }

    const messagingEvents = Array.isArray(entry.messaging) ? entry.messaging : [];
    for (const messagingEvent of messagingEvents) {
      try {
        await handleMessagingEvent({ igBusinessAccountId, messagingEvent });
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error('[webhook] failed to handle messaging event', {
          igBusinessAccountId,
          error: err.message,
        });
      }
    }
  }
});

/**
 * Resolves which tenant / connected_account / campaign a comment belongs to,
 * then either enqueues the reward directly (require_follow_gate = false) or
 * enqueues the ask-to-follow gate message (require_follow_gate = true).
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
    // code -- match_mode ('exact' | 'contains' | 'starts_with') needs
    // per-row conditional logic a single SQL equality check can't express.
    const campaignLookup = await client.query(
      `SELECT id, dm_message_text, redirect_url, match_mode, trigger_keywords,
              require_follow_gate, gate_message_text
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

    if (campaign.require_follow_gate) {
      const insertedGate = await client.query(
        `INSERT INTO follow_gate_events (tenant_id, campaign_id, ig_comment_id, ig_commenter_id, status)
         VALUES ($1, $2, $3, $4, 'gate_sent')
         ON CONFLICT (campaign_id, ig_comment_id) DO NOTHING
         RETURNING id`,
        [tenantId, campaign.id, commentId, commenterId]
      );
      if (insertedGate.rows.length === 0) return; // already gated for this comment

      await client.query(`UPDATE campaigns SET total_triggers = total_triggers + 1 WHERE id = $1`, [campaign.id]);

      await enqueueGateJob({
        tenantId,
        campaignId: campaign.id,
        connectedAccountId,
        igCommentId: commentId,
        igCommenterId: commenterId,
        gateMessageText: campaign.gate_message_text || DEFAULT_GATE_MESSAGE,
      });
      return;
    }

    // No gate configured -- original single-stage behavior.
    const inserted = await client.query(
      `INSERT INTO dm_delivery_events (tenant_id, campaign_id, ig_comment_id, ig_commenter_id, status)
       VALUES ($1, $2, $3, $4, 'queued')
       ON CONFLICT (campaign_id, ig_comment_id) DO NOTHING
       RETURNING id`,
      [tenantId, campaign.id, commentId, commenterId]
    );
    if (inserted.rows.length === 0) return; // already queued for this comment

    await client.query(`UPDATE campaigns SET total_triggers = total_triggers + 1 WHERE id = $1`, [campaign.id]);

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

/**
 * Handles the "I Followed" quick-reply tap. Looks for a payload of the form
 * FOLLOW_CONFIRM__<campaignId>__<igCommentId>, flips the matching
 * follow_gate_events row from 'gate_sent' to 'confirmed' (idempotent --
 * a second tap is a no-op because the UPDATE's WHERE clause only matches
 * 'gate_sent'), then enqueues the actual reward send.
 */
async function handleMessagingEvent({ igBusinessAccountId, messagingEvent }) {
  const senderId = messagingEvent.sender && messagingEvent.sender.id;
  const message = messagingEvent.message || {};
  const quickReplyPayload = message.quick_reply && message.quick_reply.payload;
  const postbackPayload = messagingEvent.postback && messagingEvent.postback.payload;
  const payload = quickReplyPayload || postbackPayload;

  if (!senderId || !payload) return;
  if (!payload.startsWith('FOLLOW_CONFIRM__')) {
    // eslint-disable-next-line no-console
    console.warn('[webhook] unrecognized messaging payload, ignoring', { payload });
    return;
  }

  const [, campaignId, igCommentId] = payload.split('__');
  if (!campaignId || !igCommentId) return;

  const accountLookup = await queryUnscoped(
    `SELECT id AS connected_account_id, tenant_id
     FROM connected_accounts
     WHERE ig_business_account_id = $1 AND status = 'active'
     LIMIT 1`,
    [igBusinessAccountId]
  );
  if (accountLookup.rows.length === 0) return;
  const { connected_account_id: connectedAccountId, tenant_id: tenantId } = accountLookup.rows[0];

  await withTenant(tenantId, async (client) => {
    const gateUpdate = await client.query(
      `UPDATE follow_gate_events SET status = 'confirmed', confirmed_at = now()
       WHERE campaign_id = $1 AND ig_comment_id = $2 AND status = 'gate_sent'
       RETURNING id`,
      [campaignId, igCommentId]
    );
    if (gateUpdate.rows.length === 0) return; // already confirmed (duplicate tap), or unknown -- ignore

    const campaignLookup = await client.query(
      `SELECT dm_message_text, redirect_url FROM campaigns WHERE id = $1`,
      [campaignId]
    );
    if (campaignLookup.rows.length === 0) return;
    const campaign = campaignLookup.rows[0];

    await enqueueRewardJob({
      tenantId,
      campaignId,
      connectedAccountId,
      igCommentId,
      igCommenterId: senderId,
      dmMessageText: campaign.dm_message_text,
      redirectUrl: campaign.redirect_url,
    });
  });
}

// ============================================================================
// AUTH API
// ============================================================================

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  // NOTE: email uniqueness is enforced per-tenant (tenant_id, lower(email)),
  // not globally -- so in principle the same email could exist under two
  // different tenants. This picks the first match, which is fine while
  // you're the only real customer; once you onboard others, either enforce
  // global email uniqueness or add a workspace selector to login.
  const result = await queryUnscoped(
    `SELECT id, tenant_id, email, password_hash, role, is_platform_admin
     FROM users WHERE lower(email) = lower($1) LIMIT 1`,
    [email]
  );

  if (result.rows.length === 0 || !verifyPassword(password, result.rows[0].password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const user = result.rows[0];
  const token = generateSessionToken();
  const tokenHash = hashSessionToken(token);
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

  await queryUnscoped(
    `INSERT INTO sessions (user_id, tenant_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)`,
    [user.id, user.tenant_id, tokenHash, expiresAt]
  );

  res.setHeader('Set-Cookie', serializeSessionCookie(token));
  res.json({ id: user.id, email: user.email, role: user.role, isPlatformAdmin: user.is_platform_admin });
});

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  const token = req.cookies[SESSION_COOKIE_NAME];
  if (token) {
    await queryUnscoped(`DELETE FROM sessions WHERE token_hash = $1`, [hashSessionToken(token)]);
  }
  res.setHeader('Set-Cookie', clearSessionCookie());
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json(req.user);
});

// ============================================================================
// TENANT DASHBOARD API
// ============================================================================

app.get('/api/dashboard/summary', requireAuth, async (req, res, next) => {
  try {
    const summary = await withTenant(req.user.tenantId, async (client) => {
      const [accounts, campaigns, events] = await Promise.all([
        client.query(
          `SELECT id, ig_username, ig_business_account_id, status, last_synced_at
           FROM connected_accounts ORDER BY created_at ASC`
        ),
        client.query(
          `SELECT id, name, is_active, require_follow_gate, total_triggers, total_dms_sent
           FROM campaigns ORDER BY created_at DESC`
        ),
        client.query(
          `SELECT id, campaign_id, status, ig_commenter_id, queued_at, sent_at
           FROM dm_delivery_events ORDER BY queued_at DESC LIMIT 20`
        ),
      ]);

      const totals = campaigns.rows.reduce(
        (acc, c) => {
          acc.totalTriggers += Number(c.total_triggers);
          acc.totalDmsSent += Number(c.total_dms_sent);
          return acc;
        },
        { totalTriggers: 0, totalDmsSent: 0 }
      );

      return {
        connectedAccounts: accounts.rows,
        campaigns: campaigns.rows,
        recentEvents: events.rows,
        totals: {
          ...totals,
          activeCampaigns: campaigns.rows.filter((c) => c.is_active).length,
          totalCampaigns: campaigns.rows.length,
        },
      };
    });
    res.json(summary);
  } catch (err) {
    next(err);
  }
});

app.get('/api/campaigns', requireAuth, async (req, res, next) => {
  try {
    const result = await withTenant(req.user.tenantId, (client) =>
      client.query(
        `SELECT c.*, ca.ig_username
         FROM campaigns c
         JOIN connected_accounts ca ON ca.id = c.connected_account_id
         ORDER BY c.created_at DESC`
      )
    );
    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

app.post('/api/campaigns', requireAuth, async (req, res, next) => {
  try {
    const {
      connectedAccountId,
      name,
      triggerKeywords,
      matchMode,
      requireFollowGate,
      gateMessageText,
      dmMessageText,
      rewardType,
      redirectUrl,
    } = req.body || {};

    if (!connectedAccountId || !name || !Array.isArray(triggerKeywords) || triggerKeywords.length === 0 || !dmMessageText) {
      return res.status(400).json({
        error: 'connectedAccountId, name, triggerKeywords (non-empty array), and dmMessageText are required',
      });
    }

    const normalizedKeywords = triggerKeywords.map((k) => String(k).trim().toLowerCase()).filter(Boolean);

    const result = await withTenant(req.user.tenantId, async (client) => {
      // Postgres FK constraint checks don't go through the referencing
      // role's RLS policies, so without this explicit check a caller could
      // in principle point a new campaign at another tenant's
      // connected_account_id (if they somehow knew its UUID) and the
      // INSERT would still succeed. This SELECT is RLS-scoped, so it only
      // finds the account if it actually belongs to req.user.tenantId.
      const ownershipCheck = await client.query(
        `SELECT id FROM connected_accounts WHERE id = $1`,
        [connectedAccountId]
      );
      if (ownershipCheck.rows.length === 0) {
        const err = new Error('connectedAccountId does not belong to this tenant');
        err.statusCode = 400;
        throw err;
      }

      return client.query(
        `INSERT INTO campaigns
           (tenant_id, connected_account_id, name, trigger_keywords, match_mode,
            require_follow_gate, gate_message_text, dm_message_text, reward_type, redirect_url)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING *`,
        [
          req.user.tenantId,
          connectedAccountId,
          name,
          normalizedKeywords,
          matchMode || 'contains',
          requireFollowGate !== false,
          gateMessageText || null,
          dmMessageText,
          rewardType || 'link',
          redirectUrl || null,
        ]
      );
    });

    res.status(201).json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

app.patch('/api/campaigns/:id', requireAuth, async (req, res, next) => {
  try {
    const allowedFields = {
      name: 'name',
      triggerKeywords: 'trigger_keywords',
      matchMode: 'match_mode',
      isActive: 'is_active',
      requireFollowGate: 'require_follow_gate',
      gateMessageText: 'gate_message_text',
      dmMessageText: 'dm_message_text',
      rewardType: 'reward_type',
      redirectUrl: 'redirect_url',
    };

    const updates = [];
    const values = [];
    let i = 1;

    for (const [bodyKey, column] of Object.entries(allowedFields)) {
      if (Object.prototype.hasOwnProperty.call(req.body || {}, bodyKey)) {
        let value = req.body[bodyKey];
        if (bodyKey === 'triggerKeywords' && Array.isArray(value)) {
          value = value.map((k) => String(k).trim().toLowerCase()).filter(Boolean);
        }
        updates.push(`${column} = $${i}`);
        values.push(value);
        i += 1;
      }
    }

    if (updates.length === 0) return res.status(400).json({ error: 'No updatable fields provided' });

    values.push(req.params.id);
    const result = await withTenant(req.user.tenantId, (client) =>
      client.query(`UPDATE campaigns SET ${updates.join(', ')} WHERE id = $${i} RETURNING *`, values)
    );

    if (result.rows.length === 0) return res.status(404).json({ error: 'Campaign not found' });
    res.json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

// ============================================================================
// PLATFORM ADMIN API (cross-tenant, requires is_platform_admin)
// ============================================================================

app.get('/api/admin/overview', requireAdmin, async (req, res, next) => {
  try {
    const overview = await withAdmin(async (client) => {
      const tenants = await client.query(
        `SELECT id, name, slug, billing_tier, is_active, created_at FROM tenants ORDER BY created_at ASC`
      );

      const campaignStats = await client.query(
        `SELECT tenant_id,
                COUNT(*) AS campaign_count,
                COALESCE(SUM(total_triggers), 0) AS total_triggers,
                COALESCE(SUM(total_dms_sent), 0) AS total_dms_sent
         FROM campaigns
         GROUP BY tenant_id`
      );

      const accountStats = await client.query(
        `SELECT tenant_id, COUNT(*) AS connected_account_count
         FROM connected_accounts WHERE status = 'active'
         GROUP BY tenant_id`
      );

      const statsByTenant = new Map();
      for (const row of campaignStats.rows) {
        statsByTenant.set(row.tenant_id, {
          campaignCount: Number(row.campaign_count),
          totalTriggers: Number(row.total_triggers),
          totalDmsSent: Number(row.total_dms_sent),
          connectedAccountCount: 0,
        });
      }
      for (const row of accountStats.rows) {
        const existing = statsByTenant.get(row.tenant_id) || {
          campaignCount: 0,
          totalTriggers: 0,
          totalDmsSent: 0,
          connectedAccountCount: 0,
        };
        existing.connectedAccountCount = Number(row.connected_account_count);
        statsByTenant.set(row.tenant_id, existing);
      }

      const tenantsWithStats = tenants.rows.map((t) => ({
        ...t,
        stats: statsByTenant.get(t.id) || {
          campaignCount: 0,
          totalTriggers: 0,
          totalDmsSent: 0,
          connectedAccountCount: 0,
        },
      }));

      const platformTotals = tenantsWithStats.reduce(
        (acc, t) => {
          acc.totalTenants += 1;
          acc.totalCampaigns += t.stats.campaignCount;
          acc.totalTriggers += t.stats.totalTriggers;
          acc.totalDmsSent += t.stats.totalDmsSent;
          acc.totalConnectedAccounts += t.stats.connectedAccountCount;
          return acc;
        },
        { totalTenants: 0, totalCampaigns: 0, totalTriggers: 0, totalDmsSent: 0, totalConnectedAccounts: 0 }
      );

      return { tenants: tenantsWithStats, platformTotals };
    });

    res.json(overview);
  } catch (err) {
    next(err);
  }
});

app.get('/healthz', (_req, res) => res.status(200).json({ status: 'ok' }));

// Central error handler -- keeps route handlers from needing individual
// try/catch-and-respond boilerplate; anything passed to next(err) lands here.
// Routes can set err.statusCode to return something other than 500 (e.g.
// the connectedAccountId ownership check in POST /api/campaigns).
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  const statusCode = err.statusCode || 500;
  if (statusCode >= 500) {
    // eslint-disable-next-line no-console
    console.error('[server] unhandled error', err);
  }
  res.status(statusCode).json({ error: statusCode >= 500 ? 'Internal server error' : err.message });
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`NexusKit webhook service listening on :${PORT}`);
});

module.exports = app;
