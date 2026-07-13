'use strict';

const { Queue } = require('bullmq');
const IORedis = require('ioredis');

const connection = new IORedis(process.env.REDIS_URL || 'redis://127.0.0.1:6379', {
  maxRetriesPerRequest: null, // required by BullMQ's blocking connection
});

/**
 * A single queue; jobs are partitioned by connected_account_id inside the
 * job payload. Meta's DM rate limit is per IG/FB account, not global, so
 * worker.js applies a Redis-backed per-account cooldown rather than
 * splitting into one queue per account.
 *
 * Three job "kinds" flow through this same queue (see worker.js):
 *   - 'direct': campaign has require_follow_gate=false -- send the reward
 *     straight off the triggering comment, same as the original MVP.
 *   - 'gate':   campaign has require_follow_gate=true -- send the
 *     ask-to-follow message (with an "I Followed" quick-reply button) off
 *     the triggering comment.
 *   - 'reward': the user tapped "I Followed" (server.js's messaging-webhook
 *     handler caught the postback) -- send the actual reward message.
 */
const dmQueue = new Queue('dm-send', { connection });

function buildJobId(kind, campaignId, igCommentId) {
  // BullMQ forbids ':' in custom job IDs (it's the internal Redis key
  // delimiter, e.g. bull:queueName:jobId) -- use '__' instead. The kind
  // prefix keeps a gate job and its eventual reward job for the same
  // comment from colliding on jobId (they're two separate sends).
  return `${kind}__${campaignId}__${igCommentId}`;
}

const DEFAULT_JOB_OPTS = {
  attempts: 5,
  backoff: { type: 'exponential', delay: 5000 },
  removeOnComplete: 1000,
  removeOnFail: 5000,
};

/**
 * @param {object} params
 * @param {string} params.tenantId
 * @param {string} params.campaignId
 * @param {string} params.connectedAccountId
 * @param {string} params.igCommentId
 * @param {string} params.igCommenterId
 * @param {string} params.dmMessageText
 * @param {string|null} params.redirectUrl
 */
async function enqueueDmJob(params) {
  const jobId = buildJobId('direct', params.campaignId, params.igCommentId);
  return dmQueue.add('send-dm', { ...params, kind: 'direct' }, { jobId, ...DEFAULT_JOB_OPTS });
}

/**
 * @param {object} params
 * @param {string} params.tenantId
 * @param {string} params.campaignId
 * @param {string} params.connectedAccountId
 * @param {string} params.igCommentId
 * @param {string} params.igCommenterId
 * @param {string} params.gateMessageText
 */
async function enqueueGateJob(params) {
  const jobId = buildJobId('gate', params.campaignId, params.igCommentId);
  return dmQueue.add('send-dm', { ...params, kind: 'gate' }, { jobId, ...DEFAULT_JOB_OPTS });
}

/**
 * @param {object} params
 * @param {string} params.tenantId
 * @param {string} params.campaignId
 * @param {string} params.connectedAccountId
 * @param {string} params.igCommentId
 * @param {string} params.igCommenterId
 * @param {string} params.dmMessageText
 * @param {string|null} params.redirectUrl
 */
async function enqueueRewardJob(params) {
  const jobId = buildJobId('reward', params.campaignId, params.igCommentId);
  return dmQueue.add('send-dm', { ...params, kind: 'reward' }, { jobId, ...DEFAULT_JOB_OPTS });
}

module.exports = { connection, dmQueue, enqueueDmJob, enqueueGateJob, enqueueRewardJob };
