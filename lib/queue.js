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
 */
const dmQueue = new Queue('dm-send', { connection });

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
  // jobId doubles as an idempotency key — a duplicate Meta webhook retry for
  // the same comment will collide here and BullMQ will simply ignore it.
  const jobId = `${params.campaignId}:${params.igCommentId}`;
  return dmQueue.add('send-dm', params, {
    jobId,
    attempts: 5,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: 1000,
    removeOnFail: 5000,
  });
}

module.exports = { connection, dmQueue, enqueueDmJob };
