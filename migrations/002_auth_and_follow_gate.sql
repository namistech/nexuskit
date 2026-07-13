-- ============================================================================
-- NexusKit — migration 002: sessions/auth, platform admin flag, and the
-- follow-required-before-DM gate automation.
--
-- migration.sql (the baseline) already ran once against the live database
-- and cannot be safely re-executed wholesale (CREATE TABLE without IF NOT
-- EXISTS would error). This file is written to be safely re-runnable
-- (IF NOT EXISTS / DROP POLICY IF EXISTS + CREATE) so it can be applied to
-- either a fresh install or the existing live database. See
-- scripts/migrate-002.js for how it's applied to a running deployment.
-- ============================================================================

BEGIN;

-- ============================================================================
-- 1. SESSIONS — server-side, revocable (see lib/auth.js for why not JWT)
-- ============================================================================
CREATE TABLE IF NOT EXISTS sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) NOT NULL, -- sha256 hex digest of the raw session token
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_sessions_token_hash ON sessions (token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
-- Deliberately NOT enabling RLS here: sessions are looked up by token_hash
-- before we know the tenant (that's the whole point of authenticating), so
-- the app always queries this table unscoped. There's no tenant-scoped
-- access pattern for it to protect.

-- ============================================================================
-- 2. PLATFORM ADMIN FLAG
--    Distinct from a tenant's own 'owner' role — lets the platform operator
--    see the cross-tenant admin dashboard without that being tied to
--    "owns tenant X" semantics. Set manually via scripts/set-admin-password.js.
-- ============================================================================
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_platform_admin BOOLEAN NOT NULL DEFAULT FALSE;

-- ============================================================================
-- 3. FOLLOW-GATE FIELDS ON CAMPAIGNS
--    require_follow_gate: when true, a comment match sends gate_message_text
--    first (with an "I Followed" quick-reply button) instead of the reward
--    directly. dm_message_text and redirect_url are reused as the reward
--    message/asset URL, sent once the user taps the button.
-- ============================================================================
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS require_follow_gate BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS gate_message_text TEXT;
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS reward_type VARCHAR(20) NOT NULL DEFAULT 'link';

ALTER TABLE campaigns DROP CONSTRAINT IF EXISTS chk_campaigns_reward_type;
ALTER TABLE campaigns ADD CONSTRAINT chk_campaigns_reward_type
    CHECK (reward_type IN ('link', 'pdf', 'text'));

-- ============================================================================
-- 4. FOLLOW_GATE_EVENTS — tracks the two-stage flow per (campaign, comment).
--    Kept separate from dm_delivery_events, which stays focused on the final
--    reward send (its existing 'queued'/'sent'/'failed' semantics didn't
--    have room for "waiting on the user to tap a button").
-- ============================================================================
CREATE TABLE IF NOT EXISTS follow_gate_events (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    campaign_id      UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    ig_comment_id    VARCHAR(64) NOT NULL,
    ig_commenter_id  VARCHAR(64) NOT NULL,
    status           VARCHAR(20) NOT NULL DEFAULT 'gate_sent'
                         CHECK (status IN ('gate_sent', 'confirmed', 'reward_sent', 'failed')),
    error_message    TEXT,
    gate_sent_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_at     TIMESTAMPTZ,
    reward_sent_at   TIMESTAMPTZ,
    CONSTRAINT uq_follow_gate_events_comment UNIQUE (campaign_id, ig_comment_id)
);

CREATE INDEX IF NOT EXISTS idx_follow_gate_events_tenant_id ON follow_gate_events (tenant_id);
CREATE INDEX IF NOT EXISTS idx_follow_gate_events_commenter ON follow_gate_events (campaign_id, ig_commenter_id);

ALTER TABLE follow_gate_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE follow_gate_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_follow_gate_events ON follow_gate_events;
CREATE POLICY tenant_isolation_follow_gate_events ON follow_gate_events
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- ============================================================================
-- 5. PLATFORM-ADMIN RLS BYPASS POLICIES
--    Second permissive policy per tenant-scoped table. Postgres ORs
--    permissive policies together, so a row is visible if EITHER the
--    tenant-isolation policy matches OR this one does (app.is_platform_admin
--    set to 'true', via lib/db.js withAdmin() — only reachable after the
--    HTTP-layer requireAdmin check in server.js).
-- ============================================================================
DROP POLICY IF EXISTS platform_admin_bypass_users ON users;
CREATE POLICY platform_admin_bypass_users ON users
    USING (current_setting('app.is_platform_admin', true) = 'true');

DROP POLICY IF EXISTS platform_admin_bypass_connected_accounts ON connected_accounts;
CREATE POLICY platform_admin_bypass_connected_accounts ON connected_accounts
    USING (current_setting('app.is_platform_admin', true) = 'true');

DROP POLICY IF EXISTS platform_admin_bypass_campaigns ON campaigns;
CREATE POLICY platform_admin_bypass_campaigns ON campaigns
    USING (current_setting('app.is_platform_admin', true) = 'true');

DROP POLICY IF EXISTS platform_admin_bypass_dm_delivery_events ON dm_delivery_events;
CREATE POLICY platform_admin_bypass_dm_delivery_events ON dm_delivery_events
    USING (current_setting('app.is_platform_admin', true) = 'true');

DROP POLICY IF EXISTS platform_admin_bypass_follow_gate_events ON follow_gate_events;
CREATE POLICY platform_admin_bypass_follow_gate_events ON follow_gate_events
    USING (current_setting('app.is_platform_admin', true) = 'true');

DROP POLICY IF EXISTS platform_admin_bypass_tenants ON tenants;
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
CREATE POLICY platform_admin_bypass_tenants ON tenants
    USING (current_setting('app.is_platform_admin', true) = 'true');
-- Note: tenants was NOT force-RLS'd in the baseline migration and has no
-- tenant_id column of its own (it IS the tenant) -- this bypass policy is
-- additive only; queryUnscoped() reads on `tenants` are unaffected since
-- RLS without FORCE still lets the owning role through regardless.

COMMIT;
