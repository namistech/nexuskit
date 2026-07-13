-- ============================================================================
-- NexusKit — Instagram Comment-to-DM Automation Platform
-- migration.sql — initial schema (PostgreSQL 14+)
--
-- Multi-tenant isolation strategy:
--   Every tenant-scoped table carries a NOT NULL tenant_id FK to `tenants`.
--   Row-Level Security policies (bottom of file) enforce that a connection
--   can only see/modify rows whose tenant_id matches the session variable
--   `app.current_tenant_id`. Application code MUST set that variable inside
--   a transaction before touching these tables — see lib/db.js `withTenant`.
--   This makes tenant isolation a database-enforced guarantee, not just an
--   application-layer convention that a missing WHERE clause could break.
-- ============================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- provides gen_random_uuid() on PG < 13

-- ============================================================================
-- 0. TENANTS
-- ============================================================================
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) NOT NULL UNIQUE,
    billing_tier    VARCHAR(50) NOT NULL DEFAULT 'trial'
                        CHECK (billing_tier IN ('trial', 'starter', 'growth', 'scale', 'enterprise')),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- 1. USERS
--    Secure passwords (bcrypt/argon2id hash only — never plaintext), profile
--    fields, and a billing tier token (Stripe/PayPal customer or subscription
--    reference) per STEP 3.1 requirement.
-- ============================================================================
CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email               VARCHAR(255) NOT NULL,
    password_hash       VARCHAR(255) NOT NULL,  -- bcrypt (cost>=12) or argon2id output
    full_name           VARCHAR(255),
    role                VARCHAR(30) NOT NULL DEFAULT 'owner'
                            CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    billing_tier_token  VARCHAR(255),            -- Stripe customer_id / PayPal subscription id
    is_email_verified   BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Case-insensitive uniqueness per tenant without requiring the citext extension.
CREATE UNIQUE INDEX uq_users_tenant_email ON users (tenant_id, lower(email));
CREATE INDEX idx_users_tenant_id ON users (tenant_id);

-- ============================================================================
-- 2. CONNECTED_ACCOUNTS
--    Encrypted Meta OAuth access tokens + platform identifiers. Tokens are
--    encrypted at the application layer (AES-256-GCM, see lib/tokenCipher.js)
--    before insert — the DB only ever stores ciphertext + IV + auth tag.
-- ============================================================================
CREATE TABLE connected_accounts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id                 UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    platform                VARCHAR(30) NOT NULL DEFAULT 'instagram'
                                CHECK (platform IN ('instagram', 'facebook')),
    ig_business_account_id  VARCHAR(64) NOT NULL,   -- Meta IG Business Account ID (webhook entry.id)
    ig_username             VARCHAR(255),
    fb_page_id              VARCHAR(64),            -- only set for the classic Page-linked
                                                       -- flow; NULL for Instagram API with
                                                       -- Instagram Login (no Page involved)
    access_token_encrypted  BYTEA NOT NULL,          -- AES-256-GCM ciphertext
    access_token_iv         BYTEA NOT NULL,          -- 12-byte IV, unique per encryption
    access_token_auth_tag   BYTEA NOT NULL,          -- GCM auth tag
    token_expires_at        TIMESTAMPTZ,
    scopes                  TEXT[] NOT NULL DEFAULT '{}',
    status                  VARCHAR(20) NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active', 'revoked', 'expired', 'error')),
    last_synced_at          TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_connected_accounts_page UNIQUE (tenant_id, fb_page_id)
);

CREATE INDEX idx_connected_accounts_tenant_id ON connected_accounts (tenant_id);
-- Hot path: webhook lookup by ig_business_account_id happens on every inbound comment.
CREATE INDEX idx_connected_accounts_ig_business_account_id ON connected_accounts (ig_business_account_id)
    WHERE status = 'active';

-- ============================================================================
-- 3. CAMPAIGNS
--    Target trigger keywords, DM text output, and redirect URL per STEP 3.1.
-- ============================================================================
CREATE TABLE campaigns (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connected_account_id  UUID NOT NULL REFERENCES connected_accounts(id) ON DELETE CASCADE,
    name                  VARCHAR(255) NOT NULL,
    trigger_keywords      TEXT[] NOT NULL,  -- store lowercase/normalized; app layer enforces this
    match_mode            VARCHAR(20) NOT NULL DEFAULT 'contains'
                              CHECK (match_mode IN ('exact', 'contains', 'starts_with')),
    dm_message_text       TEXT NOT NULL,
    redirect_url          TEXT,
    is_active             BOOLEAN NOT NULL DEFAULT TRUE,
    daily_send_cap        INTEGER NOT NULL DEFAULT 500,
    total_triggers        BIGINT NOT NULL DEFAULT 0,
    total_dms_sent        BIGINT NOT NULL DEFAULT 0,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_trigger_keywords_not_empty CHECK (array_length(trigger_keywords, 1) > 0)
);

CREATE INDEX idx_campaigns_tenant_id ON campaigns (tenant_id);
CREATE INDEX idx_campaigns_connected_account_id ON campaigns (connected_account_id);
-- Hot path: webhook matches an incoming comment against active campaigns for the account.
CREATE INDEX idx_campaigns_active_lookup ON campaigns (connected_account_id) WHERE is_active = TRUE;
CREATE INDEX idx_campaigns_trigger_keywords_gin ON campaigns USING GIN (trigger_keywords);

-- ============================================================================
-- 4. DM_DELIVERY_EVENTS
--    One row per (campaign, comment) — idempotency guard against Meta webhook
--    retries, and the source of truth for the dashboard's live volume counters.
-- ============================================================================
CREATE TABLE dm_delivery_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    campaign_id     UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    ig_comment_id   VARCHAR(64) NOT NULL,
    ig_commenter_id VARCHAR(64) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'sent', 'failed', 'skipped_rate_limit', 'skipped_duplicate')),
    error_message   TEXT,
    queued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at         TIMESTAMPTZ,
    CONSTRAINT uq_dm_delivery_events_comment UNIQUE (campaign_id, ig_comment_id)
);

CREATE INDEX idx_dm_delivery_events_tenant_id ON dm_delivery_events (tenant_id);
CREATE INDEX idx_dm_delivery_events_campaign_status ON dm_delivery_events (campaign_id, status);
CREATE INDEX idx_dm_delivery_events_queued_at ON dm_delivery_events (queued_at DESC);

-- ============================================================================
-- 5. updated_at maintenance trigger
-- ============================================================================
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenants_updated_at
    BEFORE UPDATE ON tenants FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_connected_accounts_updated_at
    BEFORE UPDATE ON connected_accounts FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_campaigns_updated_at
    BEFORE UPDATE ON campaigns FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================================
-- 6. ROW-LEVEL SECURITY — hard multi-tenant isolation layer
--    Requires application code to run tenant-scoped queries via a transaction
--    that sets app.current_tenant_id (see lib/db.js withTenant()).
-- ============================================================================
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE connected_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE dm_delivery_events ENABLE ROW LEVEL SECURITY;

ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE connected_accounts FORCE ROW LEVEL SECURITY;
ALTER TABLE campaigns FORCE ROW LEVEL SECURITY;
ALTER TABLE dm_delivery_events FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_users ON users
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

CREATE POLICY tenant_isolation_connected_accounts ON connected_accounts
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

CREATE POLICY tenant_isolation_campaigns ON campaigns
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

CREATE POLICY tenant_isolation_dm_delivery_events ON dm_delivery_events
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

COMMIT;
