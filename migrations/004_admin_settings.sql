-- ============================================================================
-- NexusKit — migration 004: platform admin control center.
--
-- Adds: username + 2FA + theme preference on users; a singleton
-- platform_settings row for SMTP / payment gateways / channel toggles
-- (secrets stored AES-256-GCM encrypted via lib/tokenCipher.js
-- encryptSecret/decryptSecret -- one BYTEA column per secret, packed as
-- iv+authTag+ciphertext); payment_plans; and notifications (in-app +
-- email-send audit trail).
--
-- Written to be safely re-runnable (IF NOT EXISTS / DROP ... IF EXISTS +
-- CREATE), same convention as migrations 002 and 003.
-- ============================================================================

BEGIN;

-- ============================================================================
-- 1. USERS — username, 2FA, theme preference
-- ============================================================================
ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_encrypted BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS theme_preference VARCHAR(10) NOT NULL DEFAULT 'light';
ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_users_theme_preference;
ALTER TABLE users ADD CONSTRAINT chk_users_theme_preference CHECK (theme_preference IN ('light', 'dark'));

-- Case-insensitive uniqueness per tenant, same pattern as email; NULLs
-- (no username set yet) are simply not indexed by a partial unique index.
DROP INDEX IF EXISTS uq_users_tenant_username;
CREATE UNIQUE INDEX uq_users_tenant_username ON users (tenant_id, lower(username)) WHERE username IS NOT NULL;

-- ============================================================================
-- 2. PLATFORM_SETTINGS — singleton row (id is always 1). Platform-level
--    because these are the app-level credentials (SMTP relay, payment
--    gateway API keys, social platform developer app secrets) that the
--    whole NexusKit deployment runs on -- distinct from a tenant's own
--    connected_accounts (e.g. their individual Instagram Business Account).
-- ============================================================================
CREATE TABLE IF NOT EXISTS platform_settings (
    id                              SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),

    -- SMTP (for sending custom/system emails)
    smtp_host                       TEXT,
    smtp_port                       INTEGER,
    smtp_username                   TEXT,
    smtp_password_encrypted         BYTEA,
    smtp_from_email                 TEXT,
    smtp_secure                     BOOLEAN NOT NULL DEFAULT TRUE,

    -- Stripe
    stripe_enabled                  BOOLEAN NOT NULL DEFAULT FALSE,
    stripe_publishable_key          TEXT,
    stripe_secret_key_encrypted     BYTEA,

    -- PayPal
    paypal_enabled                  BOOLEAN NOT NULL DEFAULT FALSE,
    paypal_client_id                TEXT,
    paypal_client_secret_encrypted  BYTEA,

    -- Safepay
    safepay_enabled                 BOOLEAN NOT NULL DEFAULT FALSE,
    safepay_api_key_encrypted       BYTEA,
    safepay_secret_key_encrypted    BYTEA,

    -- PayFast
    payfast_enabled                 BOOLEAN NOT NULL DEFAULT FALSE,
    payfast_merchant_id             TEXT,
    payfast_merchant_key_encrypted  BYTEA,
    payfast_passphrase_encrypted    BYTEA,

    -- Channels (feature flag + platform-level developer-app credentials;
    -- a tenant's individual account connection still lives in
    -- connected_accounts once a channel is enabled)
    instagram_enabled               BOOLEAN NOT NULL DEFAULT TRUE,
    tiktok_enabled                  BOOLEAN NOT NULL DEFAULT FALSE,
    tiktok_client_key               TEXT,
    tiktok_client_secret_encrypted  BYTEA,
    youtube_enabled                 BOOLEAN NOT NULL DEFAULT FALSE,
    youtube_client_id               TEXT,
    youtube_client_secret_encrypted BYTEA,
    twitter_enabled                 BOOLEAN NOT NULL DEFAULT FALSE,
    twitter_api_key                 TEXT,
    twitter_api_secret_encrypted    BYTEA,

    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by                      UUID REFERENCES users(id)
);

INSERT INTO platform_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
-- Deliberately NOT RLS'd: there is exactly one row, it's platform-wide
-- config, and every access path already goes through requireAdmin in
-- server.js before this table is ever touched.

-- ============================================================================
-- 3. PAYMENT_PLANS — platform-level plan catalog (name, price, features)
-- ============================================================================
CREATE TABLE IF NOT EXISTS payment_plans (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              VARCHAR(100) NOT NULL,
    price_cents       INTEGER NOT NULL DEFAULT 0,
    currency          VARCHAR(3) NOT NULL DEFAULT 'USD',
    billing_interval  VARCHAR(10) NOT NULL DEFAULT 'month'
                          CHECK (billing_interval IN ('month', 'year', 'one_time')),
    features          JSONB NOT NULL DEFAULT '[]',
    is_active         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- 4. NOTIFICATIONS — in-app messages sent by an admin to a user (or
--    broadcast to an entire tenant / everyone). Also doubles as the audit
--    trail for "send custom email" (channel = 'email').
-- ============================================================================
CREATE TABLE IF NOT EXISTS notifications (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID REFERENCES tenants(id) ON DELETE CASCADE, -- NULL = platform-wide broadcast
    user_id      UUID REFERENCES users(id) ON DELETE CASCADE,   -- NULL = broadcast to whole tenant
    channel      VARCHAR(10) NOT NULL DEFAULT 'in_app' CHECK (channel IN ('in_app', 'email')),
    title        VARCHAR(255) NOT NULL,
    body         TEXT NOT NULL,
    sent_by      UUID REFERENCES users(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications (user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_tenant_id ON notifications (tenant_id);
-- Deliberately NOT RLS'd, same reasoning as `sessions`: notifications are
-- looked up by user_id (with NULL-tenant broadcasts needing to be visible
-- to everyone), which doesn't fit the single tenant_id-equality policy
-- shape. Every read is explicitly scoped to req.user.id in application code.

COMMIT;
