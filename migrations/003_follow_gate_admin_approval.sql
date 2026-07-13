-- ============================================================================
-- NexusKit — migration 003: require explicit admin approval before the
-- reward DM is sent, instead of auto-sending the instant a customer taps
-- "I Followed".
--
-- Why: Instagram's API has no endpoint to verify whether an arbitrary user
-- actually follows a business account -- the "I Followed" button tap is
-- purely a self-report from the commenter. Per the original spec ("i'll
-- validate everytime they click on button that says, followed"), that
-- validation is a human (the tenant admin/owner) step, not an automatic one.
-- This migration adds an 'approved' status between 'confirmed' (tapped,
-- awaiting review) and 'reward_sent' (delivered), so the actual send only
-- happens after an authenticated dashboard user explicitly approves it.
-- ============================================================================

BEGIN;

ALTER TABLE follow_gate_events DROP CONSTRAINT IF EXISTS follow_gate_events_status_check;
ALTER TABLE follow_gate_events ADD CONSTRAINT follow_gate_events_status_check
    CHECK (status IN ('gate_sent', 'confirmed', 'approved', 'reward_sent', 'failed'));

ALTER TABLE follow_gate_events ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;
ALTER TABLE follow_gate_events ADD COLUMN IF NOT EXISTS approved_by UUID REFERENCES users(id);

COMMIT;
