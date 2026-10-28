-- ============================================================================
-- WAKeep Hardened Database Schema & Row Level Security (RLS) Configuration
-- Run this script in your Supabase SQL Editor (South Asia Mumbai or your region)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Table Creation: wa_auth_vault
-- Stores AES-256-GCM encrypted multi-device companion tokens and pre-keys.
-- Zero chat messages, audio, or media are stored.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.wa_auth_vault (
    id TEXT PRIMARY KEY,
    encrypted_payload TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc'::TEXT, NOW()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc'::TEXT, NOW())
);

-- Index for fast key lookup
CREATE INDEX IF NOT EXISTS idx_wa_auth_vault_updated_at ON public.wa_auth_vault (updated_at DESC);

-- Automatic timestamp updater trigger
CREATE OR REPLACE FUNCTION public.touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = TIMEZONE('utc'::TEXT, NOW());
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_touch_wa_auth_vault ON public.wa_auth_vault;
CREATE TRIGGER trigger_touch_wa_auth_vault
    BEFORE UPDATE ON public.wa_auth_vault
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();

-- ----------------------------------------------------------------------------
-- 2. Drop Legacy Message Table (Strict Zero Data Collection Compliance)
-- ----------------------------------------------------------------------------
DROP TABLE IF EXISTS public.wa_recent_messages CASCADE;
DROP FUNCTION IF EXISTS public.prune_old_wa_messages CASCADE;

-- ----------------------------------------------------------------------------
-- 3. Row Level Security (RLS) & Permission Lockdown
-- ----------------------------------------------------------------------------
-- Enable and force RLS on the vault table
ALTER TABLE public.wa_auth_vault ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.wa_auth_vault FORCE ROW LEVEL SECURITY;

-- Revoke all direct privileges from public / unauthenticated / client roles
REVOKE ALL ON TABLE public.wa_auth_vault FROM anon;
REVOKE ALL ON TABLE public.wa_auth_vault FROM authenticated;
REVOKE ALL ON TABLE public.wa_auth_vault FROM public;

-- Grant access strictly and exclusively to service_role (used by WAKeep backend server)
GRANT ALL ON TABLE public.wa_auth_vault TO service_role;

-- ----------------------------------------------------------------------------
-- 4. Definitive RLS Policies
-- ----------------------------------------------------------------------------
-- Drop any previous or conflicting policies
DROP POLICY IF EXISTS "Deny anon all access" ON public.wa_auth_vault;
DROP POLICY IF EXISTS "Deny authenticated client all access" ON public.wa_auth_vault;
DROP POLICY IF EXISTS "Service role has full access to auth vault" ON public.wa_auth_vault;
DROP POLICY IF EXISTS "Service role full access" ON public.wa_auth_vault;

-- Policy 1: Explicitly DENY all read, insert, update, and delete actions for anon role
CREATE POLICY "Deny anon all access"
    ON public.wa_auth_vault
    FOR ALL
    TO anon
    USING (false)
    WITH CHECK (false);

-- Policy 2: Explicitly DENY all read, insert, update, and delete actions for authenticated clients
CREATE POLICY "Deny authenticated client all access"
    ON public.wa_auth_vault
    FOR ALL
    TO authenticated
    USING (false)
    WITH CHECK (false);

-- Policy 3: Allow service_role complete access for backend synchronization
CREATE POLICY "Service role full access"
    ON public.wa_auth_vault
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- ============================================================================
-- 5. RLS & Permission Verification Test Queries
-- Copy and run these queries in Supabase SQL Editor to test permissions:
-- ============================================================================
/*
-- TEST A: Attempting to READ (SELECT) as public anon role (Must return 0 rows or error)
SET ROLE anon;
SELECT * FROM public.wa_auth_vault;
RESET ROLE;

-- TEST B: Attempting to CREATE (INSERT) as public anon role (Must fail with permission/RLS violation)
SET ROLE anon;
INSERT INTO public.wa_auth_vault (id, encrypted_payload) VALUES ('test_hacked', 'dummy_payload');
RESET ROLE;

-- TEST C: Attempting to UPDATE as public anon role (Must affect 0 rows or fail)
SET ROLE anon;
UPDATE public.wa_auth_vault SET encrypted_payload = 'malicious' WHERE id = 'main_session:creds.json';
RESET ROLE;

-- TEST D: Attempting to DELETE as public anon role (Must affect 0 rows or fail)
SET ROLE anon;
DELETE FROM public.wa_auth_vault WHERE id = 'main_session:creds.json';
RESET ROLE;

-- TEST E: Verify service_role full access (Must succeed)
SET ROLE service_role;
SELECT COUNT(*) FROM public.wa_auth_vault;
RESET ROLE;
*/
