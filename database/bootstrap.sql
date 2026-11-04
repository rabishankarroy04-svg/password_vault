\set ON_ERROR_STOP on
-- The caller supplies --single-transaction. Serialize concurrent bootstraps.
SELECT pg_advisory_xact_lock(732643281);
SET LOCAL search_path = public, pg_catalog;
DO $$
BEGIN
    IF current_database() <> 'securevault_db' OR current_user <> 'postgres' THEN
        RAISE EXCEPTION 'Bootstrap requires postgres in securevault_db';
    END IF;
    IF to_regclass('public.securevault_bootstrap_state') IS NULL AND (
        EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                  AND n.nspname NOT LIKE 'pg_toast%')
        OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                   WHERE n.nspname = 'public')
    ) THEN
        RAISE EXCEPTION 'Unrecognized or partial schema; refusing initialization';
    END IF;
END $$;

SELECT to_regclass('public.securevault_bootstrap_state') IS NULL AS initialize \gset
\if :initialize
    \ir app-user.sql
    -- Fresh-only copy generated without DROP TRIGGER statements by Compose.
    \ir /tmp/schema-initial.sql
    CREATE TABLE securevault_bootstrap_state (
        version INTEGER PRIMARY KEY CHECK (version = 1)
    );
    INSERT INTO securevault_bootstrap_state VALUES (1);
\else
    DO $$
    DECLARE
        expected TEXT[] := ARRAY[
            'roles','users','user_roles','sessions','devices','login_mfa_challenges',
            'vaults','vault_members','folders','categories','tags','credentials',
            'tag_mappings','attachments','sharing','audit_logs','security_events',
            'security_event_history','blocked_ips','notifications','password_health',
            'login_stats','threat_detection_settings','securevault_bootstrap_state'];
    BEGIN
        IF (SELECT count(*) FROM securevault_bootstrap_state WHERE version = 1) <> 1
           OR EXISTS (SELECT 1 FROM unnest(expected) AS t(name)
                      WHERE to_regclass('public.' || name) IS NULL)
           OR EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public'
                      AND NOT (tablename = ANY(expected))
                      AND tablename NOT IN ('user_vault_categories','account_sensitive_attempts')) THEN
            RAISE EXCEPTION 'Unexpected or incomplete schema; manual migration required';
        END IF;
    END $$;
    \echo 'Recognized initialized schema; skipping schema and seed SQL.'
\endif
\ir app-privileges.sql
