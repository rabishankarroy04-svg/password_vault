-- Applied only after schema initialization, in the bootstrap transaction.
GRANT CONNECT ON DATABASE securevault_db TO securevault_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO securevault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    roles, users, user_roles, sessions, devices, login_mfa_challenges,
    vaults, vault_members, folders, categories, tags, credentials,
    tag_mappings, attachments, sharing, security_events, blocked_ips,
    notifications, password_health, login_stats TO securevault_app;
REVOKE ALL ON audit_logs, security_event_history FROM securevault_app;
GRANT SELECT, INSERT ON audit_logs, security_event_history TO securevault_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO securevault_app;
-- No broad defaults: future migrations must grant their own permissions.
REVOKE ALL ON securevault_bootstrap_state FROM PUBLIC, securevault_app;

-- Alert deletion would cascade away protected investigation history. No application API needs it.
REVOKE DELETE ON security_events FROM securevault_app;
