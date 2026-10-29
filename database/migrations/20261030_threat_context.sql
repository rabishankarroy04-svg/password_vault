-- Additive threat-context migration. Review and run with the schema owner during deployment.
-- Does not alter accounts, MFA enrollment, credentials, vault contents or Docker volumes.
BEGIN;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS context jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS detection_context jsonb;
CREATE TABLE IF NOT EXISTS threat_detection_settings (
 rule_name varchar(100) PRIMARY KEY, threshold integer NOT NULL CHECK(threshold BETWEEN 1 AND 10000),
 window_minutes integer NOT NULL CHECK(window_minutes BETWEEN 1 AND 1440),
 cooldown_minutes integer NOT NULL CHECK(cooldown_minutes BETWEEN 1 AND 10080)
);
INSERT INTO threat_detection_settings VALUES
 ('SUSPICIOUS_VAULT_ACCESS',20,5,30),('CREDENTIAL_SHARED',5,5,15),
 ('VAULT_ACCESS_DENIED',5,5,15),('ROLE_CHANGED',3,10,30),('SHARING_NEW_RECIPIENTS',3,5,15)
ON CONFLICT DO NOTHING;
GRANT SELECT ON threat_detection_settings TO securevault_app;
REVOKE INSERT,UPDATE,DELETE ON threat_detection_settings FROM securevault_app;
REVOKE DELETE ON security_events FROM securevault_app;
-- Evidence is captured once (or atomically refreshed on escalation). Do not correlate
-- both security and audit copies of the same login or include subsequent activity.
CREATE OR REPLACE FUNCTION securevault_alert_evidence(alert_id uuid)
RETURNS TABLE(id uuid,action_type text,status text,ip_address varchar,details text,"timestamp" timestamptz)
LANGUAGE sql STABLE AS $$
 SELECT l.id,l.action_type::text,l.status::text,l.ip_address,l.details,l.timestamp
 FROM security_events e JOIN audit_logs l ON
 EXISTS(SELECT 1 FROM jsonb_array_elements_text(COALESCE(e.detection_context->'evidenceAuditIds','[]'::jsonb)) a WHERE a.value=l.id::text)
 WHERE e.id=alert_id
 UNION ALL
 -- Historical thresholds/windows were not stored. Show the actual original alert
 -- as the sole evidence, not fabricated retrospective configuration or broad matches.
 SELECT e.id,e.event_type::text,e.severity::text,e.ip_address,
 'Legacy alert record. Original detection configuration/evidence snapshot unavailable. '||COALESCE(e.detection_reason,''),e.timestamp
 FROM security_events e WHERE e.id=alert_id AND e.detection_context IS NULL
 ORDER BY 6 DESC,1 LIMIT 100
$$;
CREATE OR REPLACE FUNCTION securevault_detect_vault_access_burst() RETURNS trigger AS $$
DECLARE cfg threat_detection_settings; n integer; ids jsonb;
BEGIN
 IF NEW.status<>'SUCCESS' OR NEW.action_type LIKE 'CREDENTIAL_SHARE%' OR NEW.action_type LIKE 'SHARE_%' OR (NEW.action_type NOT ILIKE 'VAULT_%' AND NEW.action_type NOT ILIKE 'CREDENTIAL_%') THEN RETURN NEW; END IF;
 SELECT * INTO cfg FROM threat_detection_settings WHERE rule_name='SUSPICIOUS_VAULT_ACCESS';
 PERFORM pg_advisory_xact_lock(hashtextextended('vault:'||COALESCE(NEW.user_id::text,'unknown')||NEW.ip_address,0));
 SELECT count(*),jsonb_agg(l.id ORDER BY l.timestamp,l.id) INTO n,ids FROM audit_logs l
 WHERE l.user_id IS NOT DISTINCT FROM NEW.user_id AND l.ip_address=NEW.ip_address AND l.status='SUCCESS'
 AND (l.action_type ILIKE 'VAULT_%' OR l.action_type ILIKE 'CREDENTIAL_%') AND l.action_type NOT LIKE 'CREDENTIAL_SHARE%'
 AND l.timestamp BETWEEN NEW.timestamp-make_interval(mins=>cfg.window_minutes) AND NEW.timestamp;
 IF n>=cfg.threshold AND NOT EXISTS(SELECT 1 FROM security_events e WHERE e.event_type=cfg.rule_name AND e.user_id IS NOT DISTINCT FROM NEW.user_id AND e.ip_address=NEW.ip_address AND e.timestamp>=NEW.timestamp-make_interval(mins=>cfg.cooldown_minutes)) THEN
 INSERT INTO security_events(user_id,event_type,severity,risk_score,anomaly_detected,ip_address,alert_title,detection_reason,detection_context,timestamp)
 VALUES(NEW.user_id,cfg.rule_name,'HIGH',80,true,NEW.ip_address,'Unusual vault activity burst',
 format('Rule %s: %s successful actions >= threshold %s within %s minutes; HIGH (80) due to burst threshold.',cfg.rule_name,n,cfg.threshold,cfg.window_minutes),
 NEW.context||jsonb_build_object('threshold',cfg.threshold,'windowMinutes',cfg.window_minutes,'eventCount',n,'riskFactors',jsonb_build_array(cfg.rule_name),'evidenceAuditIds',ids,'suggestedAction','Review source operations and account permissions; never retrieve credential plaintext for this investigation.'),NEW.timestamp);
 END IF;RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION securevault_detect_credential_sharing() RETURNS trigger AS $$
DECLARE cfg threat_detection_settings; recipient_cfg threat_detection_settings; n integer; ids jsonb; escalation boolean; recipients integer;
BEGIN
 IF NEW.action_type NOT IN('CREDENTIAL_SHARED','SHARING_PERMISSION_CHANGED','CREDENTIAL_SHARE_DENIED','SHARE_PERMISSION_CHANGED','SHARE_REVOKED') AND NEW.action_type NOT LIKE 'CREDENTIAL_SHARE_%' AND NEW.action_type NOT LIKE 'SHARE_PERMISSION_%' THEN RETURN NEW; END IF;
 SELECT * INTO cfg FROM threat_detection_settings WHERE rule_name='CREDENTIAL_SHARED';
 SELECT * INTO recipient_cfg FROM threat_detection_settings WHERE rule_name='SHARING_NEW_RECIPIENTS';
 PERFORM pg_advisory_xact_lock(hashtextextended('sharing:'||COALESCE(NEW.user_id::text,'unknown')||NEW.ip_address,0));
 SELECT count(*),jsonb_agg(l.id ORDER BY l.timestamp,l.id) INTO n,ids FROM audit_logs l
 WHERE l.user_id IS NOT DISTINCT FROM NEW.user_id AND l.ip_address=NEW.ip_address
 AND (l.action_type IN('CREDENTIAL_SHARED','SHARING_PERMISSION_CHANGED','CREDENTIAL_SHARE_DENIED','SHARE_PERMISSION_CHANGED','SHARE_REVOKED') OR l.action_type LIKE 'CREDENTIAL_SHARE_%' OR l.action_type LIKE 'SHARE_PERMISSION_%')
 AND l.timestamp BETWEEN NEW.timestamp-make_interval(mins=>cfg.window_minutes) AND NEW.timestamp;
 SELECT count(DISTINCT l.context->>'recipientRef') INTO recipients FROM audit_logs l
 WHERE l.user_id IS NOT DISTINCT FROM NEW.user_id AND l.ip_address=NEW.ip_address
 AND l.action_type='CREDENTIAL_SHARED' AND l.context->>'recipientIsNew'='true'
 AND l.timestamp BETWEEN NEW.timestamp-make_interval(mins=>LEAST(cfg.window_minutes,recipient_cfg.window_minutes)) AND NEW.timestamp;
 escalation=COALESCE(NEW.context->>'permissionEscalation','false')='true' OR recipients>=recipient_cfg.threshold;
 IF (n>=cfg.threshold OR escalation) AND NOT EXISTS(SELECT 1 FROM security_events e WHERE e.event_type=cfg.rule_name AND e.user_id IS NOT DISTINCT FROM NEW.user_id AND e.ip_address=NEW.ip_address AND e.timestamp>=NEW.timestamp-make_interval(mins=>cfg.cooldown_minutes)) THEN
 INSERT INTO security_events(user_id,event_type,severity,risk_score,anomaly_detected,ip_address,alert_title,detection_reason,detection_context,timestamp)
 VALUES(NEW.user_id,cfg.rule_name,CASE WHEN escalation THEN 'HIGH' ELSE 'MEDIUM' END,CASE WHEN escalation THEN 75 ELSE 50 END,true,NEW.ip_address,'Unusual credential sharing activity',
 format('Rule sharing: %s events; threshold %s within %s minutes; permission escalation or new-recipient threshold=%s. Severity %s; review legitimate sharing context.',n,cfg.threshold,cfg.window_minutes,escalation,CASE WHEN escalation THEN 'HIGH' ELSE 'MEDIUM' END),
 NEW.context||jsonb_build_object('threshold',cfg.threshold,'windowMinutes',cfg.window_minutes,'eventCount',n,'riskFactors',jsonb_build_array('SHARING_ACTIVITY'),'newRecipientCount',recipients,'newRecipientThreshold',recipient_cfg.threshold,'newRecipientWindowMinutes',LEAST(cfg.window_minutes,recipient_cfg.window_minutes),'evidenceAuditIds',ids,'suggestedAction','Review recipient references, authorization decisions and sharing scope with the owner.'),NEW.timestamp);
 END IF;RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION securevault_detect_permission_activity() RETURNS trigger AS $$
DECLARE cfg threat_detection_settings; typ text; n integer; ids jsonb; escalation boolean;
BEGIN
 IF NEW.action_type IN('USER_ROLE_CHANGED','ROLE_CHANGED') THEN typ='ROLE_CHANGED';
 ELSIF NEW.action_type='VAULT_ACCESS_DENIED' THEN typ='VAULT_ACCESS_DENIED';ELSE RETURN NEW;END IF;
 SELECT * INTO cfg FROM threat_detection_settings WHERE rule_name=typ;
 PERFORM pg_advisory_xact_lock(hashtextextended(typ||COALESCE(NEW.user_id::text,'unknown')||NEW.ip_address,0));
 SELECT count(*),jsonb_agg(l.id ORDER BY l.timestamp,l.id) INTO n,ids FROM audit_logs l
 WHERE l.user_id IS NOT DISTINCT FROM NEW.user_id AND l.ip_address=NEW.ip_address
 AND (l.action_type=NEW.action_type OR (typ='ROLE_CHANGED' AND l.action_type IN('USER_ROLE_CHANGED','ROLE_CHANGED')))
 AND l.timestamp BETWEEN NEW.timestamp-make_interval(mins=>cfg.window_minutes) AND NEW.timestamp;
 escalation=COALESCE(NEW.context->>'permissionEscalation','false')='true';
 IF (n>=cfg.threshold OR escalation) AND NOT EXISTS(SELECT 1 FROM security_events e WHERE e.event_type=typ AND e.user_id IS NOT DISTINCT FROM NEW.user_id AND e.ip_address=NEW.ip_address AND e.timestamp>=NEW.timestamp-make_interval(mins=>cfg.cooldown_minutes)) THEN
 INSERT INTO security_events(user_id,event_type,severity,risk_score,anomaly_detected,ip_address,alert_title,detection_reason,detection_context,timestamp)
 VALUES(NEW.user_id,typ,'HIGH',75,true,NEW.ip_address,'Permission activity requires review',
 format('Rule %s: %s events; threshold %s within %s minutes; privilege escalation=%s. HIGH (75) because repetition or explicit privilege elevation requires review.',typ,n,cfg.threshold,cfg.window_minutes,escalation),
 NEW.context||jsonb_build_object('threshold',cfg.threshold,'windowMinutes',cfg.window_minutes,'eventCount',n,'riskFactors',jsonb_build_array(typ),'evidenceAuditIds',ids,'suggestedAction','Verify authorization and change approval with an independent administrator.'),NEW.timestamp);
 END IF;RETURN NEW;
END $$ LANGUAGE plpgsql;
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='trg_securevault_permission_activity') THEN
 CREATE TRIGGER trg_securevault_permission_activity AFTER INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION securevault_detect_permission_activity();
END IF;END $$;
COMMIT;
