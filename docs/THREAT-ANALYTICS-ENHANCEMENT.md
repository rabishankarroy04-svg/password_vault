# SecureVault threat analytics enhancement — October 30, 2026

## Scope and repository safety

Work performed in `password_vault/project`, branch `TEAM-3`, starting at `1869d2e` with a clean working tree. `mygithub` is the personal `akshaya-2k7/password_vault` remote; `origin` is the original team repository. No commits, pushes, merges, resets, branch switches, live application restarts, account changes, MFA enrollments, Docker volume changes or live schema migrations were performed. Payroll source was not edited.

The Admin dashboard is the **root React `src/` application**. `frontend/` is a separate account/vault shell and remains unchanged. Authentication uses the existing BCrypt/JWT/session/TOTP/email-MFA mechanisms. Both admin security layers remain active. A verified active non-admin session receives 403; absent/invalid sessions receive 401. Ordinary role claims supplied by clients never grant admin access.

## Inspection and implementation status

| Area | Existing implementation | Enhancement / boundary |
|---|---|---|
| Failed sign-ins | Per-failure alerts and a configurable 4-in-5-minute aggregate | Failures remain audit events; one aggregate incident stores actual threshold/window/evidence; escalation at threshold+2 updates it atomically |
| Supporting evidence | Different list/count queries, hardcoded windows, audit/security double copies | One canonical SQL function powers both; captured audit IDs exclude later events and duplicates; max 100 displayed/countable evidence records |
| Legacy alerts | Historical config was not stored | Show original legacy alert as one explicitly labeled evidence record; original thresholds/windows are unavailable, never replaced by today's settings |
| Denied requests | One alert per request plus repeated-denial alert | Every request is audited, aggregate alert at default 5 in 5 minutes, 15-minute cooldown; known account only when its active session is verified |
| Device identification | Pseudonymous device fingerprint and session user agent | Reuse those identities; coarse category/OS/browser and recognition state, no raw agent in new audit metadata or claim of a physical model/owner |
| Novel login patterns | Three separate novelty alerts | Combined explainable score; first success establishes a baseline, routine recognized login creates no alert; factors are also visible as audit activity |
| IP/proxy | Explicit trusted CIDRs, no forwarded-header trust by default | Preserved and regression-tested; private/Docker/loopback/VPN/documentation addresses cannot receive public-location claims |
| Location | No provider | Optional verified local IP-to-country/region provider; 30-day freshness, provenance and literal-public-IP checks; missing/unreliable means Location unavailable |
| Unusual time | 00:00–05:00 UTC after at least 5 prior successes, no known night pattern | Defaults preserved; hour/history/cooldown settings now configurable; combined incidents count toward cooldown |
| Role changes | Actual administrator password recheck and audit | Explicit target-ID/role/escalation metadata; elevated privileges or repeated changes generate explainable review alerts |
| Vault access | Tables and a burst trigger; **no real vault CRUD/access controller** | Existing burst threshold retained (20/5 minutes); repeated vault-denial detector prepared. Ownership enforcement requires the missing vault API; no placeholder endpoints or live fake events were created |
| Sharing | Tables and a trigger that alerted on every share; **no real sharing controller** | Configurable burst/new-recipient/permission-escalation/revocation signals from genuine audit events; ordinary single share does not alert. End-to-end sharing detection awaits source operations |
| Investigation | Open/Investigating/Resolved/False Positive, notes and reviewer history | Preserved; row lock makes concurrent previous-status history accurate; audit tables remain append-only for app role; deleting parent alerts is also revoked to prevent cascade removal of review history |
| Dashboard | Five required cards and daily severity chart | Preserved; actual selected-range type/status breakdown, success/failure counts, device/denial patterns, device context and filterable audit browser |
| Date boundaries | UTC daily grouping but session-local date filters | Explicit UTC boundaries now match across cards, charts and audit; verified near local midnight |
| Development password | Boot's unused default user auto-configuration | Excluded only generated-user auto-configuration; existing security filter chain, auth and MFA retained; context/log regression tests |

## Configuration and deterministic risk

Java settings live in `application.properties`; Compose forwards only environment names/defaults, never literal credentials.

- Existing failed-login threshold/window: `SECUREVAULT_FAILED_LOGIN_THRESHOLD=4`, `SECUREVAULT_FAILED_LOGIN_WINDOW_MINUTES=5`. Critical at threshold + 2. This is separate from the unchanged account lockout policy.
- Denials: `SECUREVAULT_DENIED_THRESHOLD=5`, `SECUREVAULT_DENIED_WINDOW_MINUTES=5`, `SECUREVAULT_DENIED_COOLDOWN_MINUTES=15`.
- Login weights: device 25, IP 20, location 20, unusual time 20. Environment names `SECUREVAULT_RISK_DEVICE_WEIGHT`, `SECUREVAULT_RISK_IP_WEIGHT`, `SECUREVAULT_RISK_LOCATION_WEIGHT`, `SECUREVAULT_RISK_TIME_WEIGHT`.
- Boundaries: medium 25, high 60, critical 85 (`SECUREVAULT_RISK_MEDIUM_SCORE`, `...HIGH_SCORE`, `...CRITICAL_SCORE`). Lower scores are Low. Values are validated and scoring is capped at 100.
- IP novelty and location novelty are **one network dimension**: use the larger configured network weight, never both. Device+network+unusual-time defaults to 65/High; device+network to 45/Medium. An unfamiliar device/IP is a review signal, not confirmed compromise. These weights replace the old separate 55/50 novelty alerts to reduce duplicate/noisy incidents.
- Single-login incidents retain the source login record and a 15-minute incident cooldown. Failed-login and denial windows keep their actual configured values in each alert. Threshold escalation replaces the incident context and evidence together.
- Unusual hours: `SECUREVAULT_UNUSUAL_START_HOUR=0`, `SECUREVAULT_UNUSUAL_END_HOUR=5` (end exclusive), `SECUREVAULT_UNUSUAL_MINIMUM_HISTORY=5`, `SECUREVAULT_UNUSUAL_COOLDOWN_HOURS=24`; comparison history is the last 30 days.
- SQL-backed vault/sharing/permission settings are in `threat_detection_settings`, editable by the schema owner, **read-only to the app**: vault burst 20/5/30, sharing 5/5/15, new recipients 3/5/15, vault denials 5/5/15, role changes 3/10/30 (threshold/window minutes/cooldown minutes). Effective new-recipient window is the smaller of its configured window and the sharing window, keeping evidence causal.

This is deterministic **rule-based analysis, not machine learning**. No security response automatically locks an account merely because of device/IP/location novelty. Existing authentication rate limits and lockout remain unchanged.

## Optional reliable geolocation

No external network service/API key is required or called by the default provider. `SECUREVAULT_GEO_FILE` can point to an operator-maintained Java properties file populated from a trustworthy licensed geolocation source. Each literal public-IP entry has this format:

`IP=COUNTRY_CODE|REGION|VERIFIED_UTC_DATE|SOURCE_NAME`

No populated production example or synthetic public-IP location is supplied. Country must be two uppercase letters; region/source are bounded; verification must not be future-dated or older than 30 days. Only configured exact matches are used; unavailable is not inferred from private IPs. With Docker, the configured file must be mounted read-only through an operator's local Compose override and the environment path must reference that container mount. Blank configuration is the default.

A first located login establishes history; later country/region novelty is compared to prior located successful logins. IP/country changes may reflect VPNs, travel or provider errors; the UI labels location approximate and recommends owner verification. `LocationProvider` is the extension point for a future reviewed provider with timeout/cache/error/privacy controls; no live third-party lookup was performed here.

`ClientIpResolver` ignores `X-Forwarded-For` unless the direct peer is in explicitly configured trusted proxy CIDRs. It walks from the trusted edge and stops at the first untrusted hop. Configure only proxies you control; never trust arbitrary headers or broad public ranges. Docker gateway `172.21.0.1` remains a private source with Location unavailable, not a public country.

## Genuine vault/sharing source integration contract

The missing vault/sharing module must authenticate the existing session, enforce ownership/membership/sharing permission on the backend, and persist its operation plus a **minimal** audit event in the same transaction. A denied attempt must be logged even though the requested action is rejected (avoid rolling its audit back with the denied business operation). Use 403 or non-disclosing 404 as appropriate. User B must never receive User A's private vault contents without permission. These functional operations and cross-user resource tests are **not implemented in this checkout**.

Use existing `audit_logs` fields: verified actor `user_id` (NULL only if genuinely unknown), `action_type`, `status` SUCCESS/FAILURE, trusted resolved `ip_address`, safe details and `context` JSON. Accepted sources include:

- `VAULT_READ`, `VAULT_OPEN`, `CREDENTIAL_READ`, other genuine `VAULT_*`/`CREDENTIAL_*` access actions: successful bursts.
- `VAULT_ACCESS_DENIED`: failure, repeated unauthorized resource access.
- `CREDENTIAL_SHARED`, `CREDENTIAL_SHARE_*`, `SHARING_PERMISSION_CHANGED`, `SHARE_PERMISSION_*`, `SHARE_REVOKED`: sharing/denial/permission/revocation activity.
- Optional safe sharing context: opaque `recipientRef`, boolean `recipientIsNew` calculated by the backend, boolean `permissionEscalation` calculated from actual authorization changes, opaque resource reference. Recipient counts are distinct; repeated same-recipient events do not inflate novelty.
- `USER_ROLE_CHANGED` is emitted by the existing role API with actual target reference, old/new roles and explicit elevation flag.

Do not accept event actor, permission outcome or escalation flags on an unauthenticated public telemetry endpoint. Never include credential titles/contents, passwords, JWTs, session secrets, MFA codes, recovery secrets or raw request bodies. Sharing operations are excluded from the generic access-burst detector to avoid duplicate incidents for the same sharing burst. The regression suite uses disposable source fixtures, not fabricated live evidence.

## Deployment and migration (not executed live)

1. Review the local diff on `TEAM-3` and use your normal backup/maintenance process. Do not reinitialize volumes or regenerate credentials.
2. Review `database/migrations/20261030_threat_context.sql`. It adds `audit_logs.context`, nullable `security_events.detection_context`, an app-read-only settings table, the canonical evidence function and trigger replacements/new permission trigger. It preserves existing rows and does not backfill invented detection settings.
3. Apply that migration using the schema owner's existing secure connection during an approved deployment window. It acquires normal DDL locks. Do **not** run the whole seed/schema file against a live installation.
4. The fresh schema contains the same definitions without an inner COMMIT: existing bootstrap `--single-transaction` behavior stays atomic. The bootstrap whitelist now requires the new settings table. Retained old installations must be migrated before starting the updated stack; the bootstrap intentionally fails closed on an incomplete schema rather than initializing it.
5. Deploy updated backend and root Admin frontend manually. No running application was started/stopped/restarted here. Existing JWT/DB/MFA/mail credentials and volumes stay in place.
6. Do not drop the context columns or remove alert/audit data to roll back. Older code can be reviewed separately for compatibility; no automatic data rollback is included.

Geolocation stays disabled unless you configure a verified file. No secrets are added to tracked files. The generated Boot user is removed while the existing JWT/session chain remains authoritative.

## Verification commands and safety

From the SecureVault repository root in PowerShell:

```powershell
$env:JAVA_HOME = 'C:\Program Files\Java\jdk-21'
$env:PATH = (Join-Path $env:JAVA_HOME 'bin') + ';' + $env:PATH
.\scripts\Verify-ThreatAnalytics.ps1
npm.cmd test
npm.cmd run build -- --outDir (Join-Path $env:TEMP 'securevault-admin-reviewed-build')
npm.cmd --prefix frontend run build -- --outDir (Join-Path $env:TEMP 'securevault-account-reviewed-build')
docker compose config --quiet
git diff --check
```

The backend script copies only backend source/POM into a private temporary folder and creates a UUID-labeled PostgreSQL 17 container on a random loopback port with **tmpfs, no Docker volumes**, and random test-only credentials in a private temp file. It checks a database marker before test fixture cleanup, verifies fresh schema plus idempotent migration, exercises the actual atomic bootstrap fresh/reuse paths in another disposable database, and runs Maven unit tests plus the `threat-verification` Failsafe profile. Finally it stops/removes only its owned labeled container, without force/volume flags. Raw test logs remain private temp files, not evidence from real users.

Tests cover device/OS/browser parsing, optional/expired/private geolocation, no network-weight double counting, severity settings, proxy spoofing, generated-password absence, actual admin filter authorization, existing login/MFA tests, related counts/windows/escalation, denial deduplication, SQL sharing/vault/role source integration, notes/status history, append-only audit permissions, UTC totals, search/type/sort/pagination and UI unavailable-data handling. No real vault ownership test can run before the missing resource APIs exist.

See `THREAT-ANALYTICS-TEST-REVIEW.md` for measured final results and intermediate failures. Remote CI, real user/browser interactions, reliable production geolocation and functional end-to-end vault/sharing remain separate validation steps.

## Manual demonstration after reviewed deployment

- Log in with an existing administrator/MFA enrollment. No accounts or MFA secrets need changing.
- Open Threat analysis; set a date range and compare the five cards, daily chart and selected-range type/status breakdown. Global metrics are explicitly labeled exceptions.
- In the audit browser, search/filter actual login, failed-login, MFA, denial and role activity; inspect coarse device and location availability. A normal login is audit activity, not automatically an alert.
- Open an existing alert. New alerts show stored factor/threshold/window/severity context and up to 100 captured evidence records; the count matches the list. Legacy alerts explicitly lack their original configuration snapshot.
- Change an authorized investigation to Investigating, record a non-sensitive note, then resolve/mark False Positive as appropriate. These are live writes: perform only with suitable administrator authorization and genuine review reason. Reviewer/history remain recorded.
- Use disposable verification evidence to demonstrate repeated failures, multi-factor novelty, sharing and vault signals without deliberately generating fake incidents in the live database. Do not claim missing vault/sharing operations are complete.

Recommended commit message (not committed): `feat(threats): add explainable multi-factor analytics and consistent audit evidence`

## Changed-file inventory

- Backend: `pom.xml`; `SecureVaultApplication.java`; `admin/AdminController.java`, `AdminService.java`, `AdminSessionAuthenticationFilter.java`; `auth/LoginService.java`; `common/SecurityEventRecorder.java`; `resources/application.properties`.
- New backend threat package: `DeviceMetadata.java`, `RiskPolicy.java`, `LocationProvider.java`, `ConfiguredLocationProvider.java`, `ThreatTelemetry.java`.
- Backend tests: updated `ApplicationContextTest.java`; new `AdminThreatAuthorizationTest.java`, `threat/ThreatPolicyTest.java`, `ClientIpResolverTest.java`, `ThreatPostgresIT.java`.
- Database: `schema.sql`, `bootstrap.sql`, `bootstrap-app-privileges.sql`; new `migrations/20261030_threat_context.sql`.
- Root Admin UI: `src/App.jsx`, `App.css`, `adminApi.js`; new `ThreatContext.jsx`, `ThreatContext.test.jsx`.
- Infrastructure: `docker-compose.yml` (configuration passthrough only); new `scripts/Verify-ThreatAnalytics.ps1`.
- Documentation: `README.md`; this guide, `THREAT-ANALYTICS-TEST-REVIEW.md` and aggregate `threat-verification-results.json`.
