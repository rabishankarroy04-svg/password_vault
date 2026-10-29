# Threat analytics verification review — October 30, 2026

## Final measured results

| Check | Result |
|---|---|
| Maven unit/context/authentication/security tests | 40 passed; 0 failures, 0 errors, 0 skipped |
| Real disposable PostgreSQL integration tests | 16 passed; 0 failures, 0 errors, 0 skipped |
| Complete backend `-Pthreat-verification verify` | **56 passed**, BUILD SUCCESS |
| Root Admin React Vitest | **12 passed**, 3 test files; 0 failures/skips |
| Root Admin production build | Passed, Vite 8.3.5, 23 modules, output in a new temp directory |
| Separate account `frontend/` production build | Passed, 23 modules, output in a new temp directory |
| Fresh SQL schema and additive migration reapplication | Passed in disposable PostgreSQL |
| Actual atomic bootstrap, fresh then retained schema | Passed in a second database inside the same disposable container |
| `docker compose config --quiet` | Exit 0; resolved secret values were not printed |
| PowerShell script parser | 0 errors |
| `git diff --check` | Passed |
| Owned verification containers after cleanup | None running |
| Branch | TEAM-3 throughout; no commits/staging/pushes/merges/resets/branch switches |

Backend final verification files: `%TEMP%\securevault-threat-verify-d39aec6ca78a457fbf900b0a1ae1d0c1` (private raw logs/reports, test-only credentials). Root UI final log: `%TEMP%\securevault-threat-ui-verified.log`. Existing `backend/target`, root build output, account frontend output and live databases were not used as test output locations.

## Regressions exercised

- Existing registration/login/password validation, MFA encryption/enrollment and role-change tests retained.
- No Boot generated development password and no redundant UserDetailsService bean.
- Actual Spring Security filter chain: anonymous 401, active non-admin 403, admin permitted, forged token denied.
- Coarse mobile/tablet/desktop, Windows/Android/iOS/macOS/Linux and browser parsing; unknown metadata remains unknown.
- Trusted proxy chain behavior and rejection of spoofed/malformed forwarded headers.
- Optional verified location mapping, expiry, private/Docker/VPN/documentation exclusions; novel location compared with successful history.
- Deterministic risk boundaries and configurable weights; network novelty counted once; ordinary and first-baseline login does not generate an alert.
- Failed-login threshold/window evidence and same-incident critical escalation; later/out-of-window events do not inflate captured support.
- Repeated denial audit events generate one incident rather than a per-request alert flood.
- Single ordinary share does not alert; repeated distinct new recipients escalate; same-recipient repetition does not inflate recipient novelty.
- Genuine-source SQL trigger integration for vault denial, access bursts and permission elevation (isolated fixtures only, not functional vault/sharing HTTP operations).
- Investigation notes, reviewer identity, status transitions and database audit write protection, including prevention of cascade deletion through parent alerts. The runner simulates legacy DELETE grants before migration and asserts reused bootstrap does not reopen them.
- UTC date filtering, five-card totals, selected-range grouping, parameterized search/type filters, sorting and pagination.
- Legacy evidence clearly identifies missing original configuration; no fabricated historical threshold.
- MFA incident escalation updates one incident with matching evidence instead of duplicates.
- New audit context omits password/token strings from malicious user-agent input.
- React risk/explanation rendering, unknown-location messaging, audit query controls/pagination, missing-data errors and backend-derived breakdowns.

## Intermediate failures found and fixed

No failures were hidden or skipped:

1. The first disposable schema run found PostgreSQL's reserved `timestamp` output-column declaration needed quoting. Fixed; schema initialization and reapplication subsequently passed.
2. Two diagnostic integration runs had 37 unit tests pass and 12 integration tests run with **1 failure**: the selected-date query omitted events near local midnight because timestamp filtering used the JDBC session's local time while grouping used UTC. Fixed with explicit UTC start/end boundaries; the original expected counts were preserved. Subsequent expanded runs passed.
3. The Admin production bundler caught mixed Windows/UTF-8 encoding in the new JSX file even though the component tests passed. Normalized the changed file to UTF-8; reran all 12 UI tests and the actual production build successfully.

## Not verified / remaining dependencies

- No migration or feature activation was performed against the real SecureVault database.
- No existing application was started/stopped/restarted; no live user/account/MFA/credential/volume mutations or synthetic live security events were used.
- No actual browser/live user demonstration or remote CI run was claimed.
- Functional vault ownership and sharing APIs are absent. SQL source-event detection tests do not prove cross-user resource authorization; that requires real authenticated operation endpoints and corresponding cross-user tests.
- Geolocation is optional and disabled by default. No live geolocation dataset/provider accuracy was validated. Metadata-based device labels do not identify physical device models or owners.
- Captured supporting evidence is bounded at 100 records for consistent list/count behavior; detection context retains actual counted events and configured thresholds separately.
- Old alerts cannot recover thresholds/windows/evidence that were never stored. The original alert record is retained and explicitly labeled legacy.

See `THREAT-ANALYTICS-ENHANCEMENT.md` for full changed-file inventory, migration/configuration and manual demonstration steps. No actual Git commit exists for this enhancement.
