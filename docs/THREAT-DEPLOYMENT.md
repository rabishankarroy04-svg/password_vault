# Reviewed local deployment scripts — October 30, 2026

**Prepared and offline-tested only. Neither deployment nor rollback entry point has been executed. No real Docker command, migration, build, restart, credential change or Git-history operation was used to validate these new scripts.**

Target: the existing SecureVault Compose project, PostgreSQL `securevault_db` owned by `postgres`, existing named database volume, host DB port 5433, backend 8085, Admin frontend 3001 and User frontend 3000. Source root comes from each script's own location; it is not hardcoded to a user's machine. The previous read-only inspection confirmed these mappings and matching running/rendered JWT, MFA-encryption and DB credentials. Scripts repeat their own preflight when explicitly executed later.

## Corrections to the earlier manual commands

| Concern | Reviewed implementation |
|---|---|
| `DockerChecked @args` | The original pattern usually forwards arguments correctly, but native stderr/exit handling in PowerShell 5.1 and output capture need care. `Invoke-SvDocker -DockerArguments <string[]>` explicitly splats the array, captures output, immediately checks the native exit code, and throws a generic error on failure. Potentially sensitive inspect/config output stays in memory, never the console or ordinary logs. |
| Preserve original image | Inspect the **running container's content image ID**, give it a unique `pre-threat` tag, verify tag-to-ID equality, and export a checksum-protected image tar. Build the new image under a separate unique tag before stopping anything. |
| Restore previous image | A saved, standalone Compose JSON configuration uses the original image and the actual running environment; it does not merge today's base files. Its backend build/dependency fields are removed. Rollback uses `--no-deps --no-build --pull never`, verifies the running image ID, and can reload the checked original image tar if its local tag is missing. A tag pointing to the wrong image is rejected. |
| Preserve literal values | Snapshots escape `$` as `$$` for Compose. This prevents saved passwords or other values from being reinterpreted during rollback. An explicit private `--env-file` and explicit project name/directory avoid unrelated working-directory configuration. |
| Validate backup | `pg_dump -Fc` exits successfully, file is copied to the private host backup, copied back under a different private container filename, checked with `pg_restore --list`, **fully decoded with `pg_restore --file=/dev/null`**, and SHA-256 checked for stability. Validation has no `--dbname` and executes no restore SQL. Migration cannot start unless these checks passed. |
| Existing data/auth compatibility | Repeat owner/project/loopback ports/named-volume checks and compare JWT, MFA, database, mail and token-lifetime settings without printing their values. Migration is additive and transaction protected. Account/MFA/session/audit/alert/history counts are compared with the quiesced pre-migration counts. Do not rerun initialization or bootstrap. |

Full archive decoding is stronger than checking only the table of contents, but **is not a restore rehearsal** proving recovery in a separate database. An independently reviewed isolated restore test remains recommended before using this procedure for higher-stakes data.

## Files

- `scripts/Deploy-ThreatAnalytics.ps1`: explicitly opted-in, staged deployment.
- `scripts/Rollback-ThreatAnalytics.ps1`: separate backend-only recovery; never restores or drops DB data.
- `scripts/SecureVaultDeployment.psm1`: shared guarded Docker/snapshot/archive/readiness functions. Import has no operational side effects.
- `scripts/Test-SecureVaultDeployment.ps1`: offline helper tests with mocked Docker and HTTP; does not execute the two entry points.

## Future execution — not run now

Pause website use and other database writers during the maintenance window. Keep sufficient free space for a database archive, its in-container verification copy and an old-image tar. Do not edit `.env` or Compose settings mid-deployment.

From the project root, when execution is separately authorised:

```powershell
.\scripts\Deploy-ThreatAnalytics.ps1 -Execute
```

Without `-Execute`, the entry point only prints an informational message and performs no actions. On machines where scripts are disabled, a process-only invocation is possible (no permanent execution-policy change):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Deploy-ThreatAnalytics.ps1 -Execute
```

Default recovery directory: `%LOCALAPPDATA%\SecureVaultBackups\<timestamp-and-random-id>`. An optional `-BackupDirectory` must name a **new directory outside the repository**. Windows ACL creation must succeed before any secrets are saved.

The private directory contains `.env`, resolved deployment/rollback Compose snapshots and a database archive. **They contain sensitive material in plaintext or database-backup form; ACL protection is not encryption. Never paste/upload/commit them.** Original runtime files are not rewritten. Backup/image/log files are retained, not automatically deleted.

## Deployment stages

1. Read-only preflight: existing running services, matching Compose project/service labels, correct DB owner, existing named volume, override ports and authentication/mail settings.
2. Preserve exact old image/tag/tar and private configurations. Hash artifacts; save an atomic recovery manifest.
3. Build only the backend under a unique new tag. On build failure the old backend remains running. Refuse to stop it if another deployment changed its container/image/configuration meanwhile.
4. Stop only backend. PostgreSQL, frontends and volumes are not stopped/recreated.
5. Take a quiesced custom-format dump. Validate the **copied host archive** and record its checksum. Container-side copies are inside a mode-700 directory under `/tmp`.
6. Apply only the copied, checksum-verified `20261030_threat_context.sql` as existing DB owner `postgres` over the container-local connection, with `ON_ERROR_STOP`, 5-second lock timeout and 60-second per-statement timeout. The SQL already contains BEGIN/COMMIT; no extra outer transaction is added. Compare preserved-record counts before starting the app.
7. Recreate **only backend**, using `--no-deps --no-build --pull never`. Bootstrap/dependencies are not run, and JWT/MFA/DB settings must still match.
8. Check public `/api/health` with a bounded backend deadline and verify both existing frontend health proxies. No protected-route polling or artificial security-alert flood is used. A frontend-only failure is reported without restarting it or undoing a healthy backend.

`deployment-state.json` records stage, content IDs/checksums and checkpoint flags, not credential values. A flag such as `BackendStopped` records completion of that stage, not a perpetual assertion about present runtime state.

## Failure and rollback

| Failure point | Safe next action |
|---|---|
| Preflight/config/image preservation/build, before backend stop | Original backend should still be running. Fix the problem; do not unnecessarily roll it back. |
| Stop/backup/validation | Backend may be stopped. Use saved rollback configuration to restore the original image. No migration should have begun if validation failed. |
| Migration error or interrupted connection | Keep maintenance paused. Transaction errors normally roll back on connection close, but an interrupted command can leave commit acknowledgement uncertain. Inspect the schema read-only; never assume `MigrationCompleted=false` proves no commit. The original backend can be restored while retaining additive schema. |
| New backend startup/readiness failure | Use backend-only rollback. It never drops columns, restores old table contents or removes newly recorded audit data. |
| PostgreSQL container/volume changed, checksum drift or wrong image ID | Scripts refuse operations; investigate manually. Do not bypass the guards or initialise a replacement database. |

When explicitly authorised, use the **exact folder printed by deployment**:

```powershell
$backup = Read-Host 'Full private recovery directory printed by deployment'
.\scripts\Rollback-ThreatAnalytics.ps1 -BackupDirectory $backup -Execute
```

Rollback verifies manifest/project/root/IDs and saved snapshot hash, validates any recorded migration backup, restores only the original image/environment and checks health. If the old image tag is absent it can load the checksum-verified saved tar; it will not pull or rebuild a replacement. Existing additive schema remains. Older backend versions do not supply all new analytics fields, so temporary legacy/unavailable UI sections are expected after an application rollback.

Neither script restores a database automatically. If actual data recovery becomes necessary, plan an isolated restore into a **new database** first and review it before any connection cutover. Never use `down -v`, restore with `--clean` into the live database, remove volumes, reset users/MFA or drop history to undo this release.

## Post-deployment browser checks

- Admin `http://127.0.0.1:3001`: existing credentials and existing MFA enrollment still work.
- User `http://127.0.0.1:3000`: normal login/MFA still work; ordinary users remain blocked from Admin APIs.
- Threat Analytics: five cards, UTC range consistency, type/status breakdown and audit search/type/order/pagination.
- Device labels: available OS/browser/category and pseudonymous references; unknown/private-IP locations stay unavailable.
- Alert detail: count and captured evidence agree, stored factors/threshold/window/severity explanation shown; legacy context clearly unavailable.
- Investigation: an authorised real review can save a non-sensitive note/status and retains reviewer/history. This is a deliberate live audit write, not part of script validation.
- Do not repeatedly generate failures to fill the dashboard; use existing records or isolated automated test evidence. Vault/sharing operational APIs remain dependencies, not completed source integrations.

## Validation performed while preparing scripts

- Windows PowerShell **5.1: 15 offline helper tests passed**.
- PowerShell **7: 15 offline helper tests passed**.
- Includes parsing, exact argument/output handling, native failure, PS 5.1 JSON arrays, credential drift, original-image rollback configuration, literal `$`, atomic state writes, copied-archive decode checks, repository backup rejection, DB-volume mismatch, snapshot drift, public readiness endpoint and complete read-only preflight fixtures.
- Docker and HTTP were replaced by test functions. Deployment and rollback entry points were **not executed**, even without `-Execute`.
- No new runtime integration/deployment test is claimed. Prior application test results remain documented separately.

No Git commit, push, merge, reset, remote edit or branch switch is part of these scripts. The only permitted future push destination remains `mygithub`, after separate approval; `origin` must never be pushed.
