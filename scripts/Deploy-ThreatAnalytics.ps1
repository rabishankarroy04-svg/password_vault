#requires -Version 5.1
[CmdletBinding()]
param([switch]$Execute,[string]$BackupDirectory)
$ErrorActionPreference='Stop'
if(-not $Execute){Write-Output 'No actions performed. Review docs/THREAT-DEPLOYMENT.md, then explicitly pass -Execute during the maintenance window.';return}
if($env:OS -ne 'Windows_NT'){throw 'This script targets the existing Windows local environment.'}
Import-Module (Join-Path $PSScriptRoot 'SecureVaultDeployment.psm1') -Force
$root=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$directory=$null;$state=$null;$stage='preflight'
try {
    Write-Output '[1/8] Read-only preflight: project, database owner, volume and authentication settings.'
    $context=Get-SvDeploymentContext $root
    $runId=(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
    if(-not $BackupDirectory){$BackupDirectory=Join-Path $env:LOCALAPPDATA ('SecureVaultBackups/'+$runId)}
    $directory=Protect-SvDirectory $BackupDirectory $root
    $stage='preserve-image-and-configuration'
    $state=[ordered]@{
        Version=1;RunId=$runId;RepositoryRoot=$root;Project=$context.Project
        DatabaseContainerId=$context.Database.Id;DatabaseVolume=$context.Volume;InitialBackendContainerId=$context.Backend.Id
        PreviousImageId=$context.Backend.Image;PreviousImageTag=('securevault-backend:pre-threat-'+$runId)
        NewImageTag=('securevault-backend:deploy-'+$runId);NewImageId=''
        DeploymentConfigHash='';RollbackConfigHash='';MigrationHash='';BackupHash='';ImageArchiveHash=''
        BeforeCounts=$context.Metadata;AfterCounts=$null
        Stage=$stage;BackendStopped=$false;BackupValidated=$false;MigrationStarted=$false;MigrationCompleted=$false
        BackendStartAttempted=$false;BackendReady=$false;FrontendReady=$false;RollbackCompleted=$false
        FailureType='';StartedAt=[DateTime]::UtcNow.ToString('o');UpdatedAt=[DateTime]::UtcNow.ToString('o')
    }
    Save-SvState $state $directory
    Write-Output "[2/8] Preserve previous image/configuration in private directory: $directory"
    Invoke-SvDocker -DockerArguments @('tag',$state.PreviousImageId,$state.PreviousImageTag) | Out-Null
    $saved=(Invoke-SvDocker -DockerArguments @('image','inspect','--format','{{.Id}}',$state.PreviousImageTag)).Trim()
    if($saved -cne $state.PreviousImageId){throw 'Previous image was not preserved correctly.'}
    Invoke-SvDocker -DockerArguments @('image','save','--output',(Join-Path $directory 'backend-before.tar'),$state.PreviousImageTag) -LogPath (Join-Path $directory 'image-preservation.log') | Out-Null
    $state.ImageArchiveHash=(Get-FileHash -LiteralPath (Join-Path $directory 'backend-before.tar')).Hash
    Save-SvState $state $directory
    Write-SvComposeSnapshots $context $directory $state.PreviousImageTag $state.NewImageTag
    $state.DeploymentConfigHash=(Get-FileHash -LiteralPath (Join-Path $directory 'deployment.compose.json')).Hash
    $state.RollbackConfigHash=(Get-FileHash -LiteralPath (Join-Path $directory 'rollback.compose.json')).Hash
    foreach($file in @('.env','.env.compose.override.yaml','docker-compose.yml')){Copy-Item -LiteralPath (Join-Path $root $file) -Destination $directory}
    $migration=Join-Path $directory 'threat-context.sql'
    Copy-Item -LiteralPath (Join-Path $root 'database/migrations/20261030_threat_context.sql') -Destination $migration
    $state.MigrationHash=(Get-FileHash -LiteralPath $migration).Hash
    Save-SvState $state $directory
    $desired=Assert-SvSnapshot $state $directory 'deployment.compose.json' $state.DeploymentConfigHash
    $old=Assert-SvSnapshot $state $directory 'rollback.compose.json' $state.RollbackConfigHash
    Assert-SvAuthMatches $context.BackendEnvironment $desired.services.backend.environment
    Assert-SvAuthMatches $context.BackendEnvironment $old.services.backend.environment
    if($old.services.backend.image -cne $state.PreviousImageTag -or (Get-SvProperty $old.services.backend 'build')){throw 'Rollback snapshot has wrong image/build configuration.'}
    $compose=Get-SvSnapshotArguments $state $directory 'deployment.compose.json'
    $stage='build';$state.Stage=$stage;Save-SvState $state $directory
    Write-Output '[3/8] Build a uniquely tagged backend image; existing containers remain running.'
    Invoke-SvDocker -DockerArguments ($compose+@('build','backend')) -LogPath (Join-Path $directory 'build.log') | Out-Null
    $state.NewImageId=(Invoke-SvDocker -DockerArguments @('image','inspect','--format','{{.Id}}',$state.NewImageTag)).Trim()
    Assert-SvDatabaseIdentity $state
    $unchanged=Get-SvContainer 'securevault-backend'
    if($unchanged.Id -cne $state.InitialBackendContainerId -or $unchanged.Image -cne $state.PreviousImageId){throw 'Backend changed during build; refusing to stop another deployment.'}
    Assert-SvAuthMatches $context.BackendEnvironment (Get-SvEnvironment $unchanged)
    $stage='stop-backend';$state.Stage=$stage;Save-SvState $state $directory
    Write-Output '[4/8] Stop only backend. Keep all browser users paused until deployment completes.'
    Invoke-SvDocker -DockerArguments ($compose+@('stop','backend')) -LogPath (Join-Path $directory 'stop.log') | Out-Null
    if((Get-SvContainer 'securevault-backend').State.Running){throw 'Backend did not stop.'}
    $state.BackendStopped=$true;Save-SvState $state $directory
    $stage='backup-and-validation';$state.Stage=$stage;Save-SvState $state $directory
    Write-Output '[5/8] Back up database; copy to host; validate table of contents, full archive readability and checksum.'
    $state.BeforeCounts=Get-SvDatabaseMetadata $state.DatabaseContainerId
    $containerDirectory='/tmp/sv-'+$runId
    Invoke-SvDocker -DockerArguments @('exec',$state.DatabaseContainerId,'mkdir','-m','700',$containerDirectory) -LogPath (Join-Path $directory 'backup.log') | Out-Null
    $dump=$containerDirectory+'/pre.dump'
    Invoke-SvDocker -DockerArguments @('exec',$state.DatabaseContainerId,'pg_dump','-U','postgres','-d','securevault_db','-Fc','-f',$dump) -LogPath (Join-Path $directory 'backup.log') | Out-Null
    Invoke-SvDocker -DockerArguments @('cp',($state.DatabaseContainerId+':'+$dump),(Join-Path $directory 'securevault.dump')) -LogPath (Join-Path $directory 'backup.log') | Out-Null
    $state.BackupHash=Test-SvArchive $state $directory
    $state.BackupValidated=$true;Save-SvState $state $directory
    Assert-SvHash (Join-Path $directory 'securevault.dump') $state.BackupHash
    Assert-SvHash $migration $state.MigrationHash
    Assert-SvDatabaseIdentity $state
    $stage='migration';$state.Stage=$stage;$state.MigrationStarted=$true;Save-SvState $state $directory
    Write-Output '[6/8] Apply only the reviewed additive migration with transaction and bounded lock/statement waits.'
    $migrationInContainer=$containerDirectory+'/threat-context.sql'
    Invoke-SvDocker -DockerArguments @('cp',$migration,($state.DatabaseContainerId+':'+$migrationInContainer)) | Out-Null
    Invoke-SvDocker -DockerArguments @('exec','-e','PGOPTIONS=-c lock_timeout=5s -c statement_timeout=60s',$state.DatabaseContainerId,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','securevault_db','-f',$migrationInContainer) -LogPath (Join-Path $directory 'migration.log') | Out-Null
    $state.MigrationCompleted=$true;Save-SvState $state $directory
    $state.AfterCounts=Get-SvDatabaseMetadata $state.DatabaseContainerId
    foreach($key in @('accounts','mfaAccounts','sessions','audit','alerts','history')){
        if((Get-SvProperty $state.BeforeCounts $key) -ne (Get-SvProperty $state.AfterCounts $key)){throw 'Preserved-record counts changed during maintenance; inspect before starting backend.'}
    }
    $stage='start-backend';$state.Stage=$stage;$state.BackendStartAttempted=$true;Save-SvState $state $directory
    Write-Output '[7/8] Recreate only backend from the verified new image; do not run bootstrap/dependencies.'
    Assert-SvHash (Join-Path $directory 'deployment.compose.json') $state.DeploymentConfigHash
    $image=(Invoke-SvDocker -DockerArguments @('image','inspect','--format','{{.Id}}',$state.NewImageTag)).Trim()
    if($image -cne $state.NewImageId){throw 'New image tag changed since build.'}
    Invoke-SvDocker -DockerArguments ($compose+@('up','-d','--no-deps','--no-build','--pull','never','backend')) -LogPath (Join-Path $directory 'start.log') | Out-Null
    $new=Get-SvContainer 'securevault-backend'
    if($new.Image -cne $state.NewImageId){throw 'Unexpected backend image running.'}
    Assert-SvAuthMatches $context.BackendEnvironment (Get-SvEnvironment $new)
    Assert-SvDatabaseIdentity $state
    $stage='readiness';$state.Stage=$stage;Save-SvState $state $directory
    Write-Output '[8/8] Bounded backend health, database and frontend proxy readiness checks.'
    Wait-SvBackend
    $state.BackendReady=$true;$state.FrontendReady=$true
    foreach($port in @(3001,3000)){
        try{$health=Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/health" -TimeoutSec 5;if($health.status -ne 'UP' -or $health.service -ne 'securevault-backend'){$state.FrontendReady=$false}}
        catch{$state.FrontendReady=$false}
    }
    $state.Stage='complete';$state.UpdatedAt=[DateTime]::UtcNow.ToString('o');Save-SvState $state $directory
    if(-not $state.FrontendReady){Write-Warning 'Backend is ready; one frontend proxy needs a manual check. No frontend was restarted.'}
    Write-Output "Backend deployment ready. Refresh the Admin UI. Keep private recovery directory: $directory"
} catch {
    if($null -ne $state){$state.Stage=$stage;$state.FailureType=$_.Exception.GetType().Name;try{Save-SvState $state $directory}catch{}}
    Write-Warning 'No automatic database restore or container rollback was attempted. Keep the maintenance window closed.'
    throw "Deployment stopped at '$stage'. Private recovery directory: $directory. Review the stage log and use Rollback-ThreatAnalytics.ps1 if appropriate. Migration commit state may need inspection if execution was interrupted."
}
