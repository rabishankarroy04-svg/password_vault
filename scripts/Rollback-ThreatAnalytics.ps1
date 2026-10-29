#requires -Version 5.1
[CmdletBinding()]
param([string]$BackupDirectory,[switch]$Execute)
$ErrorActionPreference='Stop'
if(-not $Execute){Write-Output 'No actions performed. Rollback requires -BackupDirectory <private deployment folder> -Execute. It never restores or drops database data.';return}
if(-not $BackupDirectory){throw 'Specify the private deployment backup directory.'}
Import-Module (Join-Path $PSScriptRoot 'SecureVaultDeployment.psm1') -Force
$directory=[IO.Path]::GetFullPath($BackupDirectory)
$state=Get-Content -LiteralPath (Join-Path $directory 'deployment-state.json') -Raw | ConvertFrom-Json
$root=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
if($state.Version -ne 1 -or $state.RepositoryRoot -cne $root -or $state.Project -notmatch '^[a-z0-9][a-z0-9_-]*$'){throw 'Recovery manifest does not match this repository/project.'}
if($state.RunId -notmatch '^\d{8}-\d{6}-[a-f0-9]{8}$' -or $state.PreviousImageTag -cne ('securevault-backend:pre-threat-'+$state.RunId) -or $state.PreviousImageId -notmatch '^sha256:[a-f0-9]{64}$' -or $state.DatabaseContainerId -notmatch '^[a-f0-9]{64}$'){throw 'Unexpected image/container identifiers in recovery manifest.'}
try {
    Write-Output '[1/4] Verify PostgreSQL identity, saved configuration and original image content ID.'
    Assert-SvDatabaseIdentity $state
    Get-SvDatabaseMetadata $state.DatabaseContainerId | Out-Null
    $snapshot=Assert-SvSnapshot $state $directory 'rollback.compose.json' $state.RollbackConfigHash
    if($snapshot.services.backend.image -cne $state.PreviousImageTag -or (Get-SvProperty $snapshot.services.backend 'build')){throw 'Rollback must use the saved image and no build configuration.'}
    $local=(Invoke-SvDocker -DockerArguments @('image','ls','--no-trunc','--format','{{.ID}}',$state.PreviousImageTag)).Trim()
    if(-not $local){
        Assert-SvHash (Join-Path $directory 'backend-before.tar') $state.ImageArchiveHash
        Invoke-SvDocker -DockerArguments @('image','load','--input',(Join-Path $directory 'backend-before.tar')) -LogPath (Join-Path $directory 'rollback.log') | Out-Null
    }
    $actual=(Invoke-SvDocker -DockerArguments @('image','inspect','--format','{{.Id}}',$state.PreviousImageTag)).Trim()
    if($actual -cne $state.PreviousImageId){throw 'Original image tag content differs. Refusing to pull, rebuild or overwrite a different image.'}
    if($state.MigrationStarted){
        if(-not $state.BackupValidated){throw 'Migration was started without a validated backup record; manual recovery review required.'}
        Assert-SvHash (Join-Path $directory 'securevault.dump') $state.BackupHash
    }
    Write-Output '[2/4] Restore only backend using the standalone saved configuration and original environment.'
    $compose=Get-SvSnapshotArguments $state $directory 'rollback.compose.json'
    Invoke-SvDocker -DockerArguments ($compose+@('up','-d','--no-deps','--no-build','--pull','never','backend')) -LogPath (Join-Path $directory 'rollback.log') | Out-Null
    Write-Output '[3/4] Verify image, preserved authentication configuration and health.'
    $container=Get-SvContainer 'securevault-backend'
    if($container.Image -cne $state.PreviousImageId){throw 'Rollback image verification failed.'}
    Assert-SvAuthMatches $snapshot.services.backend.environment (Get-SvEnvironment $container)
    Assert-SvDatabaseIdentity $state
    Wait-SvBackend
    $state.RollbackCompleted=$true;$state.Stage='rolled-back';$state.UpdatedAt=[DateTime]::UtcNow.ToString('o');Save-SvState $state $directory
    Write-Output '[4/4] Previous backend restored. Additive schema, accounts, sessions and audit records retained. No database restore was performed.'
} catch {
    throw 'Rollback stopped. Inspect private rollback.log and the saved manifest. No database restore/drop was attempted. Do not remove volumes or regenerate credentials.'
}
