Set-StrictMode -Version Latest
# Importing this module performs no Docker, network, Git or filesystem operations.
function Invoke-SvDocker {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$DockerArguments,[string]$InputText,[string]$LogPath)
    Get-Command docker -ErrorAction Stop | Out-Null
    $previousPreference=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        if($PSBoundParameters.ContainsKey('InputText')){ $output=@($InputText | & docker @DockerArguments 2>&1) }
        else { $output=@(& docker @DockerArguments 2>&1) }
        $nativeExit=$LASTEXITCODE
    } finally { $ErrorActionPreference=$previousPreference }
    $text=($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    if($LogPath){[IO.File]::AppendAllText($LogPath,$text+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))}
    if($nativeExit -ne 0){throw "Docker failed (exit $nativeExit). Stop; inspect the private stage log if present."}
    return $text
}
function Get-SvProperty($Object,[string]$Name) {
    if($null -eq $Object){return $null}
    if($Object -is [Collections.IDictionary]){return $Object[$Name]}
    $property=$Object.PSObject.Properties[$Name]
    if($null -ne $property){return $property.Value}
    return $null
}
function Get-SvEnvironment($Container) {
    $result=@{}
    foreach($entry in $Container.Config.Env){$parts=$entry.Split('=',2);$result[$parts[0]]=$parts[1]}
    return $result
}
function Assert-SvAuthMatches($Expected,$Actual) {
    $names=@('JWT_SECRET_BASE64','MFA_ENCRYPTION_KEY_BASE64','SPRING_DATASOURCE_URL','SPRING_DATASOURCE_USERNAME','SPRING_DATASOURCE_PASSWORD','JWT_EXPIRATION_SECONDS','SPRING_MAIL_HOST','SPRING_MAIL_PORT','SPRING_MAIL_USERNAME','SPRING_MAIL_PASSWORD','SECUREVAULT_MAIL_FROM','SPRING_MAIL_PROPERTIES_MAIL_SMTP_AUTH','SPRING_MAIL_PROPERTIES_MAIL_SMTP_STARTTLS_ENABLE')
    foreach($name in $names){
        $before=[string](Get-SvProperty $Expected $name);$after=[string](Get-SvProperty $Actual $name)
        if($name -eq 'MFA_ENCRYPTION_KEY_BASE64'){
            if(-not $before){$before=[string](Get-SvProperty $Expected 'JWT_SECRET_BASE64')}
            if(-not $after){$after=[string](Get-SvProperty $Actual 'JWT_SECRET_BASE64')}
        }
        if($before -cne $after){throw "Authentication/mail configuration differs: $name. Values suppressed; resolve drift before deployment."}
    }
}
function Get-SvContainer([string]$Name) {
    $parsed=Invoke-SvDocker -DockerArguments @('inspect',$Name) | ConvertFrom-Json
    return @($parsed)[0]
}
function Get-SvDatabaseMetadata([string]$Container) {
    $sql=@"
SELECT json_build_object(
 'database',current_database(),'role',current_user,
 'owner',(SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()),
 'ownedTables',(SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tableowner='postgres' AND tablename IN('users','sessions','audit_logs','security_events','security_event_history')),
 'accounts',(SELECT count(*) FROM users),'mfaAccounts',(SELECT count(*) FROM users WHERE mfa_enabled),
 'sessions',(SELECT count(*) FROM sessions),'audit',(SELECT count(*) FROM audit_logs),
 'alerts',(SELECT count(*) FROM security_events),'history',(SELECT count(*) FROM security_event_history));
"@
    $text=Invoke-SvDocker -DockerArguments @('exec','-e','PGOPTIONS=-c default_transaction_read_only=on',$Container,'psql','-X','-At','-v','ON_ERROR_STOP=1','-U','postgres','-d','securevault_db','-c',$sql)
    $metadata=$text | ConvertFrom-Json
    if($metadata.database -ne 'securevault_db' -or $metadata.role -ne 'postgres' -or $metadata.owner -ne 'postgres' -or $metadata.ownedTables -ne 5){throw 'Database/owner/table ownership mismatch. Refusing migration.'}
    return $metadata
}
function Get-SvDeploymentContext([string]$Root) {
    $backend=Get-SvContainer 'securevault-backend';$database=Get-SvContainer 'securevault-postgres'
    if(-not $backend.State.Running -or -not $database.State.Running){throw 'Existing backend and PostgreSQL must be running for preflight.'}
    $project=[string](Get-SvProperty $backend.Config.Labels 'com.docker.compose.project')
    if($project -notmatch '^[a-z0-9][a-z0-9_-]*$' -or $project -cne [string](Get-SvProperty $database.Config.Labels 'com.docker.compose.project')){throw 'Compose project identity mismatch.'}
    if((Get-SvProperty $backend.Config.Labels 'com.docker.compose.service') -ne 'backend' -or (Get-SvProperty $database.Config.Labels 'com.docker.compose.service') -ne 'postgres'){throw 'Unexpected Compose service identity.'}
    $arguments=@('compose','--env-file',(Join-Path $Root '.env'),'--project-name',$project,'--project-directory',$Root,'-f',(Join-Path $Root 'docker-compose.yml'),'-f',(Join-Path $Root '.env.compose.override.yaml'))
    $configuration=(Invoke-SvDocker -DockerArguments ($arguments+@('config','--format','json'))) | ConvertFrom-Json
    foreach($check in @(@('backend','8085',8080),@('postgres','5433',5432))){
        $ports=@((Get-SvProperty $configuration.services $check[0]).ports)
        if($ports.Count -ne 1 -or [string]$ports[0].published -ne $check[1] -or $ports[0].target -ne $check[2] -or $ports[0].host_ip -ne '127.0.0.1'){throw 'Expected loopback host ports 8085/5433. Review Compose override.'}
    }
    $backendEnvironment=Get-SvEnvironment $backend
    Assert-SvAuthMatches $backendEnvironment $configuration.services.backend.environment
    $databaseEnvironment=Get-SvEnvironment $database
    if([string]$databaseEnvironment['POSTGRES_PASSWORD'] -cne [string]$configuration.services.postgres.environment.POSTGRES_PASSWORD){throw 'PostgreSQL credential drift. Values suppressed.'}
    $mounts=@($database.Mounts | Where-Object { $_.Destination -eq '/var/lib/postgresql/data' -and $_.Type -eq 'volume' })
    if($mounts.Count -ne 1){throw 'Expected one existing named PostgreSQL data volume.'}
    $configuredMounts=@($configuration.services.postgres.volumes | Where-Object { $_.target -eq '/var/lib/postgresql/data' -and $_.type -eq 'volume' })
    if($configuredMounts.Count -ne 1 -or (Get-SvProperty $configuration.volumes $configuredMounts[0].source).name -cne $mounts[0].Name){throw 'Compose data volume differs from the existing PostgreSQL volume.'}
    $metadata=Get-SvDatabaseMetadata $database.Id
    return [pscustomobject]@{Project=$project;Root=$Root;Backend=$backend;Database=$database;Volume=$mounts[0].Name;Configuration=$configuration;BackendEnvironment=$backendEnvironment;Metadata=$metadata}
}
function Protect-SvDirectory([string]$Path,[string]$Root) {
    $resolved=[IO.Path]::GetFullPath($Path);$repository=[IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
    if($resolved.Equals($repository,[StringComparison]::OrdinalIgnoreCase) -or $resolved.StartsWith($repository+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Backups must be outside the repository.'}
    if(Test-Path -LiteralPath $resolved){throw 'Backup directory already exists; refusing overwrite.'}
    New-Item -ItemType Directory -Path $resolved -Force | Out-Null
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $resolved /inheritance:r /grant:r "${identity}:(OI)(CI)F" | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot secure backup ACL; refusing to save credentials.'}
    return $resolved
}
function ConvertTo-SvComposeLiteral($Value) {
    if($null -eq $Value){return $null}
    if($Value -is [string]){return $Value.Replace('$','$$')}
    if($Value -is [Collections.IDictionary]){ $map=@{};foreach($key in $Value.Keys){$map[$key]=ConvertTo-SvComposeLiteral $Value[$key]};return $map }
    if($Value -is [pscustomobject]){ $map=@{};foreach($property in $Value.PSObject.Properties){$map[$property.Name]=ConvertTo-SvComposeLiteral $property.Value};return $map }
    if($Value -is [Collections.IEnumerable]){ $items=@(foreach($item in $Value){ConvertTo-SvComposeLiteral $item});return ,$items }
    return $Value
}
function Write-SvJson([string]$Path,$Value) {
    $temporary=$Path+'.tmp-'+[guid]::NewGuid().ToString('N')
    [IO.File]::WriteAllText($temporary,($Value | ConvertTo-Json -Depth 100),[Text.UTF8Encoding]::new($false))
    if(Test-Path -LiteralPath $Path){[IO.File]::Replace($temporary,$Path,[NullString]::Value)}else{[IO.File]::Move($temporary,$Path)}
}
function Write-SvComposeSnapshots($Context,[string]$Directory,[string]$OldTag,[string]$NewTag) {
    $deployment=$Context.Configuration | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $rollback=$Context.Configuration | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $deployment.services.backend | Add-Member -NotePropertyName image -NotePropertyValue $NewTag -Force
    $rollback.services.backend | Add-Member -NotePropertyName image -NotePropertyValue $OldTag -Force
    $rollback.services.backend | Add-Member -NotePropertyName environment -NotePropertyValue $Context.BackendEnvironment -Force
    $rollback.services.backend.PSObject.Properties.Remove('build')
    $rollback.services.backend.PSObject.Properties.Remove('depends_on')
    Write-SvJson (Join-Path $Directory 'deployment.compose.json') (ConvertTo-SvComposeLiteral $deployment)
    Write-SvJson (Join-Path $Directory 'rollback.compose.json') (ConvertTo-SvComposeLiteral $rollback)
}
function Get-SvSnapshotArguments($State,[string]$Directory,[string]$File) {
    return @('compose','--env-file',(Join-Path $Directory '.env'),'--project-name',[string]$State.Project,'--project-directory',[string]$State.RepositoryRoot,'-f',(Join-Path $Directory $File))
}
function Assert-SvHash([string]$Path,[string]$Expected) {
    if(-not (Test-Path -LiteralPath $Path -PathType Leaf) -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -cne $Expected){throw 'Saved artifact is absent or its checksum differs. Stop for manual review.'}
}
function Assert-SvDatabaseIdentity($State) {
    $database=Get-SvContainer 'securevault-postgres'
    $mounts=@($database.Mounts | Where-Object { $_.Destination -eq '/var/lib/postgresql/data' -and $_.Type -eq 'volume' })
    if(-not $database.State.Running -or $database.Id -cne $State.DatabaseContainerId -or $mounts.Count -ne 1 -or $mounts[0].Name -cne $State.DatabaseVolume){throw 'PostgreSQL container/volume changed. Stop for manual review.'}
}
function Assert-SvSnapshot($State,[string]$Directory,[string]$File,[string]$Hash) {
    Assert-SvHash (Join-Path $Directory $File) $Hash
    $arguments=Get-SvSnapshotArguments $State $Directory $File
    return ((Invoke-SvDocker -DockerArguments ($arguments+@('config','--format','json'))) | ConvertFrom-Json)
}
function Test-SvArchive($State,[string]$Directory) {
    $archive=Join-Path $Directory 'securevault.dump'
    if(-not (Test-Path -LiteralPath $archive -PathType Leaf) -or (Get-Item -LiteralPath $archive).Length -eq 0){throw 'Backup archive is absent/empty.'}
    $before=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    $copy='/tmp/sv-'+$State.RunId+'/verify.dump'
    Invoke-SvDocker -DockerArguments @('cp',$archive,($State.DatabaseContainerId+':'+$copy)) -LogPath (Join-Path $Directory 'backup-validation.log') | Out-Null
    Invoke-SvDocker -DockerArguments @('exec',$State.DatabaseContainerId,'pg_restore','--list',$copy) -LogPath (Join-Path $Directory 'backup-validation.log') | Out-Null
    # No --dbname: fully decode archive contents into Unix /dev/null; execute no SQL.
    Invoke-SvDocker -DockerArguments @('exec',$State.DatabaseContainerId,'pg_restore','--exit-on-error','--file=/dev/null',$copy) -LogPath (Join-Path $Directory 'backup-validation.log') | Out-Null
    $after=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    if($before -cne $after){throw 'Host backup changed while being validated.'}
    return $after
}
function Wait-SvBackend([int]$TimeoutSeconds=120) {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds){
        try{ $health=Invoke-RestMethod -Uri 'http://127.0.0.1:8085/api/health' -TimeoutSec 3
             if($health.status -eq 'UP' -and $health.service -eq 'securevault-backend'){return} }catch{}
        Start-Sleep -Seconds 2
    }
    throw 'Backend/database health did not become UP within the readiness deadline.'
}
function Save-SvState($State,[string]$Directory) { Write-SvJson (Join-Path $Directory 'deployment-state.json') $State }
Export-ModuleMember -Function Invoke-SvDocker,Get-SvProperty,Get-SvEnvironment,Assert-SvAuthMatches,Get-SvContainer,Get-SvDatabaseMetadata,Get-SvDeploymentContext,Protect-SvDirectory,ConvertTo-SvComposeLiteral,Write-SvJson,Write-SvComposeSnapshots,Get-SvSnapshotArguments,Assert-SvHash,Assert-SvDatabaseIdentity,Assert-SvSnapshot,Test-SvArchive,Wait-SvBackend,Save-SvState
