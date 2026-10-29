#requires -Version 5.1
# OFFLINE tests only. The docker command is replaced with a function before module calls.
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('securevault-deployment-mocks-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
$global:SvMockCalls=[Collections.Generic.List[object]]::new()
$global:SvMockOutput='fixture-output';$global:SvMockExit=0;$global:SvMockFailDecode=$false;$global:SvMockRouter=$null
function global:docker {
    $global:SvMockCalls.Add([string[]]@($args))
    $global:LASTEXITCODE=$global:SvMockExit
    if($global:SvMockFailDecode -and $args -contains '--file=/dev/null'){$global:LASTEXITCODE=1}
    if($null -ne $global:SvMockRouter){& $global:SvMockRouter @args;return}
    Write-Output $global:SvMockOutput
}
if((Get-Command docker).CommandType -ne 'Function'){throw 'Docker mock was not installed; refusing tests.'}
Import-Module (Join-Path $PSScriptRoot 'SecureVaultDeployment.psm1') -Force
$script:passed=0
function Assert($Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Case([string]$Name,[scriptblock]$Action){& $Action;$script:passed++;Write-Output "PASS $Name"}
function Reject([scriptblock]$Action,[string]$Pattern){$caught=$false;try{& $Action | Out-Null}catch{$caught=$true;if($Pattern -and $_.Exception.Message -notmatch $Pattern){throw}};Assert $caught 'Expected failure was accepted'}
try {
 Case 'all deployment files parse without being executed' {
    foreach($file in @('SecureVaultDeployment.psm1','Deploy-ThreatAnalytics.ps1','Rollback-ThreatAnalytics.ps1')){
        $tokens=$null;$errors=$null
        [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file),[ref]$tokens,[ref]$errors) | Out-Null
        Assert ($errors.Count -eq 0) "Parse error in $file"
    }
 }
 Case 'native wrapper preserves argument boundaries and returns command output' {
    $global:SvMockCalls.Clear();$global:SvMockOutput="first`nsecond";$global:SvMockExit=0
    $arguments=@('compose','-f','C:\private folder\saved.json','config','--format','json','literal-$-value')
    $result=Invoke-SvDocker -DockerArguments $arguments
    Assert ($result -ceq "first`nsecond") 'Native output changed'
    Assert (($global:SvMockCalls[0] -join '|') -ceq ($arguments -join '|')) 'Arguments were flattened or expanded'
 }
 Case 'nonzero native exit fails closed without exposing captured output' {
    $global:SvMockExit=9;$global:SvMockOutput='sensitive-fixture-do-not-display'
    Reject {Invoke-SvDocker -DockerArguments @('fake')} '^Docker failed \(exit 9\)'
    $global:SvMockExit=0;$global:SvMockOutput='fixture-output'
 }
 Case 'container JSON remains a single object under PS 5.1 and 7' {
    $global:SvMockOutput='[{"Id":"fixture-container","Image":"sha256:old"}]'
    Assert ((Get-SvContainer 'fixture').Id -eq 'fixture-container') 'Container array parsing failed'
 }
 Case 'environment preserves equals signs and detects credential drift without printing values' {
    $parsed=Get-SvEnvironment ([pscustomobject]@{Config=[pscustomobject]@{Env=@('JWT_SECRET_BASE64=fixture=a=b','SPRING_DATASOURCE_PASSWORD=fixture-$-value')}})
    Assert ($parsed.JWT_SECRET_BASE64 -ceq 'fixture=a=b') 'Environment value split incorrectly'
    Assert-SvAuthMatches $parsed $parsed
    $drift=@{};foreach($key in $parsed.Keys){$drift[$key]=$parsed[$key]};$drift.SPRING_DATASOURCE_PASSWORD='different-fixture'
    Reject {Assert-SvAuthMatches $parsed $drift} 'configuration differs: SPRING_DATASOURCE_PASSWORD'
    Assert-SvAuthMatches @{JWT_SECRET_BASE64='fixture'} @{JWT_SECRET_BASE64='fixture';MFA_ENCRYPTION_KEY_BASE64='fixture'}
 }
 Case 'snapshot is standalone, uses original image/environment and preserves dollar literals' {
    $config='{"name":"fixture","services":{"backend":{"build":{"context":"C:/fixture/backend"},"depends_on":{"postgres":{"condition":"service_healthy"}},"environment":{"JWT_SECRET_BASE64":"new-fixture"},"ports":[{"target":8080,"published":"8085","host_ip":"127.0.0.1"}]},"postgres":{"image":"postgres:16-alpine"}}}' | ConvertFrom-Json
    $context=[pscustomobject]@{Configuration=$config;BackendEnvironment=@{JWT_SECRET_BASE64='old-fixture-$-literal';SPRING_DATASOURCE_PASSWORD='fixture=a=b'}}
    Write-SvComposeSnapshots $context $temporary 'fixture:previous' 'fixture:new'
    $old=Get-Content -LiteralPath (Join-Path $temporary 'rollback.compose.json') -Raw | ConvertFrom-Json
    $new=Get-Content -LiteralPath (Join-Path $temporary 'deployment.compose.json') -Raw | ConvertFrom-Json
    Assert ($old.services.backend.image -ceq 'fixture:previous') 'Old image was not pinned'
    Assert ($null -eq $old.services.backend.PSObject.Properties['build']) 'Rollback retained build configuration'
    Assert ($null -eq $old.services.backend.PSObject.Properties['depends_on']) 'Rollback retained bootstrap dependency'
    Assert ($old.services.backend.environment.JWT_SECRET_BASE64 -ceq 'old-fixture-$$-literal') 'Compose dollar escaping failed'
    Assert ($new.services.backend.image -ceq 'fixture:new') 'New image is not independently tagged'
    Assert (@($old.services.backend.ports).Count -eq 1) 'Port array shape changed'
    Assert ($old.services.backend.ports[0].published -eq '8085') 'Host port changed'
 }
 Case 'rollback command uses one saved file and explicit project identity' {
    $state=[pscustomobject]@{Project='fixture';RepositoryRoot='C:\fixture root'}
    $arguments=Get-SvSnapshotArguments $state $temporary 'rollback.compose.json'
    Assert (@($arguments | Where-Object {$_ -eq '-f'}).Count -eq 1) 'Rollback merges current Compose files'
    Assert ($arguments -contains 'C:\fixture root') 'Project directory lost'
    Assert ($arguments -contains 'fixture') 'Compose project identity lost'
 }
 Case 'atomic state replacement and checksum drift checks work' {
    $file=Join-Path $temporary 'state-fixture.json';Write-SvJson $file @{Stage='first'};Write-SvJson $file @{Stage='second'}
    Assert ((Get-Content -LiteralPath $file -Raw | ConvertFrom-Json).Stage -eq 'second') 'Atomic state update failed'
    $hash=(Get-FileHash -LiteralPath $file).Hash;Assert-SvHash $file $hash
    [IO.File]::AppendAllText($file,' ')
    Reject {Assert-SvHash $file $hash} 'checksum differs'
    Assert (@(Get-ChildItem -LiteralPath $temporary -Filter '*.tmp-*').Count -eq 0) 'Atomic write left unfinished temp files'
 }
 Case 'backup validation reads the copied host archive fully without executing SQL' {
    [IO.File]::WriteAllBytes((Join-Path $temporary 'securevault.dump'),[byte[]]@(1,2,3))
    $state=[pscustomobject]@{RunId='fixture';DatabaseContainerId='fixture-postgres'}
    $global:SvMockCalls.Clear();$global:SvMockOutput='fixture-output'
    $hash=Test-SvArchive $state $temporary
    Assert ($hash -eq (Get-FileHash -LiteralPath (Join-Path $temporary 'securevault.dump')).Hash) 'Backup checksum wrong'
    Assert ($global:SvMockCalls.Count -eq 3) 'Expected copy, TOC check and full decode'
    $decode=$global:SvMockCalls[2]
    Assert ($decode -contains '--file=/dev/null') 'Backup was not fully read'
    Assert (-not ($decode -contains '-d') -and -not ($decode -contains '--dbname')) 'Validation would execute restore SQL'
    $global:SvMockFailDecode=$true
    Reject {Test-SvArchive $state $temporary} '^Docker failed'
    $global:SvMockFailDecode=$false
 }
 Case 'backup locations inside the repository are rejected before creating files' {
    Reject {Protect-SvDirectory (Join-Path $root 'forbidden-backup-fixture') $root} 'Backups must be outside'
    Assert (-not (Test-Path -LiteralPath (Join-Path $root 'forbidden-backup-fixture'))) 'Unsafe backup path was created'
 }
 Case 'database identity check refuses a changed volume without runtime mutations' {
    $global:SvMockOutput='[{"Id":"fixture-db","State":{"Running":true},"Mounts":[{"Destination":"/var/lib/postgresql/data","Type":"volume","Name":"original-volume"}]}]'
    $state=[pscustomobject]@{DatabaseContainerId='fixture-db';DatabaseVolume='original-volume'}
    Assert-SvDatabaseIdentity $state
    $global:SvMockCalls.Clear();$global:SvMockOutput=$global:SvMockOutput.Replace('original-volume','wrong-volume')
    Reject {Assert-SvDatabaseIdentity $state} 'container/volume changed'
    Assert ($global:SvMockCalls.Count -eq 1 -and $global:SvMockCalls[0][0] -eq 'inspect') 'Identity rejection performed a mutation'
 }
 Case 'snapshot drift is rejected before any Docker call' {
    $file=Join-Path $temporary 'rollback.compose.json';$hash=(Get-FileHash -LiteralPath $file).Hash
    [IO.File]::AppendAllText($file,' ');$global:SvMockCalls.Clear()
    Reject {Assert-SvSnapshot ([pscustomobject]@{Project='fixture';RepositoryRoot=$root}) $temporary 'rollback.compose.json' $hash} 'checksum differs'
    Assert ($global:SvMockCalls.Count -eq 0) 'Changed configuration reached Docker'
 }
 Case 'health readiness uses the public endpoint and a bounded failure path' {
    $global:SvHealthCalls=[Collections.Generic.List[string]]::new()
    function global:Invoke-RestMethod {param([string]$Uri,[int]$TimeoutSec) $global:SvHealthCalls.Add($Uri);return [pscustomobject]@{status='UP';service='securevault-backend'}}
    try{
        if((Get-Command Invoke-RestMethod).CommandType -ne 'Function'){throw 'Health mock missing'}
        Wait-SvBackend -TimeoutSeconds 2
        Assert ($global:SvHealthCalls.Count -eq 1 -and $global:SvHealthCalls[0] -eq 'http://127.0.0.1:8085/api/health') 'Readiness uses a protected/wrong endpoint'
        Reject {Wait-SvBackend -TimeoutSeconds 0} 'readiness deadline'
    }finally{Remove-Item Function:\Invoke-RestMethod}
 }
 Case 'full preflight accepts only matching owner, project, ports, volume and authentication settings' {
    $fixture=@{}
    $fixture.Backend='{"Id":"fixture-backend","Image":"sha256:fixture-old","State":{"Running":true},"Config":{"Env":["JWT_SECRET_BASE64=fixture","SPRING_DATASOURCE_PASSWORD=fixture"],"Labels":{"com.docker.compose.project":"fixture","com.docker.compose.service":"backend"}}}'
    $fixture.Database='{"Id":"fixture-postgres","State":{"Running":true},"Config":{"Env":["POSTGRES_PASSWORD=fixture"],"Labels":{"com.docker.compose.project":"fixture","com.docker.compose.service":"postgres"}},"Mounts":[{"Destination":"/var/lib/postgresql/data","Type":"volume","Name":"original-volume"}]}'
    $fixture.Configuration='{"services":{"backend":{"environment":{"JWT_SECRET_BASE64":"fixture","MFA_ENCRYPTION_KEY_BASE64":"fixture","SPRING_DATASOURCE_PASSWORD":"fixture"},"ports":[{"published":"8085","target":8080,"host_ip":"127.0.0.1"}]},"postgres":{"environment":{"POSTGRES_PASSWORD":"fixture"},"ports":[{"published":"5433","target":5432,"host_ip":"127.0.0.1"}],"volumes":[{"type":"volume","source":"postgres_data","target":"/var/lib/postgresql/data"}]}},"volumes":{"postgres_data":{"name":"original-volume"}}}' | ConvertFrom-Json
    $global:SvMockRouter={
        $parts=@($args)
        if($parts[0] -eq 'inspect'){if($parts[1] -eq 'securevault-backend'){return $fixture.Backend}else{return $fixture.Database}}
        if($parts[0] -eq 'compose'){return ($fixture.Configuration | ConvertTo-Json -Depth 100)}
        if($parts[0] -eq 'exec'){
            if(-not ($parts -contains 'PGOPTIONS=-c default_transaction_read_only=on')){throw 'Preflight SQL was not read-only'}
            return '{"database":"securevault_db","role":"postgres","owner":"postgres","ownedTables":5,"accounts":1,"mfaAccounts":1,"sessions":0,"audit":2,"alerts":1,"history":0}'
        }
        throw 'Unexpected command in offline preflight'
    }.GetNewClosure()
    try{
        $result=Get-SvDeploymentContext $root
        Assert ($result.Volume -eq 'original-volume') 'Preflight selected wrong volume'
        $fixture.Configuration.services.backend.ports[0].published='8080'
        Reject {Get-SvDeploymentContext $root} 'Expected loopback host ports'
        $fixture.Configuration.services.backend.ports[0].published='8085'
        $fixture.Configuration.volumes.postgres_data.name='wrong-volume'
        Reject {Get-SvDeploymentContext $root} 'Compose data volume differs'
    }finally{$global:SvMockRouter=$null}
 }
 Case 'entry points require explicit execution and contain no destructive recovery commands' {
    foreach($name in @('Deploy-ThreatAnalytics.ps1','Rollback-ThreatAnalytics.ps1')){
        $source=Get-Content -LiteralPath (Join-Path $PSScriptRoot $name) -Raw
        Assert ($source.Contains('if(-not $Execute)')) 'Explicit execution guard absent'
        Assert (-not ($source -match 'down\s+-v|reset\s+--hard|pg_restore.*--clean|git\s+(push|commit|checkout|switch)')) 'Destructive/Git operation present'
        Assert ($source.Contains("'--no-deps','--no-build','--pull','never','backend'")) 'Backend-only pinned restart guard missing'
    }
 }
 Write-Output "Offline deployment helper tests: $script:passed passed, 0 failures. Docker was mocked; deployment/rollback entry points were not executed."
} finally {
    Remove-Item Function:\docker
    Remove-Module SecureVaultDeployment -ErrorAction SilentlyContinue
}
