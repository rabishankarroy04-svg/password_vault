param()
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$temp=Join-Path ([IO.Path]::GetTempPath()) ('securevault-threat-verify-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
if($env:OS -eq 'Windows_NT'){
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
 & icacls.exe $temp /inheritance:r /grant:r "${identity}:(OI)(CI)F" | Out-Null
 if($LASTEXITCODE -ne 0){throw 'Cannot protect isolated verification directory'}
}else{& chmod 700 $temp;if($LASTEXITCODE -ne 0){throw 'Cannot protect verification directory'}}
$bytes=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
try{$rng.GetBytes($bytes)}finally{$rng.Dispose()}
$password=[Convert]::ToBase64String($bytes)
$secret=Join-Path $temp 'pg-password';[IO.File]::WriteAllText($secret,$password,[Text.UTF8Encoding]::new($false))
$name='securevault-test-'+[guid]::NewGuid().ToString('N')
$oldUrl=$env:SECUREVAULT_TEST_PG_URL;$oldPassword=$env:SECUREVAULT_TEST_PG_PASSWORD
try{
 New-Item -ItemType Directory -Path (Join-Path $temp 'backend') | Out-Null
 Copy-Item -LiteralPath (Join-Path $root 'backend/pom.xml') -Destination (Join-Path $temp 'backend/pom.xml')
 Copy-Item -LiteralPath (Join-Path $root 'backend/src') -Destination (Join-Path $temp 'backend/src') -Recurse
 & docker run --detach --name $name --label securevault.verification=true --tmpfs /var/lib/postgresql/data -p 127.0.0.1::5432 --mount "type=bind,src=$secret,dst=/run/secrets/password,readonly" -e POSTGRES_PASSWORD_FILE=/run/secrets/password -e POSTGRES_DB=securevault_test postgres:17-alpine | Out-Null
 if($LASTEXITCODE -ne 0){throw 'Cannot create disposable test container'}
 $ready=$false
 for($i=0;$i -lt 60;$i++){
  & docker exec $name pg_isready -U postgres -d securevault_test *> $null
  if($LASTEXITCODE -eq 0){$ready=$true;break};Start-Sleep -Seconds 1
 }
 if(-not $ready){throw 'Disposable PostgreSQL readiness timed out'}
 $setup="CREATE ROLE securevault_app NOLOGIN; COMMENT ON DATABASE securevault_test IS 'securevault-isolated-verification';"
 $setup | & docker exec -i $name psql -v ON_ERROR_STOP=1 -U postgres -d securevault_test *> (Join-Path $temp 'schema.log')
 if($LASTEXITCODE -ne 0){throw 'Cannot mark disposable database'}
 Get-Content -LiteralPath (Join-Path $root 'database/schema.sql') -Raw | & docker exec -i $name psql -v ON_ERROR_STOP=1 -U postgres -d securevault_test *>> (Join-Path $temp 'schema.log')
 if($LASTEXITCODE -ne 0){throw 'Isolated schema initialization failed; inspect private schema.log'}
 # Simulate existing application grants before reapplying the additive migration.
 'GRANT SELECT,INSERT,UPDATE,DELETE ON security_events TO securevault_app; GRANT SELECT,INSERT ON audit_logs,security_event_history TO securevault_app;' | & docker exec -i $name psql -v ON_ERROR_STOP=1 -U postgres -d securevault_test *>> (Join-Path $temp 'schema.log')
 if($LASTEXITCODE -ne 0){throw 'Cannot prepare legacy-grant fixture'}
 # Verify the additive migration can be applied again without resetting data.
 Get-Content -LiteralPath (Join-Path $root 'database/migrations/20261030_threat_context.sql') -Raw | & docker exec -i $name psql -v ON_ERROR_STOP=1 -U postgres -d securevault_test *>> (Join-Path $temp 'schema.log')
 if($LASTEXITCODE -ne 0){throw 'Additive migration idempotence failed'}
 # Exercise the real bootstrap's fresh/reuse paths in a second disposable DB.
 & docker exec $name createdb -U postgres securevault_db
 if($LASTEXITCODE -ne 0){throw 'Cannot create bootstrap test database'}
 $freshSchema=Join-Path $temp 'schema-initial.sql'
 $schema=Get-Content -LiteralPath (Join-Path $root 'database/schema.sql') -Raw
 [IO.File]::WriteAllText($freshSchema,([regex]::Replace($schema,'(?m)^DROP TRIGGER IF EXISTS .*\r?\n','')),[Text.UTF8Encoding]::new($false))
 & docker cp $freshSchema "${name}:/tmp/schema-initial.sql" *> $null
 foreach($mapping in @(@('bootstrap.sql','bootstrap.sql'),@('bootstrap-app-user.sql','app-user.sql'),@('bootstrap-app-privileges.sql','app-privileges.sql'))){
  & docker cp (Join-Path $root ('database/'+$mapping[0])) ("${name}:/tmp/"+$mapping[1]) *> $null
  if($LASTEXITCODE -ne 0){throw 'Cannot copy isolated bootstrap fixture'}
 }
 for($pass=0;$pass -lt 2;$pass++){
  & docker exec $name sh -c 'export SECUREVAULT_DB_APP_PASSWORD="$(cat /run/secrets/password)"; exec psql -X -v ON_ERROR_STOP=1 -U postgres -d securevault_db --single-transaction -f /tmp/bootstrap.sql' *>> (Join-Path $temp 'bootstrap.log')
  if($LASTEXITCODE -ne 0){throw 'Fresh/reused atomic bootstrap verification failed'}
 }
 $canDelete=& docker exec $name psql -X -At -U postgres -d securevault_db -c "SELECT has_table_privilege('securevault_app','security_events','DELETE')"
 if($LASTEXITCODE -ne 0 -or "$canDelete".Trim() -ne 'f'){throw 'Bootstrap reopened unsafe alert-delete privilege'}
 $port=(& docker port $name 5432/tcp).Trim().Split(':')[-1]
 $env:SECUREVAULT_TEST_PG_URL="jdbc:postgresql://127.0.0.1:$port/securevault_test"
 $env:SECUREVAULT_TEST_PG_PASSWORD=$password
 $maven=Get-Command mvn.cmd -ErrorAction SilentlyContinue
 if(-not $maven){$maven=Get-Command mvn -ErrorAction Stop}
 & $maven.Source -B -ntp -f (Join-Path $temp 'backend/pom.xml') -Pthreat-verification verify *> (Join-Path $temp 'maven.log')
 if($LASTEXITCODE -ne 0){throw 'Backend verification failed; inspect private maven.log'}
 $counts=@{tests=0;failures=0;errors=0;skipped=0}
 foreach($file in Get-ChildItem -LiteralPath (Join-Path $temp 'backend/target') -Recurse -Filter 'TEST-*.xml'){
  [xml]$report=Get-Content -LiteralPath $file.FullName -Raw
  foreach($key in @('tests','failures','errors','skipped')){$counts[$key]+=[int]$report.testsuite.GetAttribute($key)}
 }
 $counts | ConvertTo-Json
 Write-Output 'Fresh schema, additive migration reapplication and isolated backend verification passed. No live services or volumes accessed.'
}finally{
 $env:SECUREVAULT_TEST_PG_URL=$oldUrl;$env:SECUREVAULT_TEST_PG_PASSWORD=$oldPassword
 $owned=& docker inspect --format '{{index .Config.Labels "securevault.verification"}}' $name 2>$null
 if($LASTEXITCODE -eq 0 -and "$owned".Trim() -eq 'true'){
  & docker stop $name *> $null
  if($LASTEXITCODE -eq 0){& docker rm $name *> $null}
 }
 Write-Output "Private verification files: $temp"
}
