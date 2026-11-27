param(
    [string]$BrokerImage = 'artex-galactus:broker-validation-20261127',
    [string]$SandboxImage = 'artex:local',
    [switch]$FileToolSmoke
)

$ErrorActionPreference = 'Stop'
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 12)
$brokerName = "artex-broker-control-$suffix"
$socketVolume = "artex-broker-control-$suffix"
$socket = '/run/artex-broker/broker.sock'
$volumeCreated = $false
$brokerCreated = $false

function Assert-Exit([string]$step) {
    if ($LASTEXITCODE -ne 0) { throw "$step failed (exit $LASTEXITCODE)" }
}

function NewSandboxIDs([string[]]$before) {
    @(docker ps -a --format '{{.ID}}' --filter label=org.artex.sandbox.token |
        Where-Object { $_ -and $_ -notin $before })
}

function Invoke-Broker([string]$method, [string]$path, [string]$body = '', [string]$contentType = 'application/json') {
    $dockerArgs = @('run', '--rm', '--pull=never', '--network', 'none', '--user', '0:0',
        '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
        '--mount', "type=volume,src=$socketVolume,dst=/run/artex-broker",
        '--tmpfs', '/app/data:rw,nosuid,nodev,noexec,size=1m',
        '--tmpfs', '/app/keys:rw,nosuid,nodev,noexec,size=1m',
        '--entrypoint', 'curl', $SandboxImage,
        '--silent', '--show-error', '--fail', '--unix-socket', $socket,
        '--request', $method, '--header', "Content-Type: $contentType")
    if ($body) { $dockerArgs += @('--data-binary', $body) }
    $dockerArgs += "http://broker$path"
    $result = docker @dockerArgs
    Assert-Exit "broker $method $path"
    return $result
}

try {
    $sandboxDigest = docker image inspect $SandboxImage --format '{{.Id}}'
    Assert-Exit 'inspect local sandbox image'
    docker image inspect $BrokerImage | Out-Null
    Assert-Exit 'inspect local broker image'
    $baseline = @(docker ps -a --format '{{.ID}}' --filter label=org.artex.sandbox.token)

    docker volume create --label org.artex.test=broker-docker-control $socketVolume | Out-Null
    Assert-Exit 'create private socket volume'
    $volumeCreated = $true
    docker run -d --pull=never --name $brokerName --network none `
        --label org.artex.test=broker-docker-control `
        --read-only --cap-drop=ALL --security-opt=no-new-privileges:true `
        --memory=512m --pids-limit=64 --user 0:0 `
        --mount 'type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock' `
        --mount "type=volume,src=$socketVolume,dst=/run/artex-broker" `
        --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m `
        --env DOCKER_HOST=unix:///var/run/docker.sock `
        $BrokerImage --docker-path=/usr/local/bin/docker --image=$sandboxDigest --socket=$socket | Out-Null
    Assert-Exit 'start isolated broker'
    $brokerCreated = $true

    $brokerInfo = @(docker inspect $brokerName | ConvertFrom-Json)[0]
    if ($brokerInfo.HostConfig.NetworkMode -ne 'none' -or -not $brokerInfo.HostConfig.ReadonlyRootfs -or
        @($brokerInfo.Mounts).Count -ne 2 -or
        @($brokerInfo.Mounts | Where-Object Destination -eq '/var/run/docker.sock').Count -ne 1 -or
        @($brokerInfo.Mounts | Where-Object Destination -eq '/run/artex-broker').Count -ne 1) {
        throw 'broker fixture has unexpected mounts or network'
    }
    $ready = $false
    for ($i = 0; $i -lt 15; $i++) {
        docker run --rm --pull=never --network none --user 0:0 `
            --mount "type=volume,src=$socketVolume,dst=/run/artex-broker" `
            --tmpfs /app/data:rw,nosuid,nodev,noexec,size=1m `
            --tmpfs /app/keys:rw,nosuid,nodev,noexec,size=1m `
            --entrypoint /bin/sh $SandboxImage -c "test -S $socket" 2>$null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Milliseconds 200
    }
    if (-not $ready) { docker logs $brokerName; throw 'broker socket did not appear' }

    $first = Invoke-Broker 'POST' '/v1/sandboxes' '{"campaign_id":71}' | ConvertFrom-Json
    if ($first.handle.Length -ne 64) { throw 'first campaign lacked an opaque handle' }
    $run = Invoke-Broker 'POST' "/v1/sandboxes/$($first.handle)/run" '{"command":"test ! -e /run/artex-broker/broker.sock && test ! -e /var/run/docker.sock && printf broker-integration"}' | ConvertFrom-Json
    if ($run.output -ne 'broker-integration') { throw "sandbox command returned unexpected output: $($run.output)" }
    $stdinBody = @{ command = 'cat'; input = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('SYNTHETIC_STDIN')) } | ConvertTo-Json -Compress
    $stdinRun = Invoke-Broker 'POST' "/v1/sandboxes/$($first.handle)/run-input" $stdinBody | ConvertFrom-Json
    if ($stdinRun.output -ne 'SYNTHETIC_STDIN') { throw 'sandbox stdin transfer returned unexpected output' }
    $second = Invoke-Broker 'POST' '/v1/sandboxes' '{"campaign_id":72}' | ConvertFrom-Json
    if ($second.handle.Length -ne 64 -or $second.handle -eq $first.handle) { throw 'second campaign handle invalid' }
    if ($FileToolSmoke) {
        $workingDir = '/app/data/tasks/71/main'
        $fileRequest = @{ name = 'Write'; input = @{ file_path = "$workingDir/private.txt"; content = 'A_PRIVATE' }; working_dir = $workingDir; max_output_chars = 30000 } | ConvertTo-Json -Depth 5 -Compress
        $fileBody = @{ command = '/app/artex __artex-sandbox-filetool'; input = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($fileRequest)) } | ConvertTo-Json -Compress
        $fileWrite = Invoke-Broker 'POST' "/v1/sandboxes/$($first.handle)/run-input" $fileBody | ConvertFrom-Json
        $fileResult = $fileWrite.output | ConvertFrom-Json
        if ($fileResult.is_error -or $fileResult.text -notmatch '^Created ') { throw 'sandbox file-tool write failed' }
        $listRequest = @{ name = 'LS'; input = @{ path = $workingDir }; working_dir = $workingDir; max_output_chars = 10 } | ConvertTo-Json -Depth 5 -Compress
        $listBody = @{ command = '/app/artex __artex-sandbox-filetool'; input = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($listRequest)) } | ConvertTo-Json -Compress
        $fileList = Invoke-Broker 'POST' "/v1/sandboxes/$($first.handle)/run-input" $listBody | ConvertFrom-Json
        $listResult = $fileList.output | ConvertFrom-Json
        if ($listResult.is_error -or $listResult.text -notmatch '<persisted-output>') { throw 'sandbox file-tool output did not spill privately' }
        $private = Invoke-Broker 'POST' "/v1/sandboxes/$($first.handle)/run" '{"command":"test \"$(cat /campaign/private.txt)\" = A_PRIVATE && printf private"}' | ConvertFrom-Json
        if ($private.output -ne 'private') { throw 'sandbox file-tool write was not visible to Bash' }
        $isolated = Invoke-Broker 'POST' "/v1/sandboxes/$($second.handle)/run" '{"command":"test ! -e /campaign/private.txt && test ! -e /campaign/.artex-output && printf isolated"}' | ConvertFrom-Json
        if ($isolated.output -ne 'isolated') { throw 'other campaign saw the private file' }
    }
    $artifact = Invoke-Broker 'PUT' "/v1/sandboxes/$($first.handle)/artifacts/fixture.txt" 'ARTIFACT_A' 'application/octet-stream' | ConvertFrom-Json
    if ($artifact.sha256 -ne '227bd725c586586d62c3c78f8bb304342328410324107a8580432f3345b29301') { throw 'broker returned unexpected artifact digest' }
    $read = Invoke-Broker 'POST' "/v1/sandboxes/$($first.handle)/run" '{"command":"cat /artifacts/fixture.txt && test ! -w /artifacts/fixture.txt"}' | ConvertFrom-Json
    if ($read.output -ne 'ARTIFACT_A') { throw 'delivered artifact unreadable or writable by executor' }
    $other = Invoke-Broker 'POST' "/v1/sandboxes/$($second.handle)/run" '{"command":"test ! -e /artifacts/fixture.txt"}' | ConvertFrom-Json
    if ($null -eq $other.output) { throw 'other campaign artifact check failed' }

    $children = @(NewSandboxIDs $baseline)
    if ($children.Count -ne 2) { throw "expected two owned sandboxes; found $($children.Count)" }
    $owners = @()
    foreach ($id in $children) {
        $info = @(docker inspect $id | ConvertFrom-Json)[0]
        $owner = $info.Config.Labels.'org.artex.sandbox.owner'
        if ($owner -notmatch '^[a-f0-9]{32}$') { throw "sandbox $id lacks a valid broker owner" }
        $owners += $owner
        if ($info.HostConfig.NetworkMode -ne 'none' -or -not $info.HostConfig.ReadonlyRootfs -or
            $info.Config.User -ne '10001:10001' -or
            @($info.Mounts | Where-Object Type -ne 'tmpfs').Count -ne 0) {
            throw "sandbox $id violated isolation policy"
        }
    }
    if (@($owners | Select-Object -Unique).Count -ne 1) { throw 'campaign sandboxes have different broker owners' }

    Invoke-Broker 'DELETE' "/v1/sandboxes/$($first.handle)" | Out-Null
    if (@(NewSandboxIDs $baseline).Count -ne 1) { throw 'explicit removal left an unexpected sandbox count' }
    if ($FileToolSmoke) {
        $reused = Invoke-Broker 'POST' '/v1/sandboxes' '{"campaign_id":71}' | ConvertFrom-Json
        $empty = Invoke-Broker 'POST' "/v1/sandboxes/$($reused.handle)/run" '{"command":"test ! -e /campaign/private.txt && printf clean"}' | ConvertFrom-Json
        if ($empty.output -ne 'clean') { throw 'recreated campaign retained old private file' }
        Invoke-Broker 'DELETE' "/v1/sandboxes/$($reused.handle)" | Out-Null
    }
    docker stop --time=80 $brokerName | Out-Null
    Assert-Exit 'graceful broker stop'
    if (@(NewSandboxIDs $baseline).Count -ne 0) { throw 'broker shutdown left an owned sandbox' }
    docker run --rm --pull=never --network none --user 0:0 `
        --mount "type=volume,src=$socketVolume,dst=/run/artex-broker" `
        --tmpfs /app/data:rw,nosuid,nodev,noexec,size=1m `
        --tmpfs /app/keys:rw,nosuid,nodev,noexec,size=1m `
        --entrypoint /bin/sh $SandboxImage -c "test ! -e $socket"
    Assert-Exit 'broker socket cleanup'
    Write-Output 'PASS: Docker-backed broker created isolated sandboxes, delivered a private artifact, ran commands, and removed sandboxes and socket.'
} finally {
    if ($brokerCreated) { docker stop --time=80 $brokerName 2>$null | Out-Null }
    docker rm -f -v $brokerName 2>$null | Out-Null
    if ($volumeCreated) { docker volume rm $socketVolume 2>$null | Out-Null }
}
