param(
    [string]$BrokerImage = 'artex-galactus:broker-validation-20261127',
    [string]$SandboxImage = 'artex:local'
)

$ErrorActionPreference = 'Stop'
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 12)
$brokerName = "artex-broker-recovery-$suffix"
$foreignName = "artex-broker-foreign-$suffix"
$socketVolume = "artex-broker-recovery-$suffix"
$socket = '/run/artex-broker/broker.sock'
$brokerCreated = $false
$volumeCreated = $false
$ownedID = ''
$foreignID = ''

function Assert-Exit([string]$step) {
    if ($LASTEXITCODE -ne 0) { throw "$step failed (exit $LASTEXITCODE)" }
}

function Start-Broker([string]$imageDigest) {
    docker run -d --pull=never --name $brokerName --network none `
        --label org.artex.test=broker-crash-recovery `
        --read-only --cap-drop=ALL --security-opt=no-new-privileges:true `
        --memory=512m --pids-limit=64 --user 0:0 `
        --mount 'type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock' `
        --mount "type=volume,src=$socketVolume,dst=/run/artex-broker" `
        --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m `
        --env DOCKER_HOST=unix:///var/run/docker.sock `
        $BrokerImage --docker-path=/usr/local/bin/docker --image=$imageDigest --socket=$socket | Out-Null
    Assert-Exit 'start disposable broker'
}

function Invoke-Broker([string]$method, [string]$path, [string]$body = '') {
    $dockerArgs = @('run', '--rm', '--pull=never', '--network', 'none', '--user', '0:0',
        '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
        '--mount', "type=volume,src=$socketVolume,dst=/run/artex-broker",
        '--tmpfs', '/app/data:rw,nosuid,nodev,noexec,size=1m',
        '--tmpfs', '/app/keys:rw,nosuid,nodev,noexec,size=1m',
        '--entrypoint', 'curl', $SandboxImage,
        '--silent', '--show-error', '--fail', '--unix-socket', $socket,
        '--request', $method, '--header', 'Content-Type: application/json')
    if ($body) { $dockerArgs += @('--data', $body) }
    $dockerArgs += "http://broker$path"
    $result = docker @dockerArgs
    Assert-Exit "broker $method $path"
    return $result
}

try {
    $imageDigest = docker image inspect $SandboxImage --format '{{.Id}}'
    Assert-Exit 'inspect sandbox image'
    docker image inspect $BrokerImage | Out-Null
    Assert-Exit 'inspect broker image'
    $baseline = @(docker ps -a --format '{{.ID}}' --filter label=org.artex.sandbox.token)

    docker volume create --label org.artex.test=broker-crash-recovery $socketVolume | Out-Null
    Assert-Exit 'create disposable socket volume'
    $volumeCreated = $true
    Start-Broker $imageDigest
    $brokerCreated = $true

    $created = $null
    for ($i = 0; $i -lt 20; $i++) {
        try {
            $created = Invoke-Broker 'POST' '/v1/sandboxes' '{"campaign_id":91}' | ConvertFrom-Json
            break
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $created -or $created.handle.Length -ne 64) { docker logs $brokerName; throw 'first broker did not create a sandbox' }
    $children = @(docker ps -a --format '{{.ID}}' --filter label=org.artex.sandbox.token | Where-Object { $_ -and $_ -notin $baseline })
    if ($children.Count -ne 1) { throw "expected one owned sandbox, found $($children.Count)" }
    $ownedID = $children[0]
    $owner = (@(docker inspect $ownedID | ConvertFrom-Json)[0]).Config.Labels.'org.artex.sandbox.owner'
    Assert-Exit 'inspect owner label'
    if ($owner -notmatch '^[a-f0-9]{32}$') { throw 'invalid owner label' }

    docker kill --signal=KILL $brokerName | Out-Null
    Assert-Exit 'kill disposable broker'
    docker rm -f -v $brokerName | Out-Null
    Assert-Exit 'remove crashed broker container'
    $brokerCreated = $false
    docker inspect $ownedID | Out-Null
    Assert-Exit 'confirm orphaned sandbox exists'

    $foreignToken = 'e' * 64
    $foreignID = docker create --pull=never --name $foreignName --network none `
        --label "org.artex.sandbox.owner=$owner" `
        --label "org.artex.sandbox.token=$foreignToken" `
        --read-only --user 10001:10001 --entrypoint /bin/sh $SandboxImage -c 'sleep infinity'
    Assert-Exit 'create foreign-labeled fixture'

    Start-Broker $imageDigest
    $brokerCreated = $true
    $recovered = $false
    for ($i = 0; $i -lt 20; $i++) {
        docker inspect $ownedID 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { $recovered = $true; break }
        Start-Sleep -Milliseconds 250
    }
    if (-not $recovered) { docker logs $brokerName; throw 'orphaned sandbox was not recovered' }
    $ownedID = ''
    docker inspect $foreignID | Out-Null
    Assert-Exit 'foreign-labeled fixture survived recovery'

    $second = Invoke-Broker 'POST' '/v1/sandboxes' '{"campaign_id":92}' | ConvertFrom-Json
    if ($second.handle.Length -ne 64) { throw 'restarted broker did not accept requests' }
    $secondIDs = @(docker ps -a --format '{{.ID}}' --filter label=org.artex.sandbox.token | Where-Object { $_ -and $_ -notin $baseline -and $_ -ne $foreignID.Substring(0, 12) })
    if ($secondIDs.Count -ne 1) { throw 'restarted broker created unexpected sandbox count' }
    $ownedID = $secondIDs[0]
    $newOwner = (@(docker inspect $ownedID | ConvertFrom-Json)[0]).Config.Labels.'org.artex.sandbox.owner'
    Assert-Exit 'inspect restarted owner'
    if ($newOwner -ne $owner) { throw 'broker owner changed on restart' }
    Invoke-Broker 'DELETE' "/v1/sandboxes/$($second.handle)" | Out-Null
    $ownedID = ''
    docker stop --time=80 $brokerName | Out-Null
    Assert-Exit 'graceful stop after recovery'
    Write-Output 'PASS: crashed broker recovered its journaled sandbox, preserved a foreign-labeled container, and reused its owner identity.'
} finally {
    if ($brokerCreated) { docker stop --time=80 $brokerName 2>$null | Out-Null }
    docker rm -f -v $brokerName 2>$null | Out-Null
    if ($ownedID) { docker rm -f -v $ownedID 2>$null | Out-Null }
    if ($foreignID) { docker rm -f -v $foreignID 2>$null | Out-Null }
    if ($volumeCreated) { docker volume rm $socketVolume 2>$null | Out-Null }
}
