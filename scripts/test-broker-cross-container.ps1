param([string]$RuntimeImage = 'artex:local')

$ErrorActionPreference = 'Stop'
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 12)
$builder = "artex-broker-build-$suffix"
$server = "artex-broker-server-$suffix"
$volume = "artex-broker-socket-$suffix"
$binary = Join-Path $env:TEMP "artex-broker-test-$suffix"
$goImage = 'golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0'
$socket = '/run/artex-broker/broker.sock'
$createdVolume = $false

function Assert-Exit([string]$step) {
    if ($LASTEXITCODE -ne 0) { throw "$step failed (exit $LASTEXITCODE)" }
}

try {
    docker image inspect $RuntimeImage | Out-Null
    Assert-Exit 'inspect local runtime image'
    docker image inspect $goImage | Out-Null
    Assert-Exit 'inspect pinned local Go image'

    docker create --pull=never --name $builder --network none `
        --label org.artex.test=broker-cross-container `
        --tmpfs /tmp:rw,exec,size=1g --entrypoint sleep $goImage 600 | Out-Null
    Assert-Exit 'create builder'
    docker start $builder | Out-Null
    Assert-Exit 'start builder'
    docker exec $builder mkdir -p /src
    Assert-Exit 'prepare builder'
    docker cp ./go.mod "${builder}:/src/go.mod"
    Assert-Exit 'copy go.mod'
    docker cp ./go.sum "${builder}:/src/go.sum"
    Assert-Exit 'copy go.sum'
    docker cp ./sandboxbroker "${builder}:/src/sandboxbroker"
    Assert-Exit 'copy broker source'
    docker exec -w /src $builder go test -race -c -o /src/broker.test ./sandboxbroker
    Assert-Exit 'build Linux broker test fixture'
    docker cp "${builder}:/src/broker.test" $binary
    Assert-Exit 'copy Linux broker test fixture'

    docker volume create --label org.artex.test=broker-cross-container $volume | Out-Null
    Assert-Exit 'create socket volume'
    $createdVolume = $true
    docker create --pull=never --name $server --network none `
        --label org.artex.test=broker-cross-container `
        --cap-drop=ALL --security-opt=no-new-privileges:true `
        --mount "type=volume,src=$volume,dst=/run/artex-broker" `
        --tmpfs /app/data:rw,nosuid,nodev,noexec,size=1m `
        --tmpfs /app/keys:rw,nosuid,nodev,noexec,size=1m `
        --env "ARTEX_BROKER_CROSS_CONTAINER_SOCKET=$socket" `
        --entrypoint /broker.test $RuntimeImage '-test.run=^TestBrokerCrossContainerServeUnix$' '-test.v' | Out-Null
    Assert-Exit 'create broker service fixture'
    docker cp $binary "${server}:/broker.test"
    Assert-Exit 'copy broker binary to service fixture'
    docker start $server | Out-Null
    Assert-Exit 'start broker service fixture'

    $ready = $false
    for ($i = 0; $i -lt 50; $i++) {
        docker exec $server /bin/sh -c "test -S $socket" 2>$null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) { throw 'broker socket did not appear' }

    $rootReply = docker run --rm --pull=never --network none --user 0:0 `
        --mount "type=volume,src=$volume,dst=/run/artex-broker" `
        --tmpfs /app/data:rw,nosuid,nodev,noexec,size=1m `
        --tmpfs /app/keys:rw,nosuid,nodev,noexec,size=1m `
        --entrypoint curl $RuntimeImage --silent --show-error --fail `
        --unix-socket $socket --header 'Content-Type: application/json' `
        --data '{"campaign_id":42}' 'http://broker/v1/sandboxes'
    Assert-Exit 'root control client'
    $reply = $rootReply | ConvertFrom-Json
    if ($reply.handle.Length -ne 64) { throw 'root client did not receive an opaque handle' }

    # Test SO_PEERCRED independently of socket file permissions.
    docker exec $server chmod 0755 /run/artex-broker
    Assert-Exit 'open test-only directory permission'
    docker exec $server chmod 0666 $socket
    Assert-Exit 'open test-only socket permission'
    $nonrootClient = @'
import socket
s = socket.socket(socket.AF_UNIX)
s.settimeout(3)
s.connect('/run/artex-broker/broker.sock')
try:
    s.sendall(b'GET /v1/sandboxes HTTP/1.1\r\nHost: broker\r\n\r\n')
    assert s.recv(1) == b'', 'non-root process received an HTTP response'
except (BrokenPipeError, ConnectionResetError):
    pass
print('non-root peer connected but was rejected')
'@
    docker run --rm --pull=never --network none --user 10001:10001 `
        --mount "type=volume,src=$volume,dst=/run/artex-broker" `
        --tmpfs /app/data:rw,nosuid,nodev,noexec,size=1m `
        --tmpfs /app/keys:rw,nosuid,nodev,noexec,size=1m `
        --entrypoint python3 $RuntimeImage -c $nonrootClient
    Assert-Exit 'non-root peer rejection'

    docker exec $server /bin/sh -c 'touch /run/artex-broker/stop'
    Assert-Exit 'signal graceful broker shutdown'
    $serviceExit = docker wait $server
    Assert-Exit 'wait for broker service fixture'
    if ($serviceExit.Trim() -ne '0') {
        docker logs $server
        throw "broker service fixture exited $serviceExit"
    }
    docker run --rm --pull=never --network none --user 0:0 `
        --mount "type=volume,src=$volume,dst=/run/artex-broker" `
        --tmpfs /app/data:rw,nosuid,nodev,noexec,size=1m `
        --tmpfs /app/keys:rw,nosuid,nodev,noexec,size=1m `
        --entrypoint /bin/sh $RuntimeImage -c "test ! -e $socket"
    Assert-Exit 'broker socket cleanup'
    Write-Output 'PASS: cross-container root client allowed; non-root peer rejected by kernel credential check; socket and sandbox cleaned on shutdown.'
} finally {
    docker rm -f -v $server $builder 2>$null | Out-Null
    if ($createdVolume) { docker volume rm $volume 2>$null | Out-Null }
    Remove-Item -LiteralPath $binary -Force -ErrorAction SilentlyContinue
}
