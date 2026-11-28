param([string]$SandboxImage = 'artex:local')

$ErrorActionPreference = 'Stop'
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 12)
$volumeA = "artex-upload-probe-a-$suffix"
$volumeB = "artex-upload-probe-b-$suffix"
$seedName = "artex-upload-seed-$suffix"
$sandboxA = "artex-upload-a-$suffix"
$sandboxB = "artex-upload-b-$suffix"
$createdVolumes = @()

function Assert-Exit([string]$step) {
    if ($LASTEXITCODE -ne 0) { throw "$step failed (exit $LASTEXITCODE)" }
}

try {
    docker image inspect $SandboxImage --format '{{.Id}}' | Out-Null
    Assert-Exit 'inspect local sandbox image'

    foreach ($name in @($volumeA, $volumeB)) {
        docker volume create --label org.artex.test=upload-volume $name | Out-Null
        Assert-Exit "create disposable volume $name"
        $createdVolumes += $name
    }

    docker run --rm --pull=never --name $seedName --network none --read-only `
        --cap-drop=ALL --security-opt=no-new-privileges:true --user 0:0 `
        --mount "type=volume,src=$volumeA,dst=/uploads" `
        --tmpfs /app/data:rw,nosuid,nodev,noexec,size=1m `
        --tmpfs /app/keys:rw,nosuid,nodev,noexec,size=1m `
        --entrypoint /bin/sh $SandboxImage -c `
        'set -eu; dd if=/dev/zero of=/uploads/large.bin bs=1M count=17 status=none; truncate -s 536870912 /uploads/large.bin; printf A_PRIVATE > /uploads/marker; chmod 0444 /uploads/large.bin /uploads/marker'
    Assert-Exit 'seed synthetic attachment volume'

    $sandboxOptions = @('--rm', '--pull=never', '--network', 'none', '--read-only',
        '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--user', '10001:10001',
        '--memory=256m', '--memory-swap=256m', '--cpus=0.5', '--pids-limit=64',
        '--tmpfs', '/campaign:rw,nosuid,nodev,noexec,size=128m,uid=10001,gid=10001,mode=0700',
        '--tmpfs', '/app/data:rw,nosuid,nodev,noexec,size=1m',
        '--tmpfs', '/app/keys:rw,nosuid,nodev,noexec,size=1m')

    docker run @sandboxOptions --name $sandboxA `
        --mount "type=volume,src=$volumeA,dst=/campaign/main/uploads,readonly" `
        --entrypoint /bin/sh $SandboxImage -c `
        'set -eu; test "$(cat /campaign/main/uploads/marker)" = A_PRIVATE; test "$(stat -c %s /campaign/main/uploads/large.bin)" = 536870912; test "$(dd if=/campaign/main/uploads/large.bin bs=1 skip=536870911 count=1 status=none | wc -c)" = 1; test ! -w /campaign/main/uploads/marker; test ! -w /campaign/main/uploads; printf A_OK'
    Assert-Exit 'read-only nested mount in campaign A'

    docker run @sandboxOptions --name $sandboxB `
        --mount "type=volume,src=$volumeB,dst=/campaign/main/uploads,readonly" `
        --entrypoint /bin/sh $SandboxImage -c `
        'set -eu; test ! -e /campaign/main/uploads/marker; test ! -e /campaign/main/uploads/large.bin; test ! -w /campaign/main/uploads; printf B_OK'
    Assert-Exit 'campaign B cannot see A attachment'

    Write-Output 'PASS: disposable nested read-only upload volumes kept a synthetic 512 MiB file visible only to its campaign.'
} finally {
    foreach ($name in @($seedName, $sandboxA, $sandboxB)) {
        docker rm -f -v $name 2>$null | Out-Null
    }
    foreach ($name in $createdVolumes) {
        docker volume rm $name 2>$null | Out-Null
    }
}
