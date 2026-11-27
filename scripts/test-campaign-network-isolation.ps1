param(
    [string]$Image = 'artex:local'
)

$ErrorActionPreference = 'Stop'
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 12)
$campaignNet = "artex-campaign-test-$suffix"
$targetNet = "artex-target-test-$suffix"
$sandbox = "artex-sandbox-test-$suffix"
$gateway = "artex-gateway-test-$suffix"
$target = "artex-target-test-$suffix"
$created = [System.Collections.Generic.List[string]]::new()

function Assert-DockerSuccess([string]$step) {
    if ($LASTEXITCODE -ne 0) { throw "$step failed (docker exit $LASTEXITCODE)" }
}

function Start-Fixture([string]$name, [string]$network) {
    docker run -d --rm --pull=never --network $network --name $name `
        --label org.artex.test=campaign-network-isolation `
        --read-only --cap-drop=ALL --security-opt=no-new-privileges:true `
        --user 10001:10001 --memory=128m --pids-limit=32 `
        --tmpfs /tmp:rw,nosuid,nodev,size=16m `
        --tmpfs /app/data:rw,nosuid,nodev,noexec,size=1m `
        --tmpfs /app/keys:rw,nosuid,nodev,noexec,size=1m `
        --entrypoint /usr/local/bin/python3 $Image -m http.server 18080 --bind 0.0.0.0 | Out-Null
    Assert-DockerSuccess "start $name"
    $created.Add($name)
}

try {
    docker image inspect $Image | Out-Null
    Assert-DockerSuccess 'inspect local image'

    docker network create --internal --label org.artex.test=campaign-network-isolation $campaignNet | Out-Null
    Assert-DockerSuccess 'create campaign network'
    docker network create --internal --label org.artex.test=campaign-network-isolation $targetNet | Out-Null
    Assert-DockerSuccess 'create target network'

    Start-Fixture $target $targetNet
    Start-Fixture $gateway $campaignNet
    docker network connect $targetNet $gateway
    Assert-DockerSuccess 'attach gateway to target network'

    docker run -d --rm --pull=never --network $campaignNet --name $sandbox `
        --label org.artex.test=campaign-network-isolation `
        --read-only --cap-drop=ALL --security-opt=no-new-privileges:true `
        --user 10001:10001 --memory=128m --pids-limit=32 `
        --tmpfs /tmp:rw,nosuid,nodev,size=16m `
        --tmpfs /app/data:rw,nosuid,nodev,noexec,size=1m `
        --tmpfs /app/keys:rw,nosuid,nodev,noexec,size=1m `
        --entrypoint /bin/sh $Image -c 'sleep 120' | Out-Null
    Assert-DockerSuccess 'start sandbox'
    $created.Add($sandbox)

    Start-Sleep -Seconds 2
    $campaignInfo = @(docker network inspect $campaignNet | ConvertFrom-Json)[0]
    $targetInfo = @(docker network inspect $targetNet | ConvertFrom-Json)[0]
    if (-not $campaignInfo.Internal -or -not $targetInfo.Internal) { throw 'network is not internal' }
    $campaignMembers = @($campaignInfo.Containers.PSObject.Properties.Name)
    $targetMembers = @($targetInfo.Containers.PSObject.Properties.Name)
    if ($campaignMembers.Count -ne 2 -or $targetMembers.Count -ne 2) {
        throw "unexpected network members: campaign=$($campaignMembers.Count) target=$($targetMembers.Count)"
    }

    $sandboxInfo = @(docker inspect $sandbox | ConvertFrom-Json)[0]
    if ($sandboxInfo.NetworkSettings.Networks.PSObject.Properties.Name -cne $campaignNet) { throw 'sandbox has an unexpected network' }
    if (@($sandboxInfo.Mounts | Where-Object Type -ne 'tmpfs').Count -ne 0) { throw 'sandbox has a persistent mount' }
    if ($sandboxInfo.HostConfig.Privileged -or -not $sandboxInfo.HostConfig.ReadonlyRootfs) { throw 'sandbox isolation options changed' }
    $routes = docker exec $sandbox /sbin/ip route
    Assert-DockerSuccess 'inspect sandbox routes'
    if (@($routes | Where-Object { $_ -match '^default\s' }).Count -ne 0) { throw 'sandbox has a default route' }

    $targetIp = $targetInfo.Containers.PSObject.Properties.Value | Where-Object Name -eq $target | Select-Object -First 1 -ExpandProperty IPv4Address
    if (-not $targetIp) { throw 'target IP not found' }
    $targetIp = $targetIp.Split('/')[0]

    docker exec $sandbox /bin/sh -c ('curl -fsS --noproxy "*" --max-time 3 -o /dev/null http://{0}:18080/' -f $gateway)
    Assert-DockerSuccess 'sandbox to gateway'
    docker exec $gateway /bin/sh -c ('curl -fsS --noproxy "*" --max-time 3 -o /dev/null http://{0}:18080/' -f $target)
    Assert-DockerSuccess 'gateway to target'

    docker exec $sandbox /bin/sh -c ('nc -z -w 2 {0} 18080' -f $targetIp) 2>$null
    if ($LASTEXITCODE -eq 0) { throw 'sandbox reached target network directly' }
    docker exec $sandbox /bin/sh -c 'nc -z -w 2 192.0.2.1 443' 2>$null
    if ($LASTEXITCODE -eq 0) { throw 'sandbox reached TEST-NET directly' }

    Write-Output 'PASS: sandbox reaches its gateway; gateway reaches the synthetic target; sandbox cannot reach the target or TEST-NET directly.'
} finally {
    foreach ($name in $created) { docker rm -f -v $name 2>$null | Out-Null }
    foreach ($network in @($campaignNet, $targetNet)) { docker network rm $network 2>$null | Out-Null }
}
