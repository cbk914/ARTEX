# Use only a disposable local instance and a synthetic password.
param(
    [Parameter(Mandatory = $true)][string]$BaseUrl,
    [Parameter(Mandatory = $true)][string]$Password
)

$ErrorActionPreference = 'Stop'
$uri = [Uri]$BaseUrl
if ($uri.Scheme -ne 'http' -or $uri.Host -notin @('127.0.0.1', 'localhost') -or $uri.AbsolutePath -ne '/') {
    throw 'Use only a disposable localhost HTTP fixture'
}
$base = $uri.GetLeftPart([UriPartial]::Authority)
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$body = @{ username = 'ARTEX'; password = $Password } | ConvertTo-Json -Compress
$login = Invoke-WebRequest -Uri "$base/api/auth/login" -Method Post -Body $body -ContentType 'application/json' `
    -Headers @{ Origin = $base; 'X-ARTEX-Browser-Session' = '1' } -WebSession $session
$setCookie = $login.Headers['Set-Cookie'] -join '; '
if ($login.StatusCode -ne 200 -or ($login.Content | ConvertFrom-Json).ok -ne $true -or
    $login.Content -match 'token' -or $setCookie -notmatch 'HttpOnly' -or $setCookie -notmatch 'SameSite=Lax') {
    throw 'Browser login contract failed'
}
$cookie = $session.Cookies.GetCookies($base)['artex_token']
if (-not $cookie -or -not $cookie.HttpOnly) { throw 'Browser cookie missing' }
$check = Invoke-RestMethod -Uri "$base/api/auth/session" -WebSession $session
if (-not $check.authenticated) { throw 'Session cookie rejected' }
$tasks = Invoke-WebRequest -Uri "$base/api/tasks" -WebSession $session
if ($tasks.StatusCode -ne 200) { throw 'Session did not authorize tasks' }
$logout = Invoke-WebRequest -Uri "$base/api/auth/logout" -Method Post -Headers @{ Origin = $base } -WebSession $session
if ($logout.StatusCode -ne 200) { throw 'Logout failed' }
$replay = Invoke-WebRequest -Uri "$base/api/tasks" -Headers @{ Authorization = "Bearer $($cookie.Value)" } -SkipHttpErrorCheck
if ($replay.StatusCode -ne 401) { throw 'Copied bearer survived logout' }
$after = Invoke-RestMethod -Uri "$base/api/auth/session" -WebSession $session
if ($after.authenticated) { throw 'Browser session survived logout' }
Write-Output 'PASS: browser-session HTTP contract, logout and copied-token revocation'
