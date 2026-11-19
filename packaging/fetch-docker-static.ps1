# Downloads the pinned Docker + Compose static binaries into packaging\tools\docker and verifies every file
# against packaging\docker-static.pin. Run on an internet-connected build machine; the release bundle then
# carries these files so the server never needs the internet to get Docker.
#
#   .\packaging\fetch-docker-static.ps1 [-OutDir <folder>]
param([string] $OutDir = (Join-Path $PSScriptRoot "tools\docker"))
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$pin = @{}
foreach ($line in (Get-Content -LiteralPath (Join-Path $PSScriptRoot "docker-static.pin"))) {
    if ($line -match '^\s*#' -or $line.Trim() -eq "") { continue }
    if ($line -cnotmatch '^([A-Z0-9_]+)=(\S+)$') { throw "docker-static.pin: malformed line: $line" }
    $pin[$Matches[1]] = $Matches[2]
}
foreach ($k in "DOCKER_VERSION","COMPOSE_VERSION","DOCKER_SHA256_X86_64","DOCKER_SHA256_AARCH64","COMPOSE_SHA256_X86_64","COMPOSE_SHA256_AARCH64") {
    if (-not $pin.ContainsKey($k)) { throw "docker-static.pin: missing $k" }
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$files = @(
    @{ Name = "docker-$($pin.DOCKER_VERSION)-x86_64.tgz";  Url = "https://download.docker.com/linux/static/stable/x86_64/docker-$($pin.DOCKER_VERSION).tgz";  Sha = $pin.DOCKER_SHA256_X86_64 },
    @{ Name = "docker-$($pin.DOCKER_VERSION)-aarch64.tgz"; Url = "https://download.docker.com/linux/static/stable/aarch64/docker-$($pin.DOCKER_VERSION).tgz"; Sha = $pin.DOCKER_SHA256_AARCH64 },
    @{ Name = "docker-compose-linux-x86_64";  Url = "https://github.com/docker/compose/releases/download/$($pin.COMPOSE_VERSION)/docker-compose-linux-x86_64";  Sha = $pin.COMPOSE_SHA256_X86_64 },
    @{ Name = "docker-compose-linux-aarch64"; Url = "https://github.com/docker/compose/releases/download/$($pin.COMPOSE_VERSION)/docker-compose-linux-aarch64"; Sha = $pin.COMPOSE_SHA256_AARCH64 }
)
foreach ($f in $files) {
    $path = Join-Path $OutDir $f.Name
    $have = if (Test-Path -LiteralPath $path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() } else { "" }
    if ($have -ne $f.Sha) {
        Write-Host "Downloading $($f.Name) ..."
        Invoke-WebRequest -UseBasicParsing -Uri $f.Url -OutFile $path
        $have = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
        if ($have -ne $f.Sha) { Remove-Item -Force -LiteralPath $path; throw "$($f.Name): SHA-256 $have does not match the pinned $($f.Sha). Refusing to keep it." }
    }
    Write-Host "OK  $($f.Name)  $have"
}
Write-Host "Docker $($pin.DOCKER_VERSION) / Compose $($pin.COMPOSE_VERSION) ready in $OutDir"
