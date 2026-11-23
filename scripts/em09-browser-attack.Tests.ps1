# Tests for scenarios/endpoint-mastery/em-09-browser-attack.yaml.
#
# The command under test is extracted from the YAML itself, so these tests run the exact text
# that the signed scenario ships. Fixture tests build a temporary LOCALAPPDATA tree and need no
# browser. Lab tests run against the real profiles and only when BAS_EM09_LAB=1 is set.
#
# Run: Invoke-Pester scripts/em09-browser-attack.Tests.ps1

BeforeAll {
$ErrorActionPreference = 'Stop'
$script:yamlPath = Join-Path $PSScriptRoot '..\scenarios\endpoint-mastery\em-09-browser-attack.yaml'

function Get-EM09Command([string]$stepName) {
    $lines = Get-Content -LiteralPath $script:yamlPath -Encoding UTF8
    $inStep = $false; $inCmd = $false; $out = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
        if ($l -match '^\s+- name: ') { $inStep = ($l -like "*$stepName*"); $inCmd = $false; continue }
        if (-not $inStep) { continue }
        if ($l -match '^    command: \|\s*$') { $inCmd = $true; continue }
        if ($inCmd -and $l -match '^    \S') { break }
        if ($inCmd) { $out.Add($(if ($l.Length -ge 6) { $l.Substring(6) } else { '' })) }
    }
    if ($out.Count -eq 0) { throw "command block not found for step '$stepName'" }
    return ($out -join "`r`n")
}

function Invoke-EM09Command([string]$command, [string]$localAppData) {
    $script = Join-Path ([IO.Path]::GetTempPath()) ("em09-" + [guid]::NewGuid().ToString('N') + '.ps1')
    Set-Content -LiteralPath $script -Value $command -Encoding UTF8
    $old = $env:LOCALAPPDATA
    try {
        if ($localAppData) { $env:LOCALAPPDATA = $localAppData }
        $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script 2>&1
        return @($output | ForEach-Object { "$_" } | Where-Object { $_.Trim() -ne '' })
    } finally {
        $env:LOCALAPPDATA = $old
        Remove-Item -LiteralPath $script -Force -ErrorAction SilentlyContinue
    }
}

function New-EM09Fixture([string]$browserRel, [string[]]$profiles) {
    $root = Join-Path ([IO.Path]::GetTempPath()) ("em09-local-" + [guid]::NewGuid().ToString('N'))
    $userData = Join-Path $root $browserRel
    New-Item -ItemType Directory -Path $userData -Force | Out-Null
    $cache = @{}
    foreach ($p in $profiles) { $cache[$p] = @{} }
    $ls = @{ profile = @{ info_cache = $cache } } | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath (Join-Path $userData 'Local State') -Value $ls -Encoding UTF8
    return @{ root = $root; userData = $userData }
}
}

Describe 'EM-09 scenario YAML' {
    It 'contains two steps with the expected techniques' {
        $text = Get-Content -LiteralPath $script:yamlPath -Raw
        $text | Should -Match 'technique_id: T1539'
        $text | Should -Match 'technique_id: T1555\.003'
    }
    It 'contains no citation markers or BAS-SIM tags' {
        $text = Get-Content -LiteralPath $script:yamlPath -Raw
        $text | Should -Not -Match '\[cite:'
        $text | Should -Not -Match 'BAS-SIM'
    }
    It 'does not extract, decrypt or copy browser content' {
        $cmd = (Get-EM09Command 'Chrome') + (Get-EM09Command 'Edge')
        $cmd | Should -Not -Match 'Copy-Item|Export|Decrypt|ReadAllBytes|ReadAllText|Invoke-Sqlite|sqlite'
    }
}

Describe 'EM-09 fixture: Chrome profile discovery and access' {
    BeforeAll { $chrome = Get-EM09Command 'Chrome' }

    It 'reports one line per profile from Local State, with ACCESS_ALLOWED for a readable cookie database' {
        $fx = New-EM09Fixture 'Google\Chrome\User Data' @('Default', 'Profile 1')
        try {
            foreach ($p in 'Default', 'Profile 1') {
                $dir = Join-Path $fx.userData "$p\Network"
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                Set-Content -LiteralPath (Join-Path $dir 'Cookies') -Value 'fixture' -Encoding ASCII
            }
            $out = Invoke-EM09Command $chrome $fx.root
            @($out | Where-Object { $_ -match '^FAIL: state=ACCESS_ALLOWED browser=chrome profile=' }).Count | Should -Be 2
        } finally { Remove-Item -LiteralPath $fx.root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'reports ACCESS_DENIED (PASS) when read is denied by ACL' {
        $fx = New-EM09Fixture 'Google\Chrome\User Data' @('Default')
        $file = Join-Path $fx.userData 'Default\Network\Cookies'
        New-Item -ItemType Directory -Path (Split-Path $file) -Force | Out-Null
        Set-Content -LiteralPath $file -Value 'fixture' -Encoding ASCII
        $who = "$env:USERDOMAIN\$env:USERNAME"
        & icacls.exe $file /deny "${who}:(R)" | Out-Null
        try {
            $out = Invoke-EM09Command $chrome $fx.root
            ($out -join "`n") | Should -Match '^PASS: state=ACCESS_DENIED browser=chrome profile=Default file=Network/Cookies'
        } finally {
            & icacls.exe $file /remove:d "$who" | Out-Null
            Remove-Item -LiteralPath $fx.root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'reports LOCKED_BY_BROWSER (SKIP) when another process holds the file exclusively' {
        $fx = New-EM09Fixture 'Google\Chrome\User Data' @('Default')
        $file = Join-Path $fx.userData 'Default\Network\Cookies'
        New-Item -ItemType Directory -Path (Split-Path $file) -Force | Out-Null
        Set-Content -LiteralPath $file -Value 'fixture' -Encoding ASCII
        $holder = [IO.File]::Open($file, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $out = Invoke-EM09Command $chrome $fx.root
            ($out -join "`n") | Should -Match '^SKIP: state=LOCKED_BY_BROWSER browser=chrome profile=Default'
        } finally {
            $holder.Dispose()
            Remove-Item -LiteralPath $fx.root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'reports NOT_FOUND for a profile without a cookie database, and names WAL sidecars' {
        $fx = New-EM09Fixture 'Google\Chrome\User Data' @('Default', 'Profile 2')
        $file = Join-Path $fx.userData 'Default\Network\Cookies'
        New-Item -ItemType Directory -Path (Split-Path $file) -Force | Out-Null
        Set-Content -LiteralPath $file -Value 'fixture' -Encoding ASCII
        Set-Content -LiteralPath "$file-wal" -Value 'wal' -Encoding ASCII
        try {
            $out = Invoke-EM09Command $chrome $fx.root
            $text = $out -join "`n"
            $text | Should -Match 'SKIP: state=NOT_FOUND browser=chrome profile=Profile 2 file=Cookies'
            $text | Should -Match 'sidecars=wal'
        } finally { Remove-Item -LiteralPath $fx.root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'reports NOT_FOUND when the browser is not installed' {
        $root = Join-Path ([IO.Path]::GetTempPath()) ("em09-empty-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        try {
            $out = Invoke-EM09Command $chrome $root
            ($out -join "`n") | Should -Match '^SKIP: state=NOT_FOUND browser=chrome detail=user data folder absent'
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'EM-09 fixture: Edge Login Data' {
    BeforeAll { $edge = Get-EM09Command 'Edge' }

    It 'reports ACCESS_ALLOWED for a readable Login Data file, without reading its contents' {
        $fx = New-EM09Fixture 'Microsoft\Edge\User Data' @('Default')
        $file = Join-Path $fx.userData 'Default\Login Data'
        New-Item -ItemType Directory -Path (Split-Path $file) -Force | Out-Null
        Set-Content -LiteralPath $file -Value 'fixture' -Encoding ASCII
        try {
            $out = Invoke-EM09Command $edge $fx.root
            ($out -join "`n") | Should -Match '^FAIL: state=ACCESS_ALLOWED browser=edge profile=Default file=Login Data'
        } finally { Remove-Item -LiteralPath $fx.root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'reports NOT_FOUND when a profile has no Login Data' {
        $fx = New-EM09Fixture 'Microsoft\Edge\User Data' @('Default')
        try {
            $out = Invoke-EM09Command $edge $fx.root
            ($out -join "`n") | Should -Match '^SKIP: state=NOT_FOUND browser=edge profile=Default file=Login Data'
        } finally { Remove-Item -LiteralPath $fx.root -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'EM-09 lab: real Windows browser profiles' -Skip:($env:BAS_EM09_LAB -ne '1') {
    It 'emits only evidence-state lines for the real Chrome profiles' {
        $out = Invoke-EM09Command (Get-EM09Command 'Chrome') $null
        foreach ($l in $out) { $l | Should -Match '^(PASS|FAIL|SKIP|ERROR): state=(ACCESS_ALLOWED|ACCESS_DENIED|NOT_FOUND|LOCKED_BY_BROWSER|ERROR) ' }
    }
    It 'emits only evidence-state lines for the real Edge profiles' {
        $out = Invoke-EM09Command (Get-EM09Command 'Edge') $null
        foreach ($l in $out) { $l | Should -Match '^(PASS|FAIL|SKIP|ERROR): state=(ACCESS_ALLOWED|ACCESS_DENIED|NOT_FOUND|LOCKED_BY_BROWSER|ERROR) ' }
    }
}
