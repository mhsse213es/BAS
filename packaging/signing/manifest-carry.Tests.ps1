#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Pester 5 tests for the helpers that keep a previous release's hashes ("#prev" lines) in BINARIES.sha256.
# Run: Invoke-Pester packaging/signing/manifest-carry.Tests.ps1

BeforeAll {
    . "$PSScriptRoot\sign-orchestrator-artifacts.ps1"
    function script:Hx([int]$n) { return ('{0:D64}' -f $n) }
}

Describe "Update-BinaryManifestEntries and #prev lines" {
    It "leaves a #prev line byte-identical even when its file name is being replaced" {
        # Regression: the previous release's Windows hash used to be overwritten with the current one, losing it.
        $manifest = (@(
            "$(Hx 1)  bas-agent-linux-amd64",
            "$(Hx 2)  bas-agent-windows-amd64.exe",
            "#prev $(Hx 90)  bas-agent-windows-amd64.exe",
            "#prev $(Hx 91)  bas-agent-linux-amd64"
        ) -join "`n") + "`n"
        $result = Update-BinaryManifestEntries -ManifestContent $manifest -Replacements @{ "bas-agent-windows-amd64.exe" = (Hx 7) }
        $lines = $result -split "`n" | Where-Object { $_ -ne "" }

        $lines | Should -Contain "#prev $(Hx 90)  bas-agent-windows-amd64.exe"
        $lines | Should -Contain "#prev $(Hx 91)  bas-agent-linux-amd64"
        $lines | Should -Contain "$(Hx 7)  bas-agent-windows-amd64.exe"
        $lines | Should -Not -Contain "$(Hx 2)  bas-agent-windows-amd64.exe"
        $lines.Count | Should -Be 4
    }

    It "does not count a #prev line as the entry it is asked to replace" {
        $manifest = "$(Hx 1)  bas-agent-linux-amd64`n#prev $(Hx 90)  bas-agent-windows-amd64.exe`n"
        { Update-BinaryManifestEntries -ManifestContent $manifest -Replacements @{ "bas-agent-windows-amd64.exe" = (Hx 7) } } | Should -Throw
    }
}

Describe "Add-ManifestEntryIfMissing and #prev lines" {
    It "still adds the entry when only a #prev line names the file" {
        $manifest = "$(Hx 1)  bas-agent-linux-amd64`n#prev $(Hx 90)  BASAgent.msi`n"
        $result = Add-ManifestEntryIfMissing -ManifestContent $manifest -FileName "BASAgent.msi"
        ($result -split "`n") | Should -Contain ("0" * 64 + "  BASAgent.msi")
    }
}

Describe "Get-PreviousReleaseManifest" {
    BeforeEach {
        $script:dist = Join-Path ([IO.Path]::GetTempPath()) ("dist-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:dist | Out-Null
        function script:Release([string]$ver, [bool]$withManifest = $true) {
            $d = Join-Path $script:dist "bas-install-$ver"
            New-Item -ItemType Directory -Path $d | Out-Null
            if ($withManifest) { Set-Content -LiteralPath (Join-Path $d 'BINARIES.sha256') -Value "$(Hx 1)  f" }
        }
    }
    AfterEach { Remove-Item -Recurse -Force $script:dist -ErrorAction SilentlyContinue }

    It "returns the newest release before the one being built" {
        Release '1.9.8'; Release '1.9.9'; Release '1.9.9.1'
        (Get-PreviousReleaseManifest -DistDir $script:dist -Version '1.9.10') | Should -Be (Join-Path $script:dist 'bas-install-1.9.9.1\BINARIES.sha256')
    }

    It "compares versions numerically, not as text" {
        Release '1.9.9'; Release '1.9.10'
        (Get-PreviousReleaseManifest -DistDir $script:dist -Version '1.10.0') | Should -Be (Join-Path $script:dist 'bas-install-1.9.10\BINARIES.sha256')
    }

    It "ignores the release being built and anything newer" {
        Release '1.9.8'; Release '1.9.9'; Release '2.0.0'
        (Get-PreviousReleaseManifest -DistDir $script:dist -Version '1.9.9') | Should -Be (Join-Path $script:dist 'bas-install-1.9.8\BINARIES.sha256')
    }

    It "skips a release directory that has no manifest" {
        Release '1.9.8'; Release '1.9.9' $false
        (Get-PreviousReleaseManifest -DistDir $script:dist -Version '1.9.10') | Should -Be (Join-Path $script:dist 'bas-install-1.9.8\BINARIES.sha256')
    }

    It "returns an empty string when there is no earlier release" {
        Release '1.9.9'
        (Get-PreviousReleaseManifest -DistDir $script:dist -Version '1.9.9') | Should -Be ''
        (Get-PreviousReleaseManifest -DistDir (Join-Path $script:dist 'missing') -Version '1.0.0') | Should -Be ''
    }

    It "ignores directories that are not numeric versions" {
        Release '1.9.8'; Release 'dev'
        (Get-PreviousReleaseManifest -DistDir $script:dist -Version '1.9.9') | Should -Be (Join-Path $script:dist 'bas-install-1.9.8\BINARIES.sha256')
    }
}

Describe "Test-ManifestCarriesPrevious" {
    BeforeEach {
        $script:dir = Join-Path ([IO.Path]::GetTempPath()) ("mf-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:dir | Out-Null
        $script:prev = Join-Path $script:dir 'previous.sha256'
        $script:cur  = Join-Path $script:dir 'current.sha256'
        Set-Content -LiteralPath $script:prev -Value @("$(Hx 1)  bas-agent-linux-amd64", "$(Hx 2)  bas-agent-darwin-arm64") -Encoding ascii
    }
    AfterEach { Remove-Item -Recurse -Force $script:dir -ErrorAction SilentlyContinue }

    It "reports nothing when every previous hash is carried" {
        Set-Content -LiteralPath $script:cur -Value @("$(Hx 11)  bas-agent-linux-amd64", "#prev $(Hx 1)  bas-agent-linux-amd64", "#prev $(Hx 2)  bas-agent-darwin-arm64") -Encoding ascii
        @(Test-ManifestCarriesPrevious -Manifest $script:cur -Previous $script:prev).Count | Should -Be 0
    }

    It "reports each previous hash that is neither an entry nor a #prev line" {
        Set-Content -LiteralPath $script:cur -Value @("$(Hx 11)  bas-agent-linux-amd64", "#prev $(Hx 1)  bas-agent-linux-amd64") -Encoding ascii
        $p = @(Test-ManifestCarriesPrevious -Manifest $script:cur -Previous $script:prev)
        $p.Count | Should -Be 1
        $p[0] | Should -Be "missing: $(Hx 2)  bas-agent-darwin-arm64"
    }

    It "does not report a previous hash that is still a current entry" {
        Set-Content -LiteralPath $script:cur -Value @("$(Hx 1)  bas-agent-linux-amd64", "#prev $(Hx 2)  bas-agent-darwin-arm64") -Encoding ascii
        @(Test-ManifestCarriesPrevious -Manifest $script:cur -Previous $script:prev).Count | Should -Be 0
    }

    It "reports a #prev line the server could not read" {
        Set-Content -LiteralPath $script:cur -Value @("#prev $(Hx 1)  bas-agent-linux-amd64", "#prev $(Hx 2)  bas-agent-darwin-arm64", "#prev nothex  file") -Encoding ascii
        $p = @(Test-ManifestCarriesPrevious -Manifest $script:cur -Previous $script:prev)
        $p.Count | Should -Be 1
        $p[0] | Should -Match '^malformed: #prev nothex'
    }

    It "follows the chain: a hash an earlier release carried must be carried again" {
        Set-Content -LiteralPath $script:prev -Value @("$(Hx 1)  bas-agent-linux-amd64", "#prev $(Hx 50)  bas-agent-linux-amd64") -Encoding ascii
        Set-Content -LiteralPath $script:cur -Value @("$(Hx 11)  bas-agent-linux-amd64", "#prev $(Hx 1)  bas-agent-linux-amd64") -Encoding ascii
        $p = @(Test-ManifestCarriesPrevious -Manifest $script:cur -Previous $script:prev)
        $p.Count | Should -Be 1
        $p[0] | Should -Be "missing: $(Hx 50)  bas-agent-linux-amd64"
    }
}
