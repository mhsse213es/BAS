#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    . "$PSScriptRoot\sign-orchestrator-artifacts.ps1"
}

Describe "Add-ManifestEntryIfMissing" {
    It "appends a placeholder line when the file is not listed" {
        $r = Add-ManifestEntryIfMissing -ManifestContent "aaaa  bas-agent-linux-amd64`n" -FileName "AudspectAgent-x64.msi"
        ($r -split "`n" | Where-Object { $_ -ne "" }).Count | Should -Be 2
        $r | Should -Match ("(?m)^" + ("0" * 64) + "  AudspectAgent-x64\.msi$")
    }

    It "leaves the manifest unchanged when the file is already listed" {
        $m = "bbbb  AudspectAgent-x64.msi`naaaa  bas-agent-linux-amd64`n"
        (Add-ManifestEntryIfMissing -ManifestContent $m -FileName "AudspectAgent-x64.msi") | Should -Be $m
    }

    It "does not treat a longer name as a match" {
        $r = Add-ManifestEntryIfMissing -ManifestContent "cccc  AudspectAgent-x64.msi.sha256`n" -FileName "AudspectAgent-x64.msi"
        ($r -split "`n" | Where-Object { $_ -ne "" }).Count | Should -Be 2
    }

    It "tolerates CRLF line endings and no trailing newline" {
        $r = Add-ManifestEntryIfMissing -ManifestContent "aaaa  x`r`nbbbb  y" -FileName "z.msi"
        ($r -split "`n" | Where-Object { $_ -ne "" }).Count | Should -Be 3
    }

    It "composes with Update-BinaryManifestEntries so a new artifact gets its real hash" {
        $m = Add-ManifestEntryIfMissing -ManifestContent "aaaa  x`n" -FileName "AudspectAgent-x64.msi"
        $real = "f" * 64
        $u = Update-BinaryManifestEntries -ManifestContent $m -Replacements @{ "AudspectAgent-x64.msi" = $real }
        $u | Should -Match ("(?m)^" + $real + "  AudspectAgent-x64\.msi$")
        $u | Should -Not -Match ("0" * 64)
    }
}
