Import-Module Pester
. "$PSScriptRoot\sign-orchestrator-artifacts.ps1"

Describe "Update-BinaryManifestEntries" {
    BeforeAll {
        $script:FakeManifest = @(
            "1c84399f0afd503d3f11efb9feb10dd406e25a0d863a59ead8bce97ad19f4693  bas-agent-linux-amd64",
            "f51262d1324c39175930fa19d792a1490c37b10c403a85b1da19fd94aee6791a  bas-agent-linux-arm64",
            "ec25ce6563807cebab327341c9e64563aca5067a69d662ffcaefac8eb9a112b9  bas-agent-windows-amd64.exe",
            "06705e14ce78d8f81eeee71f4f6b34a77388adaa75d465480f423e0d725689ae  bas-agent-darwin-amd64",
            "bdee267560b2f64b29398bc6c066ea4cbebfd4f4bd646a31f64f0138f1db7424  bas-agent-darwin-arm64",
            "944e9fdfc49888f61387a05a96d421279817d6cffca16fdbb48ba92265db58f1  bas-agent-windows-legacy-amd64.exe"
        ) -join "`n"
    }

    It "replaces only the targeted lines, leaves every other line byte-identical" {
        $replacements = @{
            "bas-agent-windows-amd64.exe"        = "1111111111111111111111111111111111111111111111111111111111111111"
            "bas-agent-windows-legacy-amd64.exe" = "2222222222222222222222222222222222222222222222222222222222222222"
        }
        $result = Update-BinaryManifestEntries -ManifestContent $script:FakeManifest -Replacements $replacements
        $lines = $result -split "`n" | Where-Object { $_ -ne "" }

        $lines.Count | Should Be 6
        ($lines | Where-Object { $_ -match "bas-agent-windows-amd64\.exe$" }) | Should Be "1111111111111111111111111111111111111111111111111111111111111111  bas-agent-windows-amd64.exe"
        ($lines | Where-Object { $_ -match "bas-agent-windows-legacy-amd64\.exe$" }) | Should Be "2222222222222222222222222222222222222222222222222222222222222222  bas-agent-windows-legacy-amd64.exe"
        ($lines | Where-Object { $_ -match "bas-agent-linux-amd64$" }) | Should Be "1c84399f0afd503d3f11efb9feb10dd406e25a0d863a59ead8bce97ad19f4693  bas-agent-linux-amd64"
        ($lines | Where-Object { $_ -match "bas-agent-linux-arm64$" }) | Should Be "f51262d1324c39175930fa19d792a1490c37b10c403a85b1da19fd94aee6791a  bas-agent-linux-arm64"
        ($lines | Where-Object { $_ -match "bas-agent-darwin-amd64$" }) | Should Be "06705e14ce78d8f81eeee71f4f6b34a77388adaa75d465480f423e0d725689ae  bas-agent-darwin-amd64"
        ($lines | Where-Object { $_ -match "bas-agent-darwin-arm64$" }) | Should Be "bdee267560b2f64b29398bc6c066ea4cbebfd4f4bd646a31f64f0138f1db7424  bas-agent-darwin-arm64"
    }

    It "preserves line order exactly" {
        $replacements = @{ "bas-agent-windows-amd64.exe" = "3333333333333333333333333333333333333333333333333333333333333333" }
        $result = Update-BinaryManifestEntries -ManifestContent $script:FakeManifest -Replacements $replacements
        $lines = $result -split "`n" | Where-Object { $_ -ne "" }
        $filenames = ($lines | ForEach-Object { ($_ -split "  ", 2)[1] }) -join ","
        $filenames | Should Be "bas-agent-linux-amd64,bas-agent-linux-arm64,bas-agent-windows-amd64.exe,bas-agent-darwin-amd64,bas-agent-darwin-arm64,bas-agent-windows-legacy-amd64.exe"
    }

    It "throws when a replacement key has no matching line in the input" {
        $replacements = @{ "bas-agent-nonexistent-file" = "4444444444444444444444444444444444444444444444444444444444444444" }
        { Update-BinaryManifestEntries -ManifestContent $script:FakeManifest -Replacements $replacements } | Should Throw
    }
}
