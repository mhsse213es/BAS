# Tests for scenarios/collection-channel-variants-exfil.yaml.
#
# Commands are extracted from the YAML so these tests run the text that ships. Nothing here connects to a
# host, sends data or changes firewall, proxy or policy. Firewall and proxy reads are read-only.
#
# Run: Invoke-Pester scripts/collection-channel-variants-exfil.Tests.ps1

BeforeAll {
    $ErrorActionPreference = 'Stop'
    $script:yamlPath = Join-Path $PSScriptRoot '..\scenarios\collection-channel-variants-exfil.yaml'

    function Get-ChnSteps {
        $lines = Get-Content -LiteralPath $script:yamlPath -Encoding UTF8
        $steps = @(); $cur = $null; $inCmd = $false
        foreach ($l in $lines) {
            if ($l -match '^  - name: "(.*)"') {
                if ($cur) { $steps += [pscustomobject]@{ Name = $cur.Name; Command = ($cur.Cmd -join "`r`n") } }
                $cur = @{ Name = $Matches[1]; Cmd = New-Object System.Collections.Generic.List[string] }; $inCmd = $false; continue
            }
            if (-not $cur) { continue }
            if ($l -match '^    command: \|\s*$') { $inCmd = $true; continue }
            if ($inCmd -and $l -match '^    \S') { $inCmd = $false }
            if ($inCmd) { $cur.Cmd.Add($(if ($l.Length -ge 6) { $l.Substring(6) } else { '' })) }
        }
        if ($cur) { $steps += [pscustomobject]@{ Name = $cur.Name; Command = ($cur.Cmd -join "`r`n") } }
        return $steps
    }

    function Invoke-Chn([string]$command, [hashtable]$env = @{}) {
        $file = Join-Path ([IO.Path]::GetTempPath()) ('chn-' + [guid]::NewGuid().ToString('N') + '.ps1')
        Set-Content -LiteralPath $file -Value $command -Encoding UTF8
        $old = @{}
        foreach ($k in $env.Keys) { $old[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, $env[$k]) }
        try {
            return @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $file 2>&1 | ForEach-Object { "$_" } | Where-Object { $_.Trim() -ne '' })
        } finally {
            foreach ($k in $old.Keys) { [Environment]::SetEnvironmentVariable($k, $old[$k]) }
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Channel variants scenario: structure and safety' {
    It 'has 24 steps with unique names' {
        $steps = Get-ChnSteps
        $steps.Count | Should -Be 24
        ($steps.Name | Sort-Object -Unique).Count | Should -Be 24
    }
    It 'has no connection, POST, upload or socket code anywhere' {
        $text = Get-Content -LiteralPath $script:yamlPath -Raw
        $text | Should -Not -Match 'Invoke-WebRequest|Invoke-RestMethod|TcpClient|Net\.Sockets|WebClient|Start-BitsTransfer|curl|-Method'
    }
    It 'resolves names only in the three resolver steps, each carrying the run id' {
        $hits = @(Get-ChnSteps | Where-Object { $_.Command -match 'Resolve-DnsName' })
        $hits.Count | Should -Be 3
        ($hits.Name | Sort-Object) | ForEach-Object { $_ -replace '^(Channel \d\.\d).*', '$1' } | Should -Be @('Channel 1.1', 'Channel 2.1', 'Channel 3.1')
        foreach ($h in $hits) { $h.Command | Should -Match 'bas-sim-(sftp|smb|beacon)-\$runId\.invalid' }
    }
    It 'never emits PASS or FAIL: the probe cannot establish a block or a transfer in this release' {
        $hits = @(Get-ChnSteps | Where-Object { $_.Command -match "Out-Verdict 'PASS'|Out-Verdict 'FAIL'|'FAIL:'|'PASS:'" })
        $hits.Count | Should -Be 0
    }
    It 'every step has telemetry and detection entries so the step contract is met' {
        $text = Get-Content -LiteralPath $script:yamlPath -Raw
        ([regex]::Matches($text, '\n    telemetry:\n      - ')).Count | Should -Be 24
        ([regex]::Matches($text, '\n    detection:\n      - ')).Count | Should -Be 24
    }
}

Describe 'Channel variants scenario: integrations and firewall reads' {
    It 'an unconfigured integration reports NOT_CONFIGURED' {
        $c = (Get-ChnSteps | Where-Object { $_.Name -like 'Channel 1.3*' }).Command
        $o = Invoke-Chn $c @{ BAS_CLP_ADAPTER_EGRESS = $null }
        ($o -join "`n") | Should -Match 'SKIP: state=NOT_CONFIGURED'
    }
    It 'a configured integration reports UNVERIFIED, never PASS' {
        $c = (Get-ChnSteps | Where-Object { $_.Name -like 'Channel 1.3*' }).Command
        $o = Invoke-Chn $c @{ BAS_CLP_ADAPTER_EGRESS = '1' }
        ($o -join "`n") | Should -Match 'SKIP: state=UNVERIFIED'
        ($o -join "`n") | Should -Not -Match '^PASS'
    }
    It 'the resolver step reports RESOLUTION_ONLY and never a block' {
        $c = (Get-ChnSteps | Where-Object { $_.Name -like 'Channel 2.1*' }).Command
        $o = Invoke-Chn $c
        ($o -join "`n") | Should -Match 'SKIP: state=RESOLUTION_ONLY'
        ($o -join "`n") | Should -Not -Match 'state=BLOCKED|PASS:'
    }
    It 'the firewall read reports configuration only, never ENFORCED' {
        $c = (Get-ChnSteps | Where-Object { $_.Name -like 'Channel 5.1*' }).Command
        $o = Invoke-Chn $c
        ($o -join "`n") | Should -Match '^SKIP: state=(CONFIGURED|NOT_CONFIGURED)'
        ($o -join "`n") | Should -Not -Match 'ENFORCED'
    }
    It 'the periodicity step reports NOT_CONFIGURED, since no detector exists' {
        $c = (Get-ChnSteps | Where-Object { $_.Name -like 'Channel 3.5*' }).Command
        $o = Invoke-Chn $c
        ($o -join "`n") | Should -Match 'SKIP: state=NOT_CONFIGURED no periodicity detector'
    }
}
