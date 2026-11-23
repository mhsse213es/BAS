# Tests for scenarios/collection-clipboard-exfil.yaml.
#
# Commands are extracted from the YAML so these tests run the text that ships. Policy values are
# stubbed through $global:BasStub, so enforcement logic is tested without writing HKLM or HKCU.
# Nothing here reads or stores real clipboard content; the capture test uses only its own marker.
#
# Run: Invoke-Pester scripts/collection-clipboard-exfil.Tests.ps1

BeforeAll {
    $ErrorActionPreference = 'Stop'
    $script:yamlPath = Join-Path $PSScriptRoot '..\scenarios\collection-clipboard-exfil.yaml'

    function Get-ClpSteps {
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

    function Get-ClpStep([string]$prefix) {
        $s = @(Get-ClpSteps | Where-Object { $_.Name -like "$prefix*" })
        if ($s.Count -ne 1) { throw "expected one step for '$prefix', got $($s.Count)" }
        return $s[0].Command
    }

    # Runs a command in a child PowerShell. Policy reads go to $global:BasStub (key 'path|name').
    function Invoke-Clp([string]$command, [hashtable]$stub = @{}, [hashtable]$env = @{}) {
        $stubbed = $command.Replace('try { return (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop).$name } catch { return $null }',
                                    'return $global:BasStub[$path + "|" + $name]')
        $prelude = '$global:BasStub = @{}' + "`r`n"
        foreach ($k in $stub.Keys) { $prelude += "`$global:BasStub['$k'] = " + $(if ($null -eq $stub[$k]) { '$null' } else { "'" + $stub[$k] + "'" }) + "`r`n" }
        $file = Join-Path ([IO.Path]::GetTempPath()) ('clp-' + [guid]::NewGuid().ToString('N') + '.ps1')
        Set-Content -LiteralPath $file -Value ($prelude + $stubbed) -Encoding UTF8
        $old = @{}
        foreach ($k in $env.Keys) { $old[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, $env[$k]) }
        try {
            return @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File $file 2>&1 | ForEach-Object { "$_" } | Where-Object { $_.Trim() -ne '' })
        } finally {
            foreach ($k in $old.Keys) { [Environment]::SetEnvironmentVariable($k, $old[$k]) }
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Clipboard scenario: structure and safety' {
    It 'has 32 steps with unique names' {
        $steps = Get-ClpSteps
        $steps.Count | Should -Be 32
        ($steps.Name | Sort-Object -Unique).Count | Should -Be 32
    }
    It 'has no network connection, POST or socket code anywhere' {
        $text = Get-Content -LiteralPath $script:yamlPath -Raw
        $text | Should -Not -Match 'Invoke-WebRequest|Invoke-RestMethod|TcpClient|Net\.Sockets|Net\.WebClient|Start-BitsTransfer|curl'
    }
    It 'resolves names only in the one resolver step' {
        $hits = @(Get-ClpSteps | Where-Object { $_.Command -match 'Resolve-DnsName' })
        $hits.Count | Should -Be 1
        $hits[0].Name | Should -Match '^Clipboard 7\.1'
    }
    It 'contains no clipboard content writes outside the synthetic capture step' {
        $hits = @(Get-ClpSteps | Where-Object { $_.Command -match 'SetText|Clipboard\]::Clear' })
        $hits.Count | Should -Be 1
        $hits[0].Name | Should -Match '^Clipboard 3\.1'
    }
    It 'emits only the agreed verdict words, and PASS or FAIL only from the history and sync enforcement steps' {
        $passFail = @(Get-ClpSteps | Where-Object { $_.Command -match "Out-Verdict 'PASS'|Out-Verdict 'FAIL'" })
        ($passFail.Name | Sort-Object) | ForEach-Object { $_ -replace '^(Clipboard \d\.\d).*', '$1' } | Should -Be @('Clipboard 4.1', 'Clipboard 4.2')
    }
}

Describe 'Clipboard scenario: enforcement verdicts' {
    It 'history: policy off and effective off gives PASS ENFORCED' {
        $c = Get-ClpStep 'Clipboard 4.1'
        $o = Invoke-Clp $c @{ 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System|AllowClipboardHistory' = '0'; 'HKCU:\Software\Microsoft\Clipboard|EnableClipboardHistory' = '0' }
        ($o -join "`n") | Should -Match '^PASS: state=ENFORCED'
    }
    It 'history: policy off but effective on gives FAIL CONTRADICTED' {
        $c = Get-ClpStep 'Clipboard 4.1'
        $o = Invoke-Clp $c @{ 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System|AllowClipboardHistory' = '0'; 'HKCU:\Software\Microsoft\Clipboard|EnableClipboardHistory' = '1' }
        ($o -join "`n") | Should -Match '^FAIL: state=CONTRADICTED'
    }
    It 'history: policy off with unreadable effective setting gives SKIP CANNOT_VERIFY, never PASS' {
        $c = Get-ClpStep 'Clipboard 4.1'
        $o = Invoke-Clp $c @{ 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System|AllowClipboardHistory' = '0' }
        ($o -join "`n") | Should -Match '^SKIP: state=CANNOT_VERIFY'
    }
    It 'history: no policy value gives SKIP NOT_CONFIGURED' {
        $c = Get-ClpStep 'Clipboard 4.1'
        $o = Invoke-Clp $c @{}
        ($o -join "`n") | Should -Match '^SKIP: state=NOT_CONFIGURED'
    }
    It 'history: policy allowing history gives SKIP CONFIGURED, not PASS' {
        $c = Get-ClpStep 'Clipboard 4.1'
        $o = Invoke-Clp $c @{ 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System|AllowClipboardHistory' = '1' }
        ($o -join "`n") | Should -Match '^SKIP: state=CONFIGURED'
    }
    It 'sync: policy off and effective off gives PASS ENFORCED' {
        $c = Get-ClpStep 'Clipboard 4.2'
        $o = Invoke-Clp $c @{ 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System|AllowCrossDeviceClipboard' = '0'; 'HKCU:\Software\Microsoft\Clipboard|CloudClipboardAutomaticUpload' = '0' }
        ($o -join "`n") | Should -Match '^PASS: state=ENFORCED'
    }
    It 'sync: policy off but effective on gives FAIL CONTRADICTED' {
        $c = Get-ClpStep 'Clipboard 4.2'
        $o = Invoke-Clp $c @{ 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System|AllowCrossDeviceClipboard' = '0'; 'HKCU:\Software\Microsoft\Clipboard|CloudClipboardAutomaticUpload' = '1' }
        ($o -join "`n") | Should -Match '^FAIL: state=CONTRADICTED'
    }
    It 'a policy value alone reports CONFIGURED and never scores' {
        $c = Get-ClpStep 'Clipboard 5.1'
        $o = Invoke-Clp $c @{ 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|fDisableClip' = '1' }
        ($o -join "`n") | Should -Match '^SKIP: state=CONFIGURED'
    }
}

Describe 'Clipboard scenario: integrations are never PASS' {
    It 'an unconfigured integration reports NOT_CONFIGURED' {
        $c = Get-ClpStep 'Clipboard 2.1'
        $o = Invoke-Clp $c @{} @{ BAS_CLP_ADAPTER_DEFENDER = $null }
        ($o -join "`n") | Should -Match '^SKIP: state=NOT_CONFIGURED'
    }
    It 'a configured integration reports UNVERIFIED, not PASS, because no operational probe exists' {
        $c = Get-ClpStep 'Clipboard 2.1'
        $o = Invoke-Clp $c @{} @{ BAS_CLP_ADAPTER_DEFENDER = '1' }
        ($o -join "`n") | Should -Match '^SKIP: state=UNVERIFIED'
    }
}

Describe 'Clipboard scenario: synthetic capture and clear' {
    It 'with user content present, nothing is read, written or cleared' {
        Add-Type -AssemblyName System.Windows.Forms
        $setHere = -not [System.Windows.Forms.Clipboard]::ContainsText()
        if ($setHere) { [System.Windows.Forms.Clipboard]::SetText('[BAS-SIM-CLP] user-stand-in') }
        try {
            $o = Invoke-Clp (Get-ClpStep 'Clipboard 3.1') @{} @{}
            ($o -join "`
") | Should -Match '^SKIP: state=USER_CONTENT_PRESENT'
            [System.Windows.Forms.Clipboard]::ContainsText() | Should -BeTrue
        } finally { if ($setHere) { [System.Windows.Forms.Clipboard]::Clear() } }
    }
    It 'with an empty clipboard, the synthetic marker is written, read back, cleared, and reported UNVERIFIED' {
        Add-Type -AssemblyName System.Windows.Forms
        if ([System.Windows.Forms.Clipboard]::ContainsText()) { Set-ItResult -Skipped -Because 'clipboard holds text; empty-clipboard path not reachable without changing user data' }
        else {
            $o = Invoke-Clp (Get-ClpStep 'Clipboard 3.1') @{} @{}
            ($o -join "`n") | Should -Match '^SKIP: state=UNVERIFIED'
            [System.Windows.Forms.Clipboard]::ContainsText() | Should -BeFalse
        }
    }
    It 'the clear is guarded by a clipboard sequence-number check, so a later change is never cleared' {
        $c = Get-ClpStep 'Clipboard 3.1'
        $c | Should -Match 'GetClipboardSequenceNumber'
        $c | Should -Match 'if \(\$seqNow -ne \$seqAfterSet\)'
        $c.IndexOf('$seqNow -ne $seqAfterSet') | Should -BeLessThan $c.IndexOf('Clipboard]::Clear()')
    }
}
