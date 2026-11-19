# Extracts each stage's PowerShell command from the signed AD CS scenario YAML into stageNN.ps1 plus run-all.ps1, so the
# stages can be run by hand in a lab. Read-only helper: it only writes files in -OutDir.
param(
  [string]$Yaml = (Join-Path $PSScriptRoot '..\scenarios\adcs-esc-template-exposure-audit.yaml'),
  [string]$OutDir = 'C:\temp\adcs-stages'
)
New-Item -ItemType Directory -Force $OutDir | Out-Null
$lines = [IO.File]::ReadAllText((Resolve-Path $Yaml), [Text.Encoding]::UTF8) -split "`n"
$n = 0; $i = 0
while ($i -lt $lines.Count) {
  if ($lines[$i].TrimEnd("`r").StartsWith('    command: |')) {
    $i++; $body = New-Object System.Collections.Generic.List[string]
    while ($i -lt $lines.Count) {
      $l = $lines[$i].TrimEnd("`r")
      if ($l.StartsWith('      ')) { $body.Add($l.Substring(6)) } elseif ($l.Trim() -eq '') { $body.Add('') } else { break }
      $i++
    }
    while ($body.Count -gt 0 -and $body[$body.Count - 1] -eq '') { $body.RemoveAt($body.Count - 1) }
    $path = Join-Path $OutDir ('stage{0:00}.ps1' -f $n)
    [IO.File]::WriteAllText($path, (($body -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($true)))
    $n++
  } else { $i++ }
}
$runner = @'
# Runs ADCS stages 0-17 in order (read-only). Optional: $env:BAS_ADCS_LIVE_PROBE='true' enables the ESC8 HTTP probe.
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$log = Join-Path $dir ('results-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
0..17 | ForEach-Object {
  $f = Join-Path $dir ('stage{0:00}.ps1' -f $_)
  "===== STAGE $_ =====" | Tee-Object -FilePath $log -Append
  $sw = [Diagnostics.Stopwatch]::StartNew()
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $f 2>&1 | Tee-Object -FilePath $log -Append
  ("----- exit {0}, {1:n1}s" -f $LASTEXITCODE, $sw.Elapsed.TotalSeconds) | Tee-Object -FilePath $log -Append
}
"Saved: $log"
'@
[IO.File]::WriteAllText((Join-Path $OutDir 'run-all.ps1'), $runner, (New-Object Text.UTF8Encoding($true)))
"$n stages written to $OutDir"
