Invoke-A36Test -Id 'cc4' -Technique 'T1115' -Telemetry @('sysmon:1') -Summary 'the clipboard is read programmatically, with synthetic text placed there by this step only (T1115)' -Attempt {
  $out = Join-Path $script:A36Work 'clip-out.txt'
  $text = $script:A36Marker + ' synthetic clipboard content'
  $child = Join-Path $script:A36Work 'clip.ps1'
  $sq = [string][char]39
  Set-Content -LiteralPath $child -Encoding ASCII -Value @('Add-Type -AssemblyName System.Windows.Forms', ('[Windows.Forms.Clipboard]::SetText(' + $sq + $text + $sq + ')'), 'Start-Sleep -Milliseconds 200', ('[Windows.Forms.Clipboard]::GetText() | Set-Content -LiteralPath ' + $sq + $out + $sq))
  $psExe = Join-Path $env:SystemRoot (Join-Path 'System32' (Join-Path 'WindowsPowerShell' (Join-Path 'v1.0' 'powershell.exe')))
  $placed = $false
  $p = Invoke-A36Proc -File $psExe -ArgLine ('-NoProfile -NonInteractive -STA -File "' + $child + '"') -TimeoutSec 15 -NoShell
  $placed = $true
  $read = ''
  if (Test-Path -LiteralPath $out) { $read = [string](Get-Content -LiteralPath $out -Raw) }
  $matched = ($read -like "*$($script:A36Marker)*")
  return @{ Ran = $matched; Note = "clipboard_write_attempted=$placed child_started=$($p.Started) clipboard_read_matches=$matched source=synthetic_text_only real_user_clipboard_content=untouched"; NotApplicable = '' }
}
