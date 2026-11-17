$interp = $null
foreach ($c in @(@('python.exe', '--version'), @('python3.exe', '--version'), @('node.exe', '--version'), @('perl.exe', '-v'), @('ruby.exe', '--version'), @('php.exe', '-v'), @('java.exe', '-version'), @('lua.exe', '-v'))) {
  $cmd = Get-Command $c[0] -ErrorAction SilentlyContinue | Where-Object { $_.CommandType -eq 'Application' -and $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1
  if ($cmd) { $interp = @{ Path = $cmd.Source; Args = $c[1]; Name = $c[0] }; break }
}
$needle = if ($interp) { $interp.Name } else { 'no-interpreter-present' }
Invoke-AppCtlTest -Family 'alternate_interpreters' -Collection 'Exe' -Needle $needle -Technique 'T1059' -Attempt {
  if (-not $interp) { return @{ Ran = $false; Exit = -1; Note = 'no_alternate_interpreter_installed'; NotApplicable = 'no alternate interpreter (Python, Node, Perl, Ruby, PHP, Java, Lua) is installed outside the Store, and this test never installs one' } }
  $out = Join-Path $script:AppCtlWork 'interp-out.txt'
  $err = Join-Path $script:AppCtlWork 'interp-err.txt'
  $p = Start-Process -FilePath $interp.Path -ArgumentList $interp.Args -WindowStyle Hidden -PassThru -RedirectStandardOutput $out -RedirectStandardError $err -ErrorAction SilentlyContinue
  $done = $p -and $p.WaitForExit(15000)
  if ($p -and -not $done) { try { $p.Kill() } catch {} }
  $txt = ((Get-Content $out -ErrorAction SilentlyContinue) + (Get-Content $err -ErrorAction SilentlyContinue)) -join ' '
  return @{ Ran = [bool]($done -and $txt.Length -gt 0); Exit = $(if ($done -and $null -ne $p.ExitCode) { $p.ExitCode } else { -1 }); Note = "interpreter=$($interp.Name) version_output_chars=$($txt.Length)"; NotApplicable = '' }
}
