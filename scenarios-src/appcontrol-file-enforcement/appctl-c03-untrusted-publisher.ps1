$exeName = "bas_$($script:AppCtlTid.Substring(0,8)).exe"
$certSubject = "CN=BAS-SIM-UNTRUSTED-$($script:AppCtlTid.Substring(0,8))"
Invoke-AppCtlTest -Family 'publisher_trust' -Collection 'Exe' -Needle $exeName -Technique 'T1553.002' -ExtraCleanup @() -Attempt {
  $cert = $null
  $keyDir = Join-Path $env:APPDATA 'Microsoft\Crypto\Keys'
  $keysBefore = @(Get-ChildItem -Path $keyDir -File -ErrorAction SilentlyContinue).Count
  try { $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $certSubject -CertStoreLocation 'Cert:\CurrentUser\My' -ErrorAction Stop } catch {}
  if (-not $cert) { return @{ Ran = $false; Exit = -1; Note = 'cert_create_failed'; NotApplicable = 'a self-signed code-signing certificate could not be created on this host' } }
  try {
    $exe = Join-Path $script:AppCtlWork $exeName
    if (-not (New-AppCtlExe -Path $exe)) { return @{ Ran = $false; Exit = -1; Note = 'compile_failed'; NotApplicable = (Get-AppCtlCompileReason) } }
    $sig = Set-AuthenticodeSignature -FilePath $exe -Certificate $cert -ErrorAction SilentlyContinue
    $status = (Get-AuthenticodeSignature -FilePath $exe).Status
    $trusted = $false
    $tsrc = Join-Path $env:SystemRoot 'System32\hostname.exe'
    $tcopy = Join-Path $script:AppCtlWork "bas_trusted_$($script:AppCtlTid.Substring(0,8)).exe"
    Copy-Item -Path $tsrc -Destination $tcopy -Force
    $tout = Join-Path $script:AppCtlWork 'trusted-out.txt'
    $tp = Start-Process -FilePath $tcopy -WindowStyle Hidden -PassThru -RedirectStandardOutput $tout -ErrorAction SilentlyContinue
    if ($tp -and $tp.WaitForExit(15000)) { $trusted = (((Get-Content $tout -ErrorAction SilentlyContinue) -join '').Length -gt 0) }
    $mk = Join-Path $script:AppCtlWork 'publisher-marker.txt'
    $p = Invoke-AppCtlProc -File $exe -ArgLine "`"$mk`""
    return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "untrusted_signature_status=$status trusted_microsoft_copy_ran=$trusted"; NotApplicable = '' }
  } finally {
    $kd = 'unknown'
    try {
      $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
      if ($rsa -is [Security.Cryptography.RSACng]) { $rsa.Key.Delete(); $kd = 'deleted' } elseif ($rsa) { $kd = 'not_cng' }
    } catch { $kd = 'delete_failed' }
    Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $certSubject } | ForEach-Object { Remove-Item -Path $_.PSPath -Force -ErrorAction SilentlyContinue }
    $keysAfter = @(Get-ChildItem -Path $keyDir -File -ErrorAction SilentlyContinue).Count
    Write-Output "APPCTL_CERT_CLEANUP: key_container=$kd key_files_before=$keysBefore key_files_after=$keysAfter"
  }
}
