# Cobalt Group BFSI - Encrypted Channel over Loopback TLS (c2-02)
$thumb = New-CgLoopbackTlsCertificate
if (-not $thumb) {
  Complete-CgStep @{ Outcome = 'error'; Reason = 'Could not create loopback self-signed certificate' } 'C2-02'
}
$undo_data = @{ scenario = 'c2-02'; thumbprint = $thumb }
try { New-CgUndoRecord 'c2-02' $undo_data } catch { Remove-CgLoopbackTlsCertificate -Thumbprint $thumb; Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'C2-02' }

$res = @{ Outcome = 'error'; Reason = 'TLS round trip did not run' }
$listener = $null; $server = $null; $client = $null; $tcpClient = $null
try {
  $listener = New-Object -TypeName Net.Sockets.TcpListener -ArgumentList ([Net.IPAddress]::Loopback), 0
  $listener.Start()
  $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
  $cert = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $thumb)

  $tcpClient = New-Object Net.Sockets.TcpClient
  $connectTask = $tcpClient.ConnectAsync([Net.IPAddress]::Loopback, $port)
  $acceptTask = $listener.AcceptTcpClientAsync()
  if (-not (Wait-CgTask $connectTask) -or -not (Wait-CgTask $acceptTask)) { throw 'loopback connect/accept timed out' }
  $acceptedSocket = $acceptTask.Result

  $server = New-Object Net.Security.SslStream($acceptedSocket.GetStream(), $false)
  Add-Type -TypeDefinition 'public static class BasLoopbackCertAccept { public static bool Accept(object s, System.Security.Cryptography.X509Certificates.X509Certificate c, System.Security.Cryptography.X509Certificates.X509Chain ch, System.Net.Security.SslPolicyErrors e) { return true; } }'
  $acceptCb = [Delegate]::CreateDelegate([Net.Security.RemoteCertificateValidationCallback], [BasLoopbackCertAccept].GetMethod('Accept'))
  $client = New-Object Net.Security.SslStream($tcpClient.GetStream(), $false, $acceptCb)

  $clientAuth = $client.AuthenticateAsClientAsync('localhost')
  $serverAuth = $server.AuthenticateAsServerAsync($cert, $false, [Security.Authentication.SslProtocols]::Tls12, $false)
  if (-not (Wait-CgTask $clientAuth) -or -not (Wait-CgTask $serverAuth)) { throw 'TLS handshake timed out' }

  $payload = [Text.Encoding]::ASCII.GetBytes('BAS-SIM-c2-02-ping')
  $client.Write($payload, 0, $payload.Length)
  $client.Flush()
  $buf = New-Object byte[] 64
  $readTask = $server.ReadAsync($buf, 0, $buf.Length)
  if (-not (Wait-CgTask $readTask)) { throw 'TLS read timed out' }
  $received = [Text.Encoding]::ASCII.GetString($buf, 0, $readTask.Result)

  if ($received -eq 'BAS-SIM-c2-02-ping') {
    $res = @{ Outcome = 'pass'; Reason = 'Encrypted loopback TLS session established and payload round-tripped' }
  } else {
    $res = @{ Outcome = 'fail'; Reason = 'TLS session established but payload did not round-trip' }
  }
} catch {
  $res = @{ Outcome = 'error'; Reason = "Loopback TLS session failed: $($_.Exception.Message)" }
} finally {
  foreach ($o in @($client, $server, $acceptedSocket, $tcpClient, $listener)) { if ($o) { try { $o.Dispose() } catch {} } }
  try { if ($listener) { $listener.Stop() } } catch {}
  Remove-CgLoopbackTlsCertificate -Thumbprint $thumb
}
Complete-CgStep $res 'C2-02'
