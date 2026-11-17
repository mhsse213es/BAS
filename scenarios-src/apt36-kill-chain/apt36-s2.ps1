Invoke-A36Test -Id 's2' -Technique 'T1221' -Summary 'a document with a remote attachedTemplate relationship is built and its template is fetched from a loopback server (T1221); Office is not opened' -Telemetry @('sysmon:1', 'sysmon:3') -Attempt {
  $port = Get-Random -Minimum 20000 -Maximum 29999
  $docx = Join-Path $script:A36Work 'invoice.docx'
  $tmplUrl = "http://127.0.0.1:$port/$($script:A36Tag)/template.dotm"
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="' + $tmplUrl + '" TargetMode="External"/></Relationships>'
  $ct = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
  $root = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
  $body = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>' + $script:A36Marker + ' synthetic invoice</w:t></w:r></w:p></w:body></w:document>'
  $settings = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:attachedTemplate r:id="rId1"/></w:settings>'
  $zip = [IO.Compression.ZipFile]::Open($docx, 'Create')
  try {
    foreach ($e in @(@('[Content_Types].xml', $ct), @('_rels/.rels', $root), @('word/document.xml', $body), @('word/settings.xml', $settings), @('word/_rels/settings.xml.rels', $rels))) {
      $en = $zip.CreateEntry($e[0]); $sw = New-Object IO.StreamWriter($en.Open()); $sw.Write($e[1]); $sw.Close()
    }
  } finally { $zip.Dispose() }
  $z2 = [IO.Compression.ZipFile]::OpenRead($docx)
  try { $r = New-Object IO.StreamReader($z2.GetEntry('word/_rels/settings.xml.rels').Open()); $found = $r.ReadToEnd(); $r.Close() } finally { $z2.Dispose() }
  $extracted = if ($found -match 'Target="([^"]+)"') { $matches[1] } else { '' }
  $l = New-Object Net.HttpListener
  $l.Prefixes.Add("http://127.0.0.1:$port/")
  try { $l.Start() } catch { return @{ Ran = $false; Note = 'listener_start_failed'; NotApplicable = 'a loopback HTTP listener could not be started on this host' } }
  $served = $false; $got = ''
  try {
    $ar = $l.BeginGetContext($null, $null)
    $dst = Join-Path $script:A36Work 'template.dotm'
    $child = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList ('-NoProfile -NonInteractive -Command "(New-Object Net.WebClient).DownloadFile(''' + $extracted + ''', ''' + $dst + ''')"') -WindowStyle Hidden -PassThru
    if ($ar.AsyncWaitHandle.WaitOne(15000)) {
      $ctx = $l.EndGetContext($ar)
      $bytes = [Text.Encoding]::UTF8.GetBytes($script:A36Marker + ' synthetic template, contains no macro')
      $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length); $ctx.Response.Close(); $served = $true
    }
    if ($child) { [void]$child.WaitForExit(20000) }
    if (Test-Path -LiteralPath $dst) { $got = [string](Get-Content -LiteralPath $dst -Raw) }
  } finally { try { $l.Stop() } catch {}; try { $l.Close() } catch {} }
  $landed = ($got -like "*$($script:A36Marker)*")
  return @{ Ran = ($landed -and $extracted -eq $tmplUrl); Note = "document_built=true relationship_target_matches=$($extracted -eq $tmplUrl) template_served=$served template_landed=$landed template_loaded_by_office=false macro_executed=false (Office is not opened, so template execution is not tested)"; NotApplicable = '' }
}
