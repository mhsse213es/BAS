Invoke-A36Test -Id 'cc5' -Technique 'T1113' -Telemetry @('sysmon:1') -Summary 'a screenshot is captured to a run-tagged file and its dimensions verified; the image is not exfiltrated (T1113)' -Attempt {
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  $b = [Windows.Forms.SystemInformation]::VirtualScreen
  $bmp = New-Object Drawing.Bitmap($b.Width, $b.Height)
  $g = [Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($b.Left, $b.Top, 0, 0, $b.Size)
  $out = Join-Path $script:A36Work 'capture.png'
  $bmp.Save($out, [Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
  $saved = Test-Path -LiteralPath $out
  $size = 0
  if ($saved) { $size = (Get-Item -LiteralPath $out).Length }
  return @{ Ran = ($saved -and $size -gt 0); Note = "screen_width=$($b.Width) screen_height=$($b.Height) file_bytes=$size exfiltrated=false stored_in_run_tagged_temp_only=true"; NotApplicable = '' }
}
