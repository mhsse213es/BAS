# CSCRF-EA-02: the OS is still in a supported lifecycle. Windows 10 left mainstream support on 2025-10-14; it passes only with ESU enrolment (BAS_ESU_ENROLLED=true). Read only.
try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'OS version could not be read [CSCRF-EA-02]' } 'ea-02' }
$cap = $os.Caption
$build = [int]$os.BuildNumber
if ($cap -match 'Windows 10') {
  if ($env:BAS_ESU_ENROLLED -eq 'true') { Complete-CgStep @{ Outcome = 'pass'; Reason = "$cap build $build is covered by ESU enrolment (BAS_ESU_ENROLLED=true) [CSCRF-EA-02]" } 'ea-02' }
  Complete-CgStep @{ Outcome = 'fail'; Reason = "$cap build $build is past end of mainstream support (2025-10-14) with no ESU enrolment recorded [CSCRF-EA-02]" } 'ea-02'
}
if ($cap -match 'Windows (11|Server 2019|Server 2022|Server 2025)') { Complete-CgStep @{ Outcome = 'pass'; Reason = "$cap build $build is listed as in-support in this baseline [CSCRF-EA-02]" } 'ea-02' }
Complete-CgStep @{ Outcome = 'error'; Reason = "$cap is not in the lifecycle baseline; not evaluated [CSCRF-EA-02]" } 'ea-02'
