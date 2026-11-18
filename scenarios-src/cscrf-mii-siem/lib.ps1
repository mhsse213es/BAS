# CSCRF-MII SIEM pack shared library. ASCII only. Minified by appctlgen.
# Verdicts: PASS = configured as expected. FAIL = configuration gap observed. ERROR = check could not run. SKIP = prerequisite unmet.
$ErrorActionPreference = 'SilentlyContinue'
function Write-CgVerdict { param([string]$Outcome, [string]$Reason, [string]$Id)
  $p = 'SKIP'
  if ($Outcome -eq 'pass') { $p = 'PASS' } elseif ($Outcome -eq 'fail') { $p = 'FAIL' } elseif ($Outcome -eq 'error') { $p = 'ERROR' }
  Write-Output ($p + ': ' + $Reason + ' [BAS-SIEM-' + $Id + ']')
}
function Complete-CgStep { param($Res, [string]$Id) Write-CgVerdict $Res.Outcome $Res.Reason $Id; exit 0 }
