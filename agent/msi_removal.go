package main

import (
	"fmt"
	"regexp"
)

// productCodeRe matches a braced GUID, the only form accepted from the registry before it is
// placed on a command line.
var productCodeRe = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

func validMSIProductCode(code string) bool { return productCodeRe.MatchString(code) }

// msiRemovalCommand returns the argument list (program first) that removes the MSI after the
// service has stopped: a short delay, then `msiexec /x <code> /qn /norestart`. The product code is
// validated as a GUID, so nothing from the registry can alter the command.
//
// A remote "Uninstall Agent" runs inside the service it is removing, so msiexec is started
// detached and delayed; running it immediately would race the service's own shutdown.
func msiRemovalCommand(productCode string) ([]string, error) {
	if !validMSIProductCode(productCode) {
		return nil, fmt.Errorf("invalid MSI product code")
	}
	script := "Start-Sleep -Seconds 10; Start-Process -FilePath msiexec.exe " +
		"-ArgumentList '/x','" + productCode + "','/qn','/norestart' -Wait"
	return []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script}, nil
}
