//go:build !linux && !darwin

package secretstore

import "io/fs"

// platformKeyFileCheck applies the mode check where it means something. Windows ACLs are not expressed in mode bits, and the
// product's interim key is provisioned on Linux hosts (see DefaultKeyPath). Windows builds do not run the store in production.
func platformKeyFileCheck(fi fs.FileInfo) error {
	return nil
}
