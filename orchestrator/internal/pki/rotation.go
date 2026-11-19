package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Planned, overlap-based rotation of the deployment CA (audit F-09).
//
// A rotation never replaces the CA in one step. It moves through states that are visible from the files
// in the PKI directory alone, so a crash or a restart cannot leave the server guessing:
//
//	stable    ca-key.pem, ca-cert.pem
//	prepared  + next-ca-key.pem, next-ca-cert.pem, next-ca-cross.pem   (the new CA exists; issuance is unchanged)
//	promoted  ca-* is the NEW CA; previous-ca-key.pem / previous-ca-cert.pem keep the old one trusted
//
// stable -> prepared (StartRotation) -> promoted (PromoteRotation) -> stable (RetireRotation).
// AbortRotation leaves "prepared" and RollbackRotation leaves "promoted" (back to "prepared") without loss.
//
// Agents are told to trust the new root through an operator-initiated, signed command, never through an
// enrolment response; this file only manages the server's side. A missing CA is never a rotation: every
// entry point refuses to run unless a complete current CA is present. Every step that changes live files
// first copies the PKI files to rotation-backups/ so the previous state can be restored by hand.

const (
	nextKeyFile      = "next-ca-key.pem"
	nextCertFile     = "next-ca-cert.pem"
	nextCrossFile    = "next-ca-cross.pem"
	previousKeyFile  = "previous-ca-key.pem"
	previousCertFile = "previous-ca-cert.pem"
	rotationBackups  = "rotation-backups"
)

type RotationState string

const (
	RotationStable   RotationState = "stable"
	RotationPrepared RotationState = "prepared"
	RotationPromoted RotationState = "promoted"
)

func p(dir, name string) string { return filepath.Join(dir, name) }

func present(path string) bool { _, err := os.Stat(path); return err == nil }

// RotationStatus reports the rotation state. Any combination of files that is not exactly one of the
// states above is an error, never a guess: the operator is pointed at the backups.
func RotationStatus(dir string) (RotationState, error) {
	if !present(p(dir, "ca-key.pem")) || !present(p(dir, "ca-cert.pem")) {
		return "", fmt.Errorf("no complete current CA in %s; a missing CA is not a rotation", dir)
	}
	nk, nc, nx := present(p(dir, nextKeyFile)), present(p(dir, nextCertFile)), present(p(dir, nextCrossFile))
	pk, pc := present(p(dir, previousKeyFile)), present(p(dir, previousCertFile))
	switch {
	case !nk && !nc && !nx && !pk && !pc:
		return RotationStable, nil
	case nk && nc && nx && !pk && !pc:
		return RotationPrepared, nil
	case !nk && !nc && nx && pk && pc:
		return RotationPromoted, nil
	}
	return "", fmt.Errorf("the CA rotation files in %s are in an inconsistent state (next key %v, next cert %v, cross %v, previous key %v, previous cert %v); restore from %s",
		dir, nk, nc, nx, pk, pc, p(dir, rotationBackups))
}

func requireState(dir string, want RotationState) error {
	got, err := RotationStatus(dir)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("CA rotation is %s; this step needs it to be %s", got, want)
	}
	return nil
}

// backupFiles copies every PEM in dir into a new rotation-backups/<time>-<label>/ and returns it.
func backupFiles(dir, label string, now time.Time) (string, error) {
	dst := p(dir, filepath.Join(rotationBackups, now.UTC().Format("20060102T150405.000000000Z")+"-"+label))
	if err := os.MkdirAll(dst, 0700); err != nil {
		return "", fmt.Errorf("create backup dir: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".pem" {
			continue
		}
		b, err := os.ReadFile(p(dir, e.Name()))
		if err != nil {
			return "", fmt.Errorf("back up %s: %w", e.Name(), err)
		}
		if err := os.WriteFile(p(dst, e.Name()), b, 0600); err != nil {
			return "", fmt.Errorf("back up %s: %w", e.Name(), err)
		}
	}
	return dst, nil
}

// StartRotation creates the next CA and a cross-certificate for it signed by the current CA, and backs
// up the current CA. It changes nothing about issuance or trust. Returns the backup directory.
func StartRotation(dir string, now time.Time) (string, error) {
	if err := requireState(dir, RotationStable); err != nil {
		return "", err
	}
	cur, err := loadCA(p(dir, "ca-key.pem"), p(dir, "ca-cert.pem"))
	if err != nil {
		return "", err
	}
	backup, err := backupFiles(dir, "start", now)
	if err != nil {
		return "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate next CA key: %w", err)
	}
	tmpl := func(cn string) (*x509.Certificate, error) {
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, err
		}
		return &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: cn, Organization: []string{"Audspect"}},
			NotBefore:             now.Add(-5 * time.Minute),
			NotAfter:              now.Add(caValidity),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
			IsCA:                  true,
		}, nil
	}
	cn := "Audspect Deployment CA " + now.UTC().Format("2006-01-02")
	if cn == cur.cert.Subject.CommonName {
		cn += " (next)"
	}
	nextTmpl, err := tmpl(cn)
	if err != nil {
		return "", err
	}
	nextDER, err := x509.CreateCertificate(rand.Reader, nextTmpl, nextTmpl, &key.PublicKey, key)
	if err != nil {
		return "", fmt.Errorf("create next CA certificate: %w", err)
	}
	crossTmpl, err := tmpl(cn)
	if err != nil {
		return "", err
	}
	crossDER, err := x509.CreateCertificate(rand.Reader, crossTmpl, cur.cert, &key.PublicKey, cur.key)
	if err != nil {
		return "", fmt.Errorf("create cross-certificate: %w", err)
	}
	// Key first; the certificates last, because the cross-certificate is what completes the "prepared" state.
	if err := writeECKeyPEM(p(dir, nextKeyFile), key); err != nil {
		return "", err
	}
	if err := writeCertPEM(p(dir, nextCertFile), nextDER); err != nil {
		return "", err
	}
	if err := writeCertPEM(p(dir, nextCrossFile), crossDER); err != nil {
		return "", err
	}
	return backup, nil
}

// AbortRotation discards a prepared next CA. The current CA is untouched.
func AbortRotation(dir string, now time.Time) (string, error) {
	if err := requireState(dir, RotationPrepared); err != nil {
		return "", err
	}
	backup, err := backupFiles(dir, "abort", now)
	if err != nil {
		return "", err
	}
	for _, f := range []string{nextKeyFile, nextCertFile, nextCrossFile} {
		if err := os.Remove(p(dir, f)); err != nil {
			return "", err
		}
	}
	return backup, nil
}

// PromoteRotation makes the next CA the one that issues, and keeps the old CA as the previous CA so every
// certificate it issued is still accepted. The new CA takes effect when the server next loads its CA.
func PromoteRotation(dir string, now time.Time) (string, error) {
	if err := requireState(dir, RotationPrepared); err != nil {
		return "", err
	}
	if _, err := loadCA(p(dir, nextKeyFile), p(dir, nextCertFile)); err != nil {
		return "", fmt.Errorf("the next CA is not usable: %w", err)
	}
	backup, err := backupFiles(dir, "promote", now)
	if err != nil {
		return "", err
	}
	steps := [][2]string{
		{"ca-key.pem", previousKeyFile}, {"ca-cert.pem", previousCertFile},
		{nextKeyFile, "ca-key.pem"}, {nextCertFile, "ca-cert.pem"},
	}
	for _, s := range steps {
		if err := os.Rename(p(dir, s[0]), p(dir, s[1])); err != nil {
			return backup, fmt.Errorf("promote: %w (restore from %s)", err, backup)
		}
	}
	return backup, nil
}

// RollbackRotation undoes a promotion: the old CA issues again, the new one returns to "prepared".
func RollbackRotation(dir string, now time.Time) (string, error) {
	if err := requireState(dir, RotationPromoted); err != nil {
		return "", err
	}
	backup, err := backupFiles(dir, "rollback", now)
	if err != nil {
		return "", err
	}
	steps := [][2]string{
		{"ca-key.pem", nextKeyFile}, {"ca-cert.pem", nextCertFile},
		{previousKeyFile, "ca-key.pem"}, {previousCertFile, "ca-cert.pem"},
	}
	for _, s := range steps {
		if err := os.Rename(p(dir, s[0]), p(dir, s[1])); err != nil {
			return backup, fmt.Errorf("rollback: %w (restore from %s)", err, backup)
		}
	}
	return backup, nil
}

// RetireRotation ends the overlap: the previous CA is no longer trusted. The backup it returns still
// holds the old CA, so even this step can be undone by hand. Run it only after every agent has been
// verified on the new CA.
func RetireRotation(dir string, now time.Time) (string, error) {
	if err := requireState(dir, RotationPromoted); err != nil {
		return "", err
	}
	backup, err := backupFiles(dir, "retire", now)
	if err != nil {
		return "", err
	}
	for _, f := range []string{previousKeyFile, previousCertFile, nextCrossFile} {
		if err := os.Remove(p(dir, f)); err != nil {
			return backup, err
		}
	}
	return backup, nil
}

// TrustedClientRoots are the CAs whose agent certificates the server accepts: the current CA, plus the
// previous CA while a promoted rotation is in its overlap.
func TrustedClientRoots(dir string) ([]*x509.Certificate, error) {
	state, err := RotationStatus(dir)
	if err != nil {
		return nil, err
	}
	names := []string{"ca-cert.pem"}
	if state == RotationPromoted {
		names = append(names, previousCertFile)
	}
	var roots []*x509.Certificate
	for _, n := range names {
		b, err := os.ReadFile(p(dir, n))
		if err != nil {
			return nil, err
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s: no PEM block", n)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		roots = append(roots, c)
	}
	return roots, nil
}
