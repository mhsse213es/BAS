package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Shared POSIX posture evaluators.
//
// Section B of the POSIX posture coverage map: checks that are net-new on both
// Linux and macOS. Unlike simulate_mac_posture.go, which is macOS-specific,
// the logic here is genuinely identical on both platforms -- a private key
// readable by the group is the same finding whichever kernel is underneath --
// so one evaluator serves both and the two cannot drift apart.
//
// No build tag: the reads that feed these live in the platform files, and
// every threshold is verified from the Windows build host.
//
// The verdict rules from simulate_mac_posture.go apply unchanged. In
// particular, finding nothing to assess is "skipped", not "pass": a pass
// asserts the endpoint was examined and found sound, which is a different
// claim from having had nothing to examine.

// ---------------------------------------------------------------------------
// T1552.001 -- credentials in files
// ---------------------------------------------------------------------------

// credTarget is one credential store to stat, and what to call it in a finding.
type credTarget struct {
	path string
	kind string
	// dirOfKeys marks a directory whose private-key files are enumerated
	// rather than a single file.
	dirOfKeys bool
}

// credentialFileTargets returns the credential stores to inspect under one home
// directory. These are the files whose exposure hands an attacker working
// credentials directly -- no cracking, no lateral step, just read and use.
func credentialFileTargets(home string) []credTarget {
	j := func(rel string) string { return strings.TrimRight(home, "/") + "/" + rel }
	return []credTarget{
		{path: j(".ssh"), kind: "SSH private key", dirOfKeys: true},
		{path: j(".aws/credentials"), kind: "AWS credentials"},
		{path: j(".config/gcloud/credentials.db"), kind: "Google Cloud credentials"},
		{path: j(".azure/accessTokens.json"), kind: "Azure access tokens"},
		{path: j(".netrc"), kind: "netrc credentials"},
		{path: j(".pgpass"), kind: "database credentials"},
		{path: j(".my.cnf"), kind: "database credentials"},
		{path: j(".kube/config"), kind: "Kubernetes credentials"},
		{path: j(".docker/config.json"), kind: "registry credentials"},
		{path: j(".git-credentials"), kind: "Git credentials"},
		{path: j(".npmrc"), kind: "package registry token"},
	}
}

// credFinding is one credential store that was found and stat'd.
type credFinding struct {
	Path string
	Mode fs.FileMode
	Kind string
}

// sshPrivateKeyPrefixes are the conventional private-key filenames ssh-keygen
// produces. Matching on prefix rather than an exact list keeps custom names
// like id_ed25519_prod in scope.
var sshPrivateKeyPrefixes = []string{"id_", "identity"}

// sshNonKeyNames are files that live alongside keys and are not secrets.
var sshNonKeyNames = map[string]bool{
	"known_hosts": true, "known_hosts.old": true, "config": true,
	"authorized_keys": true, "environment": true, "rc": true,
}

// isSSHPrivateKeyName reports whether a filename in ~/.ssh is a private key.
//
// The .pub exclusion is load-bearing: a public key is meant to be
// world-readable, and flagging one would put a false finding on every endpoint
// that has ever generated a key pair, burying the real ones.
func isSSHPrivateKeyName(name string) bool {
	if strings.HasSuffix(name, ".pub") || sshNonKeyNames[name] {
		return false
	}
	for _, p := range sshPrivateKeyPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// credExposedMask is group or other access of any kind. OpenSSH itself refuses
// to use a key readable beyond its owner, which is the same bar applied here.
const credExposedMask = 0o077

// evalCredentialFiles reports credential stores readable beyond their owner.
// scanned is how many stores were actually found and stat'd.
func evalCredentialFiles(findings []credFinding, scanned int) (string, string) {
	if scanned == 0 {
		return "skipped", "No credential stores were found in the scanned home directories, " +
			"so credential file exposure was not assessed. This is not evidence that none exist."
	}
	var exposed []string
	for _, f := range findings {
		if f.Mode.Perm()&credExposedMask != 0 {
			exposed = append(exposed, fmt.Sprintf("%s (%s, %04o)", f.Path, f.Kind, f.Mode.Perm()))
		}
	}
	if len(exposed) == 0 {
		return "pass", fmt.Sprintf("All %d credential store(s) found are readable only by their owner.", scanned)
	}
	sort.Strings(exposed)
	shown := exposed
	if len(shown) > 6 {
		shown = shown[:6]
	}
	return "fail", fmt.Sprintf("%d of %d credential store(s) are readable beyond their owner: %s. "+
		"Any local account that can read these has working credentials without needing to crack anything.",
		len(exposed), scanned, strings.Join(shown, ", "))
}

// ---------------------------------------------------------------------------
// T1219 -- remote access software
// ---------------------------------------------------------------------------

// remoteAccessSig is one remote-access product, matched the same way the
// security-product inventory matches its catalogue.
type remoteAccessSig struct {
	label string
	procs []string
	paths []string
}

// remoteAccessCatalogue is the unsanctioned-remote-access set. These are
// legitimate tools; the finding is that one is present on an endpoint, which
// is both a standing inbound path and the most common hands-on-keyboard route
// in support-desk fraud.
var remoteAccessCatalogue = []remoteAccessSig{
	{"AnyDesk", []string{"anydesk", "AnyDesk"}, []string{"/Applications/AnyDesk.app", "/usr/bin/anydesk", "/opt/anydesk"}},
	{"TeamViewer", []string{"teamviewerd", "TeamViewer"}, []string{"/Applications/TeamViewer.app", "/opt/teamviewer"}},
	{"RustDesk", []string{"rustdesk"}, []string{"/Applications/RustDesk.app", "/usr/bin/rustdesk"}},
	{"ConnectWise ScreenConnect", []string{"ScreenConnect", "screenconnect"}, []string{"/opt/screenconnect", "/Applications/ScreenConnect.app"}},
	{"Splashtop", []string{"SRServer", "splashtop"}, []string{"/Applications/Splashtop Streamer.app", "/opt/splashtop"}},
	{"LogMeIn / GoTo", []string{"logmein", "LMIGuardianSvc"}, []string{"/opt/logmein", "/Applications/LogMeIn.app"}},
	{"Chrome Remote Desktop", []string{"chrome-remote-desktop", "remoting_host"}, []string{"/opt/google/chrome-remote-desktop"}},
	{"VNC server", []string{"vncserver", "x11vnc", "tigervncserver", "Xvnc"}, []string{"/usr/bin/x11vnc", "/usr/bin/vncserver"}},
	{"Ammyy Admin", []string{"ammyy", "AA_v3"}, nil},
	{"Supremo", []string{"supremo", "SupremoService"}, []string{"/Applications/Supremo.app"}},
	{"Atera / Splashtop RMM", []string{"AteraAgent", "atera"}, []string{"/opt/AteraAgent"}},
	{"NinjaRMM", []string{"ninjarmm-agent", "NinjaRMMAgent"}, []string{"/opt/NinjaRMMAgent", "/Applications/NinjaRMMAgent.app"}},
}

// matchRemoteAccess reports each product seen, preferring the stronger claim.
// exists is the caller's filesystem probe, so this stays testable off-host.
func matchRemoteAccess(running map[string]bool, exists func(string) bool) []string {
	var found []string
	for _, sig := range remoteAccessCatalogue {
		matched := false
		for _, p := range sig.procs {
			if running[p] {
				found = append(found, fmt.Sprintf("%s (%s running)", sig.label, p))
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		for _, p := range sig.paths {
			if exists(p) {
				found = append(found, fmt.Sprintf("%s (installed at %s)", sig.label, p))
				break
			}
		}
	}
	return found
}

// evalRemoteAccessSoftware turns the match list into a verdict.
func evalRemoteAccessSoftware(found []string) (string, string) {
	if len(found) == 0 {
		return "pass", "No third-party remote access or RMM software was found on this endpoint."
	}
	sort.Strings(found)
	return "fail", fmt.Sprintf("%d remote access tool(s) present: %s. "+
		"Each is a standing inbound path that bypasses the network perimeter, and each must be sanctioned or removed.",
		len(found), strings.Join(found, ", "))
}

// ---------------------------------------------------------------------------
// T1553.004 -- root certificate trust store
// ---------------------------------------------------------------------------

// evalTrustStore reports certificate authorities added beyond the vendor set.
// anchorsReadable distinguishes "looked and found none" from "could not look".
func evalTrustStore(customRoots []string, anchorsReadable bool) (string, string) {
	if !anchorsReadable {
		return "skipped", "The trust anchor location could not be read, so locally added " +
			"certificate authorities were not assessed."
	}
	if len(customRoots) == 0 {
		return "pass", "No certificate authorities have been added beyond the vendor trust store."
	}
	sort.Strings(customRoots)
	shown := customRoots
	if len(shown) > 5 {
		shown = shown[:5]
	}
	return "fail", fmt.Sprintf("%d locally added certificate authority/authorities: %s. "+
		"Whoever holds the matching private key can mint certificates this endpoint trusts, "+
		"which is how TLS interception is established. Each must be justified.",
		len(customRoots), strings.Join(shown, ", "))
}

// ---------------------------------------------------------------------------
// T1543.001 / .002 -- service persistence directories
// ---------------------------------------------------------------------------

// evalWritableDirs reports directories writable by someone other than their
// owner. label names the kind of directory and risk completes the sentence
// "a plist or unit dropped here <risk>".
func evalWritableDirs(label string, modes map[string]fs.FileMode, risk string) (string, string) {
	if len(modes) == 0 {
		return "skipped", fmt.Sprintf("No %s directories could be read; this persistence surface was not assessed.", label)
	}
	paths := make([]string, 0, len(modes))
	for p := range modes {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var bad []string
	for _, p := range paths {
		// 0o022 = group-write or other-write.
		if modes[p].Perm()&0o022 != 0 {
			bad = append(bad, fmt.Sprintf("%s (%04o)", p, modes[p].Perm()))
		}
	}
	if len(bad) > 0 {
		return "fail", fmt.Sprintf("Writable by non-root: %s. A user who can write here gains persistence that %s.",
			strings.Join(bad, ", "), risk)
	}
	return "pass", fmt.Sprintf("All %d %s directories are writable only by root.", len(paths), label)
}

// evalLaunchDirPerms is section A's launchd check, expressed through the shared
// evaluator so the two cannot drift.
func evalLaunchDirPerms(modes map[string]fs.FileMode) (string, string) {
	return evalWritableDirs("launchd", modes, "executes as root at every boot")
}

// ---------------------------------------------------------------------------
// Shared readers
// ---------------------------------------------------------------------------

// homeDirsUnder lists the home directories beneath a container such as /home or
// /Users, plus any extra roots the caller names (/root on Linux). Non-existent
// roots are skipped silently -- their absence is not a finding.
func homeDirsUnder(container string, extra ...string) []string {
	var out []string
	if entries, err := os.ReadDir(container); err == nil {
		for _, e := range entries {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				out = append(out, filepath.Join(container, e.Name()))
			}
		}
	}
	for _, p := range extra {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// scanCredentialStores stats every credential target under each home directory
// and reports what was found, plus how many stores existed at all.
//
// The count matters as much as the findings: zero stores means there was
// nothing to assess, which evalCredentialFiles reports as withheld rather than
// as a clean pass.
func scanCredentialStores(homes []string) ([]credFinding, int) {
	var findings []credFinding
	scanned := 0
	for _, home := range homes {
		for _, tg := range credentialFileTargets(home) {
			if tg.dirOfKeys {
				entries, err := os.ReadDir(tg.path)
				if err != nil {
					continue
				}
				for _, e := range entries {
					if e.IsDir() || !isSSHPrivateKeyName(e.Name()) {
						continue
					}
					info, err := e.Info()
					if err != nil {
						continue
					}
					scanned++
					findings = append(findings, credFinding{
						Path: filepath.Join(tg.path, e.Name()), Mode: info.Mode(), Kind: tg.kind,
					})
				}
				continue
			}
			info, err := os.Stat(tg.path)
			if err != nil || info.IsDir() {
				continue
			}
			scanned++
			findings = append(findings, credFinding{Path: tg.path, Mode: info.Mode(), Kind: tg.kind})
		}
	}
	return findings, scanned
}

// dirModes stats each path and returns the modes of those that exist, for
// evalWritableDirs.
func dirModes(paths []string) map[string]fs.FileMode {
	modes := map[string]fs.FileMode{}
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			modes[p] = st.Mode()
		}
	}
	return modes
}

// certFilesIn lists certificate files in a trust-anchor directory, and reports
// whether the directory was readable at all.
func certFilesIn(dirs []string) (roots []string, readable bool) {
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		readable = true
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || strings.HasPrefix(n, ".") {
				continue
			}
			if strings.HasSuffix(n, ".crt") || strings.HasSuffix(n, ".pem") || strings.HasSuffix(n, ".cer") {
				roots = append(roots, n)
			}
		}
	}
	return roots, readable
}
