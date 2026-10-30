package api

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// aleefSecretsFileEnv names the env var holding the path of the secrets file that install.sh
// writes (${DATA_DIR}/aleef-secrets.env, mounted read-only into the container).
const aleefSecretsFileEnv = "ALEEF_SECRETS_FILE"

var aleefSecretKeyRe = regexp.MustCompile(`^ALEEF_SECRET_[A-Z0-9_]+$`)

// parseAleefSecretsFile reads KEY=VALUE lines. Blank lines and lines starting with # are
// ignored. The value is everything after the first "=", taken literally (no quoting, no
// trimming of inner characters). A malformed line fails the whole file with an error that names
// the line number only, never the content. A missing file is not an error: it yields no secrets.
func parseAleefSecretsFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("aleef secrets file is not readable")
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || !aleefSecretKeyRe.MatchString(k) || v == "" || strings.ContainsAny(v, "\"'\\x00") {
			return nil, fmt.Errorf("aleef secrets file: malformed line %d", n)
		}
		out[k] = v
	}
	if sc.Err() != nil {
		return nil, fmt.Errorf("aleef secrets file is not readable")
	}
	return out, nil
}
