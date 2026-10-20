//go:build !windows

package calibration

import (
	"bufio"
	"os"
	"strings"
)

// osAttributes reads the platform attributes from procfs and os-release. An attribute the
// file does not provide is left out, and CollectFingerprint records it as unavailable.
func osAttributes() map[string]sourcedValue {
	out := map[string]sourcedValue{}
	if v, ok := scanKey("/proc/cpuinfo", "model name"); ok {
		out["cpu_model"] = sourcedValue{v, "/proc/cpuinfo:model name"}
	}
	if v, ok := scanKey("/proc/meminfo", "MemTotal"); ok {
		out["memory_total_bytes"] = sourcedValue{v, "/proc/meminfo:MemTotal"}
	}
	if v, ok := scanKey("/etc/os-release", "PRETTY_NAME"); ok {
		out["os_version"] = sourcedValue{strings.Trim(v, `"`), "/etc/os-release:PRETTY_NAME"}
	}
	return out
}

// scanKey returns the value of the first "key: value" or "KEY=value" line in a file.
func scanKey(path, key string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		for _, sep := range []string{":", "="} {
			if k, v, ok := strings.Cut(line, sep); ok && strings.TrimSpace(k) == key {
				return strings.TrimSpace(v), true
			}
		}
	}
	return "", false
}
