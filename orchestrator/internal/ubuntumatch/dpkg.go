// Package ubuntumatch compares installed Ubuntu package versions against
// reviewed fixed-version mappings. It is read-only and is not wired into any
// API, scan, or build path.
package ubuntumatch

import (
	"strconv"
	"strings"
)

// DpkgCompare compares two Debian package versions using the algorithm in
// Debian Policy section 5.6.12. It returns -1, 0, or 1.
// A version with an invalid epoch is treated as epoch 0.
func DpkgCompare(a, b string) int {
	ea, ua, ra := splitVersion(a)
	eb, ub, rb := splitVersion(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	c := verrevcmp(ua, ub)
	if c == 0 {
		c = verrevcmp(ra, rb)
	}
	switch {
	case c < 0:
		return -1
	case c > 0:
		return 1
	}
	return 0
}

func splitVersion(v string) (epoch int64, upstream, revision string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if n, err := strconv.ParseInt(v[:i], 10, 64); err == nil && n >= 0 {
			epoch = n
			v = v[i+1:]
		}
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// order gives the sort weight of a character: '~' sorts before everything,
// including the end of the string; letters sort before other characters.
// Digits and the end of string both weigh 0 here, as in the Debian algorithm.
func order(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	case c != 0:
		return int(c) + 256
	default:
		return 0
	}
}

func charAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		first := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac := order(charAt(a, i))
			bc := order(charAt(b, j))
			if ac != bc {
				return ac - bc
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if first == 0 {
				first = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if first != 0 {
			return first
		}
	}
	return 0
}
