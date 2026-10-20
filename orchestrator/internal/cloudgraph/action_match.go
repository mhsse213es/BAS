package cloudgraph

import "strings"

// globMatch reports whether value matches pattern, where '*' matches any run
// of characters (including none) and every other character matches itself.
// Matching is case-insensitive, as IAM action names are. It is used for IAM
// action patterns such as "s3:*" or "s3:Get*". An empty pattern matches only
// an empty value.
func globMatch(pattern, value string) bool {
	p := strings.ToLower(pattern)
	v := strings.ToLower(value)
	// Classic two-pointer glob match: on mismatch, backtrack to the last '*'.
	pi, vi := 0, 0
	starP, starV := -1, 0
	for vi < len(v) {
		switch {
		case pi < len(p) && p[pi] == '*':
			starP = pi
			starV = vi
			pi++
		case pi < len(p) && p[pi] == v[vi]:
			pi++
			vi++
		case starP >= 0:
			pi = starP + 1
			starV++
			vi = starV
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
