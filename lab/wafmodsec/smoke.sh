#!/usr/bin/env bash
# Quick manual check that the lab actually behaves the way the
# docker-compose.yml doc comment and the Go live test expect: malicious
# requests blocked, benign requests allowed through to origin. Run after
# `docker compose up -d` from this directory. Exits non-zero on the first
# mismatch.
set -euo pipefail

base="${1:-http://localhost:8888}"

check() {
	local desc="$1" want="$2" method="$3" url="$4"
	got=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" "$url")
	if [ "$got" != "$want" ]; then
		echo "FAIL: $desc -- got status $got, want $want ($method $url)" >&2
		exit 1
	fi
	echo "ok:   $desc ($got)"
}

check "SQLI-001 malicious (blocked)"    403 GET "$base/search?q=%27%20UNION%20SELECT%20NULL%2CNULL%2CNULL--"
check "SQLI-001 benign (allowed)"       200 GET "$base/search?q=laptop%20stand"
check "XSS-001 malicious (blocked)"     403 GET "$base/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E"
check "XSS-001 benign (allowed)"        200 GET "$base/search?q=running%20shoes"
check "PATHTRAV-001 malicious (blocked)" 403 GET "$base/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
check "PATHTRAV-001 benign (allowed)"   200 GET "$base/download?file=invoice-2026-09.pdf"
check "HTTPPARSE-002 malicious (blocked)" 405 TRACE "$base/admin/settings"
check "HTTPPARSE-002 benign (allowed)"  200 GET "$base/admin/settings"

echo "All checks passed."
