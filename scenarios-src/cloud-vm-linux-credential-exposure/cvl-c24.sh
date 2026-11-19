present=""
for n in AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AZURE_CLIENT_SECRET; do [ -n "$(cv_env $n)" ] && present="$present $n"; done
g=$(cv_env GOOGLE_APPLICATION_CREDENTIALS); [ -n "$g" ] && [ -f "$g" ] && present="$present GOOGLE_APPLICATION_CREDENTIALS(file-exists)"
[ -n "$present" ] && cv_done fail "secret-bearing cloud environment variables are set in this process environment (names only):${present}" CV-LC24
cv_done pass "no secret-bearing cloud environment variables are set in the process environment checked" CV-LC24
