f="$HOME/.aws/credentials"
[ -f "$f" ] || cv_done pass "no shared AWS credentials file exists under this user's home directory" CV-LC22
profiles=$(grep -c '^[[:space:]]*\[' "$f")
echo "EXEC T1552.001: shared credentials file present; profile sections=$profiles. Key values were not recorded."
grep -Eq '^[[:space:]]*aws_secret_access_key[[:space:]]*=' "$f" && cv_done fail "a shared AWS credentials file holds a plaintext aws_secret_access_key ($profiles profile section(s)); values were not recorded" CV-LC22
cv_done pass "a shared AWS credentials file exists but holds no plaintext secret access key on this host" CV-LC22
