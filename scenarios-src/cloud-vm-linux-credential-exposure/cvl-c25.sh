hits=$(find "$HOME" -maxdepth 6 -type f \( -name 'terraform.tfstate' -o -name '*.tfstate' -o -name '*.tfstate.backup' \) 2>/dev/null | head -n 20)
n=$(printf '%s\n' "$hits" | grep -c .)
[ "$n" -eq 0 ] && cv_done pass "no Terraform state files were found under the home directory" CV-LC25
secret=0
while IFS= read -r h; do [ -n "$h" ] || continue; c=$(grep -Eoc '"(password|secret|access_key|private_key|client_secret)"' "$h"); secret=$((secret+c)); done <<EOF
$hits
EOF
echo "EXEC T1552.001: Terraform state files found=$n; secret-like attribute names=$secret. Values were not recorded."
[ "$secret" -gt 0 ] && cv_done fail "Terraform state on this host holds $secret secret-like attribute(s) in plaintext" CV-LC25
cv_done pass "Terraform state files were found but none holds secret-like attributes in plaintext" CV-LC25
