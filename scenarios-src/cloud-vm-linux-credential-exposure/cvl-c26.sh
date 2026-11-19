files=(); for p in "$HOME/.aws/config" "$HOME/.azure/config" "$HOME/.config/gcloud/configurations/config_default"; do [ -f "$p" ] && files+=("$p"); done
[ "${#files[@]}" -gt 0 ] || cv_done pass "no cloud SDK configuration files were found under the home directory" CV-LC26
hits=0; for f in "${files[@]}"; do c=$(grep -Eic '^[[:space:]]*(client_secret|secret_key|password|aws_secret_access_key)[[:space:]]*=' "$f"); hits=$((hits+c)); done
echo "EXEC T1552.001: cloud SDK configuration files present=${#files[@]}; secret-like keys=$hits. Values were not recorded."
[ "$hits" -gt 0 ] && cv_done fail "cloud SDK configuration holds $hits secret-like key(s) in plaintext" CV-LC26
cv_done pass "cloud SDK configuration files exist but hold no secret-like keys in plaintext" CV-LC26
