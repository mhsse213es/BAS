files=(); for n in accessTokens.json msal_token_cache.json; do [ -f "$HOME/.azure/$n" ] && files+=("$HOME/.azure/$n"); done
[ "${#files[@]}" -gt 0 ] || cv_done pass "no Azure CLI token cache exists under this user's home directory" CV-LC23
hits=0; for f in "${files[@]}"; do c=$(grep -Eoi '"(access_?token|refresh_?token)"' "$f" | wc -l); hits=$((hits+c)); done
echo "EXEC T1552.001: Azure CLI token cache files present=${#files[@]}; token-bearing entries=$hits. Token values were not recorded."
[ "$hits" -gt 0 ] && cv_done fail "the Azure CLI token cache holds $hits bearer or refresh token entr(y/ies) at rest on this workload VM" CV-LC23
cv_done pass "Azure CLI token cache files exist but contain no access or refresh token entries" CV-LC23
