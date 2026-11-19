cv_az_present || cv_done skip "Azure IMDS is unreachable from this host, so this is not an Azure VM" CV-LA7
expected=$(printf '%s' "${BAS_CLOUD_EXPECTED_RESOURCES:-}" | tr ',' '\n' | sed 's:/*$::; s/^ *//; s/ *$//' | grep -v '^$')
issued=0; refused=0; unexpected=""
for pair in "https://management.azure.com|$CV_RES_MGMT" "https://vault.azure.net|$CV_RES_VAULT" "https://storage.azure.com|$CV_RES_STORAGE" "https://graph.microsoft.com|$CV_RES_GRAPH"; do
  name=${pair%%|*}; enc=${pair#*|}
  cv_az_token "$enc"
  if [ -n "$CV_TOKEN" ]; then
    issued=$((issued+1))
    printf '%s\n' "$expected" | grep -qxF "$name" || unexpected="$unexpected $name"
  elif [ "$CV_TCODE" = 400 ] || [ "$CV_TCODE" = 401 ] || [ "$CV_TCODE" = 403 ] || [ "$CV_TCODE" = 404 ]; then
    refused=$((refused+1))
  fi
  CV_TOKEN=""
done
echo "EXEC T1552.005: managed-identity tokens requested for 4 resources; issued=$issued refused=$refused. Token values were not recorded."
if [ -n "$unexpected" ]; then cv_done fail "identity tokens were issued for resources outside the operator-expected list:${unexpected}" CV-LA7; fi
if [ "$issued" -gt 0 ]; then cv_done skip "tokens were issued only for resources the operator documents as expected, so no control verdict is scored" CV-LA7; fi
if [ "$refused" -gt 0 ]; then cv_done pass "no managed-identity token was issued for any tested resource; the token endpoint refused the request (no identity attached, or issuance refused)" CV-LA7; fi
cv_done error "no token request returned a classifiable answer" CV-LA7
