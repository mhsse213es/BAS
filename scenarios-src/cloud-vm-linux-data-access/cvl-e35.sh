cv_gate BAS_CONFIRM_CLOUD_SECRET_READ || cv_done skip "lab gate BAS_CONFIRM_CLOUD_SECRET_READ is not set to true; this step requests a secret value, which only a deliberate test run may do" CV-LE35
secret=$(cv_env BAS_CLOUD_TEST_SECRET_NAME)
[ -n "$secret" ] || cv_done skip "no synthetic test secret configured (BAS_CLOUD_TEST_SECRET_NAME); use a test secret holding synthetic data only" CV-LE35
vault=$(cv_env BAS_CLOUD_TEST_KEYVAULT)
if [ -n "$vault" ] && cv_az_present; then
  cv_az_token "$CV_RES_VAULT"
  [ -n "$CV_TOKEN" ] || cv_done skip "no managed-identity token for Key Vault (no identity attached to this VM)" CV-LE35
  cv_http GET "https://$vault.vault.azure.net/secrets/$secret?api-version=7.4" "$CV_TOKEN"
  len=0
  if [ "$CV_HCODE" = 200 ]; then v=$(printf '%s' "$CV_HBODY" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -n1); len=${#v}; v=""; fi
  CV_HBODY=""
  echo "EXEC T1555: Key Vault secret value requested for the synthetic test secret; http=$CV_HCODE. Only the length ($len) was observed; the value was discarded."
  cv_classify_http "$CV_HCODE" 'Key Vault secret retrieval' BAS_CLOUD_EXPECT_ENUMERATION CV-LE35
fi
if [ -n "$(cv_aws_token)" ] && cv_have_aws; then
  cv_set_region
  cv_aws secretsmanager get-secret-value --secret-id "$secret"
  len=0
  if [ "$CV_ARC" -eq 0 ]; then v=$(printf '%s' "$CV_AOUT" | sed -n 's/.*"SecretString": *"\([^"]*\)".*/\1/p' | head -n1); len=${#v}; v=""; fi
  echo "EXEC T1555: Secrets Manager value requested for the synthetic test secret; value_length=$len. The value was discarded."
  cv_classify_aws 'Secrets Manager secret retrieval' BAS_CLOUD_EXPECT_ENUMERATION CV-LE35
fi
cv_done skip "no cloud identity path is available to retrieve the synthetic test secret on this host" CV-LE35
