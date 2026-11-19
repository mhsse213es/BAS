cv_az_init CV-LA12
vault=$(cv_env BAS_CLOUD_TEST_KEYVAULT)
[ -n "$vault" ] || cv_done skip "no test Key Vault configured (BAS_CLOUD_TEST_KEYVAULT); use a dedicated test vault with synthetic secrets only" CV-LA12
cv_az_token "$CV_RES_VAULT"
[ -n "$CV_TOKEN" ] || cv_done skip "no managed-identity token for Key Vault (no identity attached to this VM)" CV-LA12
cv_http GET "https://$vault.vault.azure.net/secrets?api-version=7.4" "$CV_TOKEN"
echo "EXEC T1555: Key Vault secret names listed with the managed identity; http=$CV_HCODE names=$(cv_count '.value | length'). Secret values were never requested."
cv_classify_http "$CV_HCODE" 'Key Vault access with the managed identity' BAS_CLOUD_EXPECT_ENUMERATION CV-LA12
