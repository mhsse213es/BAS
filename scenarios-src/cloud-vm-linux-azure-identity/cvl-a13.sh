cv_az_init CV-LA13
other=$(cv_env BAS_CLOUD_TEST_RG)
[ -n "$other" ] || cv_done skip "no test resource group configured (BAS_CLOUD_TEST_RG); the token-use check needs a resource group other than this VM's own" CV-LA13
if [ "${other,,}" = "${RG,,}" ]; then cv_done skip "BAS_CLOUD_TEST_RG is this VM's own resource group, so the check would not cross a boundary" CV-LA13; fi
cv_az_token "$CV_RES_MGMT"
[ -n "$CV_TOKEN" ] || cv_done skip "no managed-identity token for the Azure management plane (no identity attached to this VM)" CV-LA13
cv_http GET "https://management.azure.com/subscriptions/$SUB/resourceGroups/$other/resources?api-version=2021-04-01" "$CV_TOKEN"
echo "EXEC T1528: a token acquired in this step was used once for a read of a resource group outside this VM's own scope; http=$CV_HCODE. Read-only; the token was not stored."
cv_classify_http "$CV_HCODE" 'token use outside the VM resource group' BAS_CLOUD_EXPECT_ENUMERATION CV-LA13
