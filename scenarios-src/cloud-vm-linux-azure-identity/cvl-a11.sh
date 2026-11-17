cv_az_init CV-LA11
cv_az_token "$CV_RES_MGMT"
[ -n "$CV_TOKEN" ] || cv_done skip "no managed-identity token for the Azure management plane (no identity attached to this VM)" CV-LA11
cv_http GET "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01" "$CV_TOKEN"
echo "EXEC T1580: storage account inventory at subscription scope; http=$CV_HCODE accounts=$(cv_count '.value | length')"
cv_classify_http "$CV_HCODE" 'storage account discovery' BAS_CLOUD_EXPECT_ENUMERATION CV-LA11
