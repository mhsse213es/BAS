cv_az_init CV-LA9
cv_az_token "$CV_RES_MGMT"
[ -n "$CV_TOKEN" ] || cv_done skip "no managed-identity token for the Azure management plane (no identity attached to this VM)" CV-LA9
cv_http GET "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&\$filter=atScope()" "$CV_TOKEN"
echo "EXEC T1069.003: role assignments visible at subscription scope; http=$CV_HCODE count=$(cv_count '.value | length')"
cv_classify_http "$CV_HCODE" 'role assignment discovery' BAS_CLOUD_EXPECT_ENUMERATION CV-LA9
