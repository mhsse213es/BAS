cv_az_init CV-LA10
cv_az_token "$CV_RES_MGMT"
[ -n "$CV_TOKEN" ] || cv_done skip "no managed-identity token for the Azure management plane (no identity attached to this VM)" CV-LA10
cv_http GET "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/$VMN/extensions?api-version=2023-03-01" "$CV_TOKEN"
echo "EXEC T1526: VM extension inventory for this VM only; http=$CV_HCODE extensions=$(cv_count '.value | length')"
cv_classify_http "$CV_HCODE" 'VM extension inventory discovery' BAS_CLOUD_EXPECT_ENUMERATION CV-LA10
