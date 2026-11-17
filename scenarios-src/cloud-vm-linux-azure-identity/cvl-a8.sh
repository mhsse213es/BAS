cv_az_init CV-LA8
cv_az_token "$CV_RES_MGMT"
[ -n "$CV_TOKEN" ] || cv_done skip "no managed-identity token for the Azure management plane (no identity attached to this VM)" CV-LA8
cv_http GET 'https://management.azure.com/subscriptions?api-version=2020-01-01' "$CV_TOKEN"
echo "EXEC T1580: subscription enumeration via the management plane; http=$CV_HCODE visible_subscriptions=$(cv_count '.value | length')"
cv_classify_http "$CV_HCODE" 'subscription and resource enumeration' BAS_CLOUD_EXPECT_ENUMERATION CV-LA8
