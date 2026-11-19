if cv_az_present; then
  cv_az_init CV-LE34
  cv_az_token "$CV_RES_MGMT"
  [ -n "$CV_TOKEN" ] || cv_done skip "no managed-identity token for the Azure management plane (no identity attached to this VM)" CV-LE34
  cv_http GET "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Sql/servers?api-version=2021-11-01" "$CV_TOKEN"
  echo "EXEC T1526: database server inventory (Azure SQL); http=$CV_HCODE servers=$(cv_count '.value | length')"
  cv_classify_http "$CV_HCODE" 'cloud database discovery' BAS_CLOUD_EXPECT_ENUMERATION CV-LE34
fi
if [ -n "$(cv_aws_token)" ] && cv_have_aws; then
  cv_set_region
  cv_aws rds describe-db-instances --max-items 5
  echo "EXEC T1526: database instance inventory (first page, RDS); exit=$CV_ARC"
  cv_classify_aws 'cloud database discovery' BAS_CLOUD_EXPECT_ENUMERATION CV-LE34
fi
cv_done skip "neither Azure IMDS nor the AWS instance metadata service with a CLI is available on this host" CV-LE34
