[ -n "$(cv_aws_token)" ] || cv_done skip "AWS IMDS is unreachable from this host, so this is not an EC2 instance" CV-LB20
cv_have_aws || cv_done skip "AWS CLI is not installed on this host" CV-LB20
cv_set_region
cv_aws secretsmanager list-secrets --max-results 5
echo "EXEC T1555: secret names listed (first page only; get-secret-value was never called); exit=$CV_ARC"
cv_classify_aws 'Secrets Manager access' BAS_CLOUD_EXPECT_ENUMERATION CV-LB20
