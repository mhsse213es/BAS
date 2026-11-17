[ -n "$(cv_aws_token)" ] || cv_done skip "AWS IMDS is unreachable from this host, so this is not an EC2 instance" CV-LB19
cv_have_aws || cv_done skip "AWS CLI is not installed on this host" CV-LB19
cv_set_region
cv_aws kms list-keys --limit 5
echo "EXEC T1580: KMS key identifiers listed (first page); exit=$CV_ARC"
cv_classify_aws 'KMS key inventory discovery' BAS_CLOUD_EXPECT_ENUMERATION CV-LB19
