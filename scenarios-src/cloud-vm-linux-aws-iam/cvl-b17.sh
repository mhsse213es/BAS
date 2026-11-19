[ -n "$(cv_aws_token)" ] || cv_done skip "AWS IMDS is unreachable from this host, so this is not an EC2 instance" CV-LB17
cv_have_aws || cv_done skip "AWS CLI is not installed on this host" CV-LB17
cv_set_region
cv_aws s3api list-buckets
echo "EXEC T1619: bucket names listed (names only); exit=$CV_ARC"
cv_classify_aws 'S3 bucket discovery' BAS_CLOUD_EXPECT_ENUMERATION CV-LB17
