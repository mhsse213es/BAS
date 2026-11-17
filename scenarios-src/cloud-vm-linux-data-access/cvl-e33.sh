bucket=$(cv_env BAS_CLOUD_TEST_BUCKET); key=$(cv_env BAS_CLOUD_TEST_OBJECT_KEY)
[ -n "$bucket" ] && [ -n "$key" ] || cv_done skip "no test bucket or synthetic object key configured (BAS_CLOUD_TEST_BUCKET, BAS_CLOUD_TEST_OBJECT_KEY)" CV-LE33
[ -n "$(cv_aws_token)" ] || cv_done skip "AWS IMDS is unreachable from this host, so this is not an EC2 instance" CV-LE33
cv_have_aws || cv_done skip "AWS CLI is not installed on this host" CV-LE33
cv_set_region
cv_aws s3api head-object --bucket "$bucket" --key "$key"
echo "EXEC T1530: metadata-only head-object on the synthetic test object; exit=$CV_ARC. The object body was never requested."
cv_classify_aws 'S3 object access' BAS_CLOUD_EXPECT_ENUMERATION CV-LE33
