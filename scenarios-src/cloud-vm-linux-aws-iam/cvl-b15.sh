[ -n "$(cv_aws_token)" ] || cv_done skip "AWS IMDS is unreachable from this host, so this is not an EC2 instance" CV-LB15
cv_have_aws || cv_done skip "AWS CLI is not installed on this host" CV-LB15
cv_set_region
cv_aws sts get-caller-identity
[ "$CV_ARC" -eq 0 ] || cv_classify_aws 'caller identity discovery' BAS_CLOUD_EXPECT_ENUMERATION CV-LB15
echo "EXEC T1087.004: caller identity resolved. The ARN was not recorded."
cv_done skip "GetCallerIdentity is permitted to every principal, so it documents identity for the report but scores no control" CV-LB15
