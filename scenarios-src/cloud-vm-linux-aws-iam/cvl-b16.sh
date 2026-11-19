[ -n "$(cv_aws_token)" ] || cv_done skip "AWS IMDS is unreachable from this host, so this is not an EC2 instance" CV-LB16
cv_have_aws || cv_done skip "AWS CLI is not installed on this host" CV-LB16
cv_set_region
role=$(cv_aws_meta 'iam/security-credentials/' | head -n1 | tr -d '\r' | sed 's/[[:space:]]*$//')
[ -n "$role" ] || cv_done pass "no instance role is attached, so there are no role policies to enumerate" CV-LB16
cv_aws iam list-attached-role-policies --role-name "$role"
echo "EXEC T1069.003: attached role policies query; exit=$CV_ARC"
cv_classify_aws 'attached role policy enumeration' BAS_CLOUD_EXPECT_ENUMERATION CV-LB16
