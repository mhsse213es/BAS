[ -n "$(cv_aws_token)" ] || cv_done skip "AWS IMDS is unreachable from this host, so this is not an EC2 instance" CV-LB18
cv_have_aws || cv_done skip "AWS CLI is not installed on this host" CV-LB18
cv_set_region
cv_aws ec2 describe-security-groups --max-items 5
echo "EXEC T1580: security group inventory (first page); exit=$CV_ARC"
cv_classify_aws 'security group and network inventory discovery' BAS_CLOUD_EXPECT_ENUMERATION CV-LB18
