tok=$(cv_aws_token)
[ -n "$tok" ] || cv_done skip "AWS IMDS is unreachable from this host, so this is not an EC2 instance" CV-LB14
code=$(curl -s -m 3 -o /dev/null -w '%{http_code}' -H "X-aws-ec2-metadata-token: $tok" 'http://169.254.169.254/latest/meta-data/iam/info')
[ "$code" = 404 ] && cv_done pass "no instance profile is attached to this EC2 instance (least-privilege posture)" CV-LB14
[ "$code" = 200 ] || cv_done error "the instance profile could not be read (HTTP $code)" CV-LB14
echo "EXEC T1552.005: an instance profile is attached. The ARN and credentials were not retrieved or recorded."
cv_gate BAS_CLOUD_EXPECT_INSTANCE_ROLE && cv_done skip "an instance role is attached and the operator documents it as expected, so no control verdict is scored" CV-LB14
cv_done fail "an instance role is attached and its profile is readable from local IMDS by any local process" CV-LB14
