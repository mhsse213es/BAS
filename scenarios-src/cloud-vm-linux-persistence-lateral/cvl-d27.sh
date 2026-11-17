cv_gate BAS_CONFIRM_CLOUD_ROLE_ASSUME || cv_done skip "lab gate BAS_CONFIRM_CLOUD_ROLE_ASSUME is not set to true; this step asks the cloud to issue temporary credentials for a test role" CV-LD27
arn=$(cv_env BAS_CLOUD_TEST_ROLE_ARN)
[ -n "$arn" ] || cv_done skip "no test role configured (BAS_CLOUD_TEST_ROLE_ARN)" CV-LD27
cv_have_aws || cv_done skip "AWS CLI is not installed on this host" CV-LD27
cv_set_region
cv_aws sts assume-role --role-arn "$arn" --role-session-name "$CV_TAG" --duration-seconds 900
echo "EXEC T1098: assume-role attempted for the test role only. Any returned credentials were discarded unrecorded."
cv_classify_aws 'role assumption of the test role' BAS_CLOUD_EXPECT_ROLE_ASSUME CV-LD27
