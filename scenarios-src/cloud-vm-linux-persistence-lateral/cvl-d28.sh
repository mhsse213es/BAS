cv_gate BAS_CONFIRM_CLOUD_IAM_WRITE || cv_done skip "lab gate BAS_CONFIRM_CLOUD_IAM_WRITE is not set to true; this step creates and then deletes an access key on a test user" CV-LD28
user=$(cv_env BAS_CLOUD_TEST_USER)
[ -n "$user" ] || cv_done skip "no test IAM user configured (BAS_CLOUD_TEST_USER)" CV-LD28
cv_have_aws || cv_done skip "AWS CLI is not installed on this host" CV-LD28
cv_set_region
cv_aws iam create-access-key --user-name "$user"
[ "$CV_ARC" -eq 0 ] || cv_classify_aws 'access key creation for the test user' BAS_CLOUD_EXPECT_KEY_CREATE CV-LD28
keyid=$(printf '%s' "$CV_AOUT" | grep -o '"AccessKeyId": *"[^"]*"' | head -n1 | cut -d'"' -f4)
CV_AOUT=""
[ -n "$keyid" ] || cv_done fail "an access key was created for the test user but its id could not be parsed, so cleanup was NOT attempted; list and delete the test user keys manually" CV-LD28
cv_aws iam delete-access-key --user-name "$user" --access-key-id "$keyid"; delrc=$CV_ARC
cv_aws iam list-access-keys --user-name "$user"; still=0
printf '%s' "$CV_AOUT" | grep -q "$keyid" && still=1
CV_AOUT=""
echo "EXEC T1098.001: access key created for the test user and deleted; delete_exit=$delrc still_listed=$still. The secret was never recorded."
if [ "$delrc" -ne 0 ] || [ "$still" -eq 1 ]; then cv_done fail "an access key was created for the test user, and cleanup was NOT verified; delete the key with id $keyid manually" CV-LD28; fi
cv_gate BAS_CLOUD_EXPECT_KEY_CREATE && cv_done skip "access key creation succeeded and is documented as expected; cleanup verified" CV-LD28
cv_done fail "the workload identity could create an access key for the test user; cleanup verified" CV-LD28
