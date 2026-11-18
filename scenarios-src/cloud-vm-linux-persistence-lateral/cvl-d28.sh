cv_gate BAS_CONFIRM_CLOUD_IAM_WRITE || cv_done skip "lab gate BAS_CONFIRM_CLOUD_IAM_WRITE is not set to true; this step creates and then deletes an access key on a test user" CV-LD28
user=$(cv_env BAS_CLOUD_TEST_USER)
[ -n "$user" ] || cv_done skip "no test IAM user configured (BAS_CLOUD_TEST_USER)" CV-LD28
cv_have_aws || cv_done skip "AWS CLI is not installed on this host" CV-LD28
cv_set_region
# Baseline: list keys before the test
cv_aws iam list-access-keys --user-name "$user"
if [ "$CV_ARC" -ne 0 ]; then cv_done error "failed to list baseline access keys for $user; undo baseline cannot be recorded" CV-LD28; fi
baseline=$(printf '%s' "$CV_AOUT" | grep -o '"AccessKeyId": *"[^"]*"' | cut -d'"' -f4 | tr '\n' ',' | sed 's/,$//')
CV_AOUT=""
# Record undo baseline (exclusive: fail if already exists)
undo_data=$(printf '{"user":"%s","baseline":"%s"}' "$user" "$baseline")
cv_undo_new CV-LD28 "$undo_data" || cv_done error "undo record for CV-LD28 already exists; a previous run was not cleaned up" CV-LD28
# Create access key
cv_aws iam create-access-key --user-name "$user"
[ "$CV_ARC" -eq 0 ] || cv_classify_aws 'access key creation for the test user' BAS_CLOUD_EXPECT_KEY_CREATE CV-LD28
keyid=$(printf '%s' "$CV_AOUT" | grep -o '"AccessKeyId": *"[^"]*"' | head -n1 | cut -d'"' -f4)
CV_AOUT=""
[ -n "$keyid" ] || cv_done fail "an access key was created for the test user but its id could not be parsed, so cleanup was NOT verified" CV-LD28
# Delete access key
cv_aws iam delete-access-key --user-name "$user" --access-key-id "$keyid"; delrc=$CV_ARC
# Verify: list again and check for any keys outside baseline
cv_aws iam list-access-keys --user-name "$user"; lrc=$CV_ARC
extra=0
if [ "$lrc" -eq 0 ]; then
  current=$(printf '%s' "$CV_AOUT" | grep -o '"AccessKeyId": *"[^"]*"' | cut -d'"' -f4)
  for id in $current; do printf '%s' "$baseline" | grep -q "$id" || extra=$((extra+1)); done
fi
CV_AOUT=""
echo "EXEC T1098.001: access key created for the test user and deleted; delete_exit=$delrc list_exit=$lrc extra_keys=$extra. The secret was never recorded."
if [ "$delrc" -ne 0 ] || [ "$lrc" -ne 0 ] || [ "$extra" -gt 0 ]; then
  cv_done fail "access key creation/deletion/verification failed; undo record is left for cleanup phase" CV-LD28
fi
# Do not remove undo record here; cleanup undo script will do it.
cv_gate BAS_CLOUD_EXPECT_KEY_CREATE && cv_done skip "access key creation succeeded and is documented as expected; cleanup verified" CV-LD28
cv_done fail "the workload identity could create an access key for the test user; cleanup verified" CV-LD28
