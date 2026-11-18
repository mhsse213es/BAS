cv_gate BAS_CONFIRM_CLOUD_IAM_WRITE || cv_done skip "lab gate BAS_CONFIRM_CLOUD_IAM_WRITE is not set to true; this step adds and then removes a client secret on a test application" CV-LD29
app=$(cv_env BAS_CLOUD_TEST_APP_OBJECT_ID)
[ -n "$app" ] || cv_done skip "no test application configured (BAS_CLOUD_TEST_APP_OBJECT_ID); use a dedicated test application" CV-LD29
cv_az_token "$CV_RES_GRAPH"
[ -n "$CV_TOKEN" ] || cv_done skip "no managed-identity token for Microsoft Graph (no identity attached to this VM)" CV-LD29
# Baseline: get current secrets before adding
cv_http GET "https://graph.microsoft.com/v1.0/applications/$app?\$select=passwordCredentials" "$CV_TOKEN"
if [ "$CV_HCODE" != 200 ]; then cv_done error "failed to get baseline secrets for app $app; undo baseline cannot be recorded" CV-LD29; fi
if ! printf '%s' "$CV_HBODY" | grep -q 'passwordCredentials'; then
  CV_HBODY=""
  cv_done error "baseline secrets response missing passwordCredentials property" CV-LD29
fi
baseline=$(printf '%s' "$CV_HBODY" | grep -o '"keyId":"[^"]*"' | cut -d'"' -f4 | tr '\n' ',' | sed 's/,$//')
CV_HBODY=""
# Record undo baseline (exclusive: fail if already exists)
undo_data=$(printf '{"app":"%s","baseline":"%s"}' "$app" "$baseline")
cv_undo_new CV-LD29 "$undo_data" || cv_done error "undo record for CV-LD29 already exists; a previous run was not cleaned up" CV-LD29
# Add secret
end=$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)
cv_http POST "https://graph.microsoft.com/v1.0/applications/$app/addPassword" "$CV_TOKEN" "{\"passwordCredential\":{\"displayName\":\"$CV_TAG\",\"endDateTime\":\"$end\"}}"
[ "$CV_HCODE" = 200 ] || cv_classify_http "$CV_HCODE" 'service principal credential addition on the test application' BAS_CLOUD_EXPECT_KEY_CREATE CV-LD29
keyid=$(printf '%s' "$CV_HBODY" | sed -n 's/.*"keyId":"\([^"]*\)".*/\1/p' | head -n1)
CV_HBODY=""
[ -n "$keyid" ] || cv_done fail "a client secret was added to the test application but its key id could not be parsed; undo record is left for cleanup phase" CV-LD29
# Remove secret
cv_http POST "https://graph.microsoft.com/v1.0/applications/$app/removePassword" "$CV_TOKEN" "{\"keyId\":\"$keyid\"}"
rmcode=$CV_HCODE
# Verify: get current secrets after removal
cv_http GET "https://graph.microsoft.com/v1.0/applications/$app?\$select=passwordCredentials" "$CV_TOKEN"
verifycode=$CV_HCODE
extra=0
if [ "$verifycode" = 200 ]; then
  current=$(printf '%s' "$CV_HBODY" | grep -o '"keyId":"[^"]*"' | cut -d'"' -f4)
  for id in $current; do printf '%s' "$baseline" | grep -q "$id" || extra=$((extra+1)); done
fi
CV_HBODY=""
echo "EXEC T1098.001: client secret added to the test application and removed; remove_http=$rmcode verify_http=$verifycode extra_secrets=$extra. The secret text was never recorded."
if [ "$rmcode" != 200 ] || [ "$verifycode" != 200 ] || [ "$extra" -gt 0 ]; then
  cv_done fail "client secret addition/removal/verification failed; undo record is left for cleanup phase" CV-LD29
fi
# Do not remove undo record here; cleanup undo script will do it.
cv_gate BAS_CLOUD_EXPECT_KEY_CREATE && cv_done skip "client secret addition succeeded and is documented as expected; cleanup verified" CV-LD29
cv_done fail "the workload identity could add a client secret to a service principal; cleanup verified" CV-LD29
