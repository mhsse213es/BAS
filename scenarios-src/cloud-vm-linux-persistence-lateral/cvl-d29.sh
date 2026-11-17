cv_gate BAS_CONFIRM_CLOUD_IAM_WRITE || cv_done skip "lab gate BAS_CONFIRM_CLOUD_IAM_WRITE is not set to true; this step adds and then removes a client secret on a test application" CV-LD29
app=$(cv_env BAS_CLOUD_TEST_APP_OBJECT_ID)
[ -n "$app" ] || cv_done skip "no test application configured (BAS_CLOUD_TEST_APP_OBJECT_ID); use a dedicated test application" CV-LD29
cv_az_token "$CV_RES_GRAPH"
[ -n "$CV_TOKEN" ] || cv_done skip "no managed-identity token for Microsoft Graph (no identity attached to this VM)" CV-LD29
end=$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)
cv_http POST "https://graph.microsoft.com/v1.0/applications/$app/addPassword" "$CV_TOKEN" "{\"passwordCredential\":{\"displayName\":\"$CV_TAG\",\"endDateTime\":\"$end\"}}"
[ "$CV_HCODE" = 200 ] || cv_classify_http "$CV_HCODE" 'service principal credential addition on the test application' BAS_CLOUD_EXPECT_KEY_CREATE CV-LD29
keyid=$(printf '%s' "$CV_HBODY" | sed -n 's/.*"keyId":"\([^"]*\)".*/\1/p' | head -n1)
CV_HBODY=""
[ -n "$keyid" ] || cv_done fail "a client secret was added to the test application but its key id could not be parsed, so removal was NOT attempted; remove the test application secret manually" CV-LD29
cv_http POST "https://graph.microsoft.com/v1.0/applications/$app/removePassword" "$CV_TOKEN" "{\"keyId\":\"$keyid\"}"
rmcode=$CV_HCODE
echo "EXEC T1098.001: client secret added to the test application and removed; remove_http=$rmcode. The secret text was never recorded."
case "$rmcode" in 2??) ;; *) cv_done fail "a client secret was added to the test application and cleanup was NOT verified; remove key id $keyid manually" CV-LD29 ;; esac
cv_gate BAS_CLOUD_EXPECT_KEY_CREATE && cv_done skip "client secret addition succeeded and is documented as expected; cleanup verified" CV-LD29
cv_done fail "the workload identity could add a client secret to a service principal; cleanup verified" CV-LD29
