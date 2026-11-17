cv_gate BAS_CONFIRM_CLOUD_EXFIL_SIM || cv_done skip "lab gate BAS_CONFIRM_CLOUD_EXFIL_SIM is not set to true; this step uploads a synthetic object to cloud storage and deletes it" CV-LE36
payload=$(mktemp "${TMPDIR:-/tmp}/${CV_TAG}.XXXXXX")
trap 'rm -f "$payload"' EXIT
for i in $(seq 1 40); do printf 'BAS SYNTHETIC DATA - NOT REAL. '; done > "$payload"
acct=$(cv_env BAS_CLOUD_TEST_STORAGE_ACCOUNT); bucket=$(cv_env BAS_CLOUD_TEST_BUCKET)
key="bas-synthetic/${CV_TAG}.txt"
if [ -n "$acct" ] && cv_az_present; then
  cv_az_token "$CV_RES_STORAGE"
  if [ -n "$CV_TOKEN" ]; then
    code=$(curl -s -m 30 -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $CV_TOKEN" -H 'x-ms-version: 2021-08-06' -H 'x-ms-blob-type: BlockBlob' -H 'Content-Type: text/plain' --data-binary @"$payload" "https://$acct.blob.core.windows.net/bas-synthetic/${CV_TAG}.txt" 2>/dev/null)
    if [ "$code" = 201 ]; then
      dc=$(curl -s -m 30 -o /dev/null -w '%{http_code}' -X DELETE -H "Authorization: Bearer $CV_TOKEN" -H 'x-ms-version: 2021-08-06' "https://$acct.blob.core.windows.net/bas-synthetic/${CV_TAG}.txt" 2>/dev/null)
      if [ "${dc:0:1}" = 2 ]; then cl="verified"; else cl="NOT verified, delete bas-synthetic/${CV_TAG}.txt manually"; fi
      cv_done fail "a synthetic object was uploaded to Azure Blob storage from this VM; egress to cloud storage is not restricted; cleanup $cl" CV-LE36
    fi
    cv_classify_http "$code" 'upload of a synthetic object to Azure Blob storage' BAS_CLOUD_EXPECT_EXFIL_SIM CV-LE36
  fi
fi
if [ -n "$bucket" ] && cv_have_aws && [ -n "$(cv_aws_token)" ]; then
  cv_set_region
  cv_aws s3 cp "$payload" "s3://$bucket/$key"
  if [ "$CV_ARC" -eq 0 ]; then
    cv_aws s3api delete-object --bucket "$bucket" --key "$key"
    if [ "$CV_ARC" -eq 0 ]; then cl="verified"; else cl="NOT verified, delete $key manually"; fi
    cv_done fail "a synthetic object was uploaded to S3 from this instance; egress to cloud storage is not restricted; cleanup $cl" CV-LE36
  fi
  cv_classify_aws 'upload of a synthetic object to S3' BAS_CLOUD_EXPECT_EXFIL_SIM CV-LE36
fi
cv_done skip "no test storage target and identity path is configured on this host" CV-LE36
