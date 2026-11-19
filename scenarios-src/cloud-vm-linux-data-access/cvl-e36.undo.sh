# Undo for cvl-e36: delete uploaded synthetic objects from cloud storage
rec=$(cv_undo_read CV-LE36)
[ -n "$rec" ] || exit 0  # record unreadable or missing; keep (may be leftover)

azure_url=$(printf '%s' "$rec" | grep -o '"azure_url":"[^"]*"' | head -n1 | cut -d'"' -f4)
s3_bucket=$(printf '%s' "$rec" | grep -o '"s3_bucket":"[^"]*"' | head -n1 | cut -d'"' -f4)
s3_key=$(printf '%s' "$rec" | grep -o '"s3_key":"[^"]*"' | head -n1 | cut -d'"' -f4)

deleted=0

# Delete Azure blob if URL is set
if [ -n "$azure_url" ]; then
  cv_az_token "$CV_RES_STORAGE" 2>/dev/null
  if [ -n "$CV_TOKEN" ]; then
    code=$(cv_curl_auth DELETE "$azure_url" "$CV_TOKEN" -H 'x-ms-version: 2021-08-06')
    if [ "${code:0:1}" = 2 ] || [ "$code" = 404 ]; then
      deleted=$((deleted+1))
    fi
  fi
fi

# Delete S3 object if bucket and key are set
if [ -n "$s3_bucket" ] && [ -n "$s3_key" ]; then
  if cv_have_aws; then
    cv_set_region 2>/dev/null
    cv_aws s3api delete-object --bucket "$s3_bucket" --key "$s3_key" 2>/dev/null
    if [ "$CV_ARC" -eq 0 ]; then
      deleted=$((deleted+1))
    fi
  fi
fi

echo "UNDO CV-LE36: deleted=$deleted"
# Record is removed when cleanup completes (delete attempts made for all recorded objects)
[ "$deleted" -gt 0 ] && cv_undo_remove CV-LE36 || true
exit 0
