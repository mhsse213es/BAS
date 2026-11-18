# Undo for cvl-d29: delete any client secret created outside baseline
rec=$(cv_undo_read CV-LD29)
[ -n "$rec" ] || exit 0  # record unreadable or missing; keep (may be leftover)

app=$(printf '%s' "$rec" | grep -o '"app":"[^"]*"' | head -n1 | cut -d'"' -f4)
baseline=$(printf '%s' "$rec" | grep -o '"baseline":"[^"]*"' | head -n1 | cut -d'"' -f4)
[ -n "$app" ] || exit 0  # malformed record; keep

cv_az_token "$CV_RES_GRAPH" 2>/dev/null
[ -n "$CV_TOKEN" ] || exit 0  # no token; keep

# Get current secrets
cv_http GET "https://graph.microsoft.com/v1.0/applications/$app?\$select=passwordCredentials" "$CV_TOKEN"
[ "$CV_HCODE" = 200 ] || exit 0  # GET failed; keep

# Delete any secrets outside baseline
current=$(printf '%s' "$CV_HBODY" | grep -o '"keyId":"[^"]*"' | cut -d'"' -f4)
removed=0
for id in $current; do
  if ! printf '%s' "$baseline" | grep -q "$id"; then
    cv_http POST "https://graph.microsoft.com/v1.0/applications/$app/removePassword" "$CV_TOKEN" "{\"keyId\":\"$id\"}"
    [ "$CV_HCODE" = 200 ] && removed=$((removed+1))
  fi
done

# Verify no extra secrets remain
cv_http GET "https://graph.microsoft.com/v1.0/applications/$app?\$select=passwordCredentials" "$CV_TOKEN"
[ "$CV_HCODE" = 200 ] || exit 0  # verification GET failed; keep

current=$(printf '%s' "$CV_HBODY" | grep -o '"keyId":"[^"]*"' | cut -d'"' -f4)
extra=0
for id in $current; do printf '%s' "$baseline" | grep -q "$id" || extra=$((extra+1)); done
CV_HBODY=""

echo "UNDO CV-LD29: removed=$removed extra_still=$extra"
# Remove record only when no extra secrets remain
[ "$extra" -eq 0 ] && cv_undo_remove CV-LD29
exit 0
