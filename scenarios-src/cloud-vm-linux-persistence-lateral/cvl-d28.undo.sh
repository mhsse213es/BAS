# Undo for cvl-d28: delete any access key created outside baseline
rec=$(cv_undo_read CV-LD28)
[ -n "$rec" ] || exit 0  # record unreadable or missing; keep (may be leftover)

user=$(printf '%s' "$rec" | grep -o '"user":"[^"]*"' | head -n1 | cut -d'"' -f4)
baseline=$(printf '%s' "$rec" | grep -o '"baseline":"[^"]*"' | head -n1 | cut -d'"' -f4)
[ -n "$user" ] || exit 0  # malformed record; keep

cv_set_region 2>/dev/null
cv_have_aws || exit 0  # AWS CLI not available; keep record

# List current keys
cv_aws iam list-access-keys --user-name "$user" 2>/dev/null
[ "$CV_ARC" -eq 0 ] || exit 0  # list failed; keep

# Delete any keys outside baseline
current=$(printf '%s' "$CV_AOUT" | grep -o '"AccessKeyId": *"[^"]*"' | cut -d'"' -f4)
removed=0
for id in $current; do
  if ! printf '%s' "$baseline" | grep -q "$id"; then
    cv_aws iam delete-access-key --user-name "$user" --access-key-id "$id" 2>/dev/null
    [ "$CV_ARC" -eq 0 ] && removed=$((removed+1))
  fi
done

# Verify no extra keys remain
cv_aws iam list-access-keys --user-name "$user" 2>/dev/null
[ "$CV_ARC" -eq 0 ] || exit 0  # verification list failed; keep

current=$(printf '%s' "$CV_AOUT" | grep -o '"AccessKeyId": *"[^"]*"' | cut -d'"' -f4)
extra=0
for id in $current; do printf '%s' "$baseline" | grep -q "$id" || extra=$((extra+1)); done

echo "UNDO CV-LD28: removed=$removed extra_still=$extra"
# Remove record only when no extra keys remain
[ "$extra" -eq 0 ] && cv_undo_remove CV-LD28
exit 0
