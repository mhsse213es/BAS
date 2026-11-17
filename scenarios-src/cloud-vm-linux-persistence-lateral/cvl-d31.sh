dirs=()
for d in /etc/rc.local /etc/cron.d /etc/cron.daily /etc/profile.d /etc/init.d "$HOME/.config/autostart" "$HOME/.bashrc"; do [ -e "$d" ] && dirs+=("$d"); done
[ "${#dirs[@]}" -gt 0 ] || cv_done pass "no standard startup script location exists on this host" CV-LD31
writable=""
for d in "${dirs[@]}"; do
  if [ -z "$(find "$d" -maxdepth 0 -perm /022 2>/dev/null)" ]; then
    [ -r "$d" ] || cv_done error "the mode of a startup location could not be read: $d" CV-LD31
  else writable="$writable $d"; fi
done
echo "EXEC T1574: read-only permission check of startup script locations; locations=${#dirs[@]} writable_by_group_or_other=$(printf '%s' "$writable" | wc -w). Nothing was written."
[ -n "$writable" ] && cv_done fail "a startup script location is writable by a group or other user (${writable# })" CV-LD31
cv_done pass "startup script locations are not writable by group or other users" CV-LD31
