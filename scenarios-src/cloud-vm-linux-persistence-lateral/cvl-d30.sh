ls_out=$(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null)
[ -n "$ls_out" ] || cv_done error "listening sockets could not be read (ss and netstat unavailable)" CV-LD30
listen=$(printf '%s\n' "$ls_out" | awk '$4 ~ /:(22|5985|5986)$/' | wc -l)
if [ "$listen" -eq 0 ]; then echo "EXEC T1021: read-only check; no SSH or WinRM listener on 22, 5985 or 5986."; cv_done pass "no remote-management listener (SSH or WinRM) is listening on this host" CV-LD30; fi
ufw_allow=0; ufw_active=0; ufw_default_allow=0; ufw_default_deny=0
ipt_accept=0; ipt_block=0; ipt_policy_accept=0; ipt_policy_drop=0
if command -v ufw >/dev/null 2>&1; then
  st=$(ufw status verbose 2>/dev/null)
  printf '%s' "$st" | grep -q '^Status: active' && ufw_active=1
  printf '%s' "$st" | grep -q 'Default: allow (incoming)' && ufw_default_allow=1
  printf '%s' "$st" | grep -q 'Default: deny (incoming)' && ufw_default_deny=1
  printf '%s' "$st" | grep -Eq '(^|[^0-9])(22|5985|5986)(/tcp)?([^0-9]|$).*ALLOW|OpenSSH.*ALLOW|WinRM.*ALLOW' && ufw_allow=1
fi
if command -v iptables >/dev/null 2>&1; then
  ipt=$(iptables -S INPUT 2>/dev/null)
  printf '%s' "$ipt" | grep -Eq -- '-P INPUT ACCEPT' && ipt_policy_accept=1
  printf '%s' "$ipt" | grep -Eq -- '-P INPUT (DROP|REJECT)' && ipt_policy_drop=1
  printf '%s' "$ipt" | grep -Eq -- '--dport (22|5985|5986) .*-j ACCEPT' && ipt_accept=1
  printf '%s' "$ipt" | grep -Eq -- '--dport (22|5985|5986) .*-j (DROP|REJECT)' && ipt_block=1
fi
echo "EXEC T1021: read-only firewall check (no rule or listener change). listeners=$listen ufw_active=$ufw_active ufw_default_allow=$ufw_default_allow ufw_allow=$ufw_allow iptables_accept=$ipt_accept iptables_policy_accept=$ipt_policy_accept"
if [ "$ufw_allow" -eq 1 ] || [ "$ipt_accept" -eq 1 ] || [ "$ufw_default_allow" -eq 1 ] || { [ "$ipt_policy_accept" -eq 1 ] && [ "$ipt_block" -eq 0 ]; }; then
  cv_done fail "a remote-management listener is present and the host firewall does not block its port (allow rule or default-accept policy)" CV-LD30
fi
if { [ "$ufw_active" -eq 1 ] && [ "$ufw_default_deny" -eq 1 ]; } || [ "$ipt_block" -eq 1 ] || [ "$ipt_policy_drop" -eq 1 ]; then
  cv_done pass "a remote-management listener exists but the host firewall blocks its port" CV-LD30
fi
cv_done error "a remote-management listener exists but the firewall state could not be determined as blocking or allowing" CV-LD30
