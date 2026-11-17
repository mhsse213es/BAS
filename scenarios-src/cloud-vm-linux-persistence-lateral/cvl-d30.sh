ls_out=$(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null)
[ -n "$ls_out" ] || cv_done error "listening sockets could not be read (ss and netstat unavailable)" CV-LD30
listen=$(printf '%s\n' "$ls_out" | awk '$4 ~ /:(22|5985|5986)$/' | wc -l)
if [ "$listen" -eq 0 ]; then echo "EXEC T1021: read-only check; no SSH or WinRM listener on 22, 5985 or 5986."; cv_done pass "no remote-management listener (SSH or WinRM) is listening on this host" CV-LD30; fi
ufw_allow=0; ufw_active=0; ipt=""; ipt_accept=0; ipt_drop=0
if command -v ufw >/dev/null 2>&1; then
  st=$(ufw status 2>/dev/null)
  printf '%s' "$st" | grep -q '^Status: active' && ufw_active=1
  printf '%s' "$st" | grep -Eq '^(22|ssh|5985|5986)[^ ]*[[:space:]]+ALLOW' && ufw_allow=1
fi
if command -v iptables >/dev/null 2>&1; then
  ipt=$(iptables -S INPUT 2>/dev/null)
  printf '%s' "$ipt" | grep -Eq -- '--dport (22|5985|5986) .*-j ACCEPT' && ipt_accept=1
  printf '%s' "$ipt" | grep -Eq -- '-P INPUT (DROP|REJECT)|-j (DROP|REJECT)' && ipt_drop=1
fi
echo "EXEC T1021: read-only firewall check (no rule or listener change). listeners=$listen ufw_active=$ufw_active ufw_allow=$ufw_allow iptables_accept=$ipt_accept iptables_drop=$ipt_drop"
if [ "$ufw_allow" -eq 1 ] || [ "$ipt_accept" -eq 1 ]; then cv_done fail "a remote-management listener is present and a firewall allow rule covers SSH or WinRM ports" CV-LD30; fi
if [ "$ufw_active" -eq 1 ] || [ "$ipt_drop" -eq 1 ]; then cv_done pass "a remote-management listener exists but the host firewall does not allow its port" CV-LD30; fi
cv_done error "a remote-management listener exists but no firewall state could be determined (ufw and iptables not readable)" CV-LD30
