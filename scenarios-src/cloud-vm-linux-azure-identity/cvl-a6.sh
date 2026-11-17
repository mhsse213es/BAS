cv_az_present || cv_done skip "Azure IMDS is unreachable from this host, so this is not an Azure VM or IMDS is blocked on the host" CV-LA6
R=$(bash -c 'curl -s -m 3 -A "bas-cv-a6" -H "Metadata: true" -o /dev/null -w "%{http_code}" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"' 2>/dev/null)
echo "EXEC T1552.005: a child shell requested IMDS with a non-default user agent; http=$R"
if [ "$R" = 200 ]; then
  cv_gate BAS_CLOUD_EXPECT_IMDS_ACCESS && cv_done skip "IMDS is reachable from a child process, which the operator documents as expected, so no control verdict is scored" CV-LA6
  cv_done fail "IMDS answered a child process with an unrelated user agent, so metadata is reachable by any local process (no host-level restriction)" CV-LA6
fi
if [ "$R" = 000 ]; then cv_done pass "IMDS access from a child process was blocked on the host" CV-LA6; fi
cv_done error "the child request produced no classifiable result (HTTP $R)" CV-LA6
