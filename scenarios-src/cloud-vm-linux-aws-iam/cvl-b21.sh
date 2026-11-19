[ -n "$(cv_aws_token)" ] || cv_done skip "AWS IMDS is unreachable from this host, so this is not an EC2 instance" CV-LB21
cv_have_aws || cv_done skip "AWS CLI is not installed on this host" CV-LB21
command -v jq >/dev/null 2>&1 || cv_done error "jq is required to read the policy simulation result, so escalation exposure is not measured" CV-LB21
cv_set_region
role=$(cv_aws_meta 'iam/security-credentials/' | head -n1 | tr -d '\r' | sed 's/[[:space:]]*$//')
[ -n "$role" ] || cv_done pass "no instance role is attached, so there is no escalation path from this instance identity" CV-LB21
cv_aws iam get-role --role-name "$role"
[ "$CV_ARC" -eq 0 ] || cv_classify_aws 'reading the instance role' BAS_CLOUD_EXPECT_ENUMERATION CV-LB21
arn=$(printf '%s' "$CV_AOUT" | jq -r '.Role.Arn' 2>/dev/null)
cv_aws iam simulate-principal-policy --policy-source-arn "$arn" --action-names iam:AttachRolePolicy iam:PutRolePolicy iam:CreatePolicyVersion iam:CreateAccessKey iam:PassRole --resource-arns '*'
[ "$CV_ARC" -eq 0 ] || cv_done error "the policy simulation was refused or failed, so escalation exposure is not measured" CV-LB21
allowed=$(printf '%s' "$CV_AOUT" | jq -r '.EvaluationResults[] | select(.EvalDecision=="allowed") | .EvalActionName' 2>/dev/null)
n=$(printf '%s\n' "$allowed" | grep -c .)
echo "EXEC T1098: IAM policy simulation only, no change made. Actions reported allowed: $n"
[ "$n" -gt 0 ] && cv_done fail "the instance role policy simulation allows privilege-escalation actions ($(printf '%s' "$allowed" | paste -sd, -)); no change was made" CV-LB21
cv_done pass "the instance role policy simulation denies every tested privilege-escalation action" CV-LB21
