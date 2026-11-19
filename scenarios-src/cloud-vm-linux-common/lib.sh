# Cloud VM Linux mastery shared library (bash). Concatenated into every Linux step by the pack builder.
# Verdicts: PASS = the cloud control refused the action. FAIL = the action succeeded where the operator did not expect it,
# or material was found at rest. SKIP = a prerequisite or gate is missing. ERROR = the result cannot be classified.
# Tokens, access keys, client secrets and secret values stay in shell variables only. They are never echoed or written to disk.
CV_RUN="${BAS_RUN_ID:-}"
CV_RUN="${CV_RUN:0:8}"
[ -n "$CV_RUN" ] || CV_RUN=$(printf '%08x' "$RANDOM$RANDOM")
CV_TAG="bas_cv_${CV_RUN}"
CV_RES_MGMT='https%3A%2F%2Fmanagement.azure.com%2F'
CV_RES_VAULT='https%3A%2F%2Fvault.azure.net'
CV_RES_STORAGE='https%3A%2F%2Fstorage.azure.com%2F'
CV_RES_GRAPH='https%3A%2F%2Fgraph.microsoft.com%2F'

cv_gate() { [ "${!1:-}" = "true" ]; }
cv_env() { printenv "$1" 2>/dev/null; }
cv_done() { # outcome reason id
  local p=SKIP
  case "$1" in pass) p=PASS ;; fail) p=FAIL ;; error) p=ERROR ;; esac
  echo "$p: $2 [BAS-SIM-$3]"
  exit 0
}

cv_az_instance() { curl -s -m 2 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null; }
cv_az_present() { printf '%s' "$(cv_az_instance)" | grep -q '"compute"'; }
cv_az_init() { # id -> sets SUB RG VMN, or SKIPs when this is not an Azure VM
  local inst
  inst=$(cv_az_instance)
  if ! printf '%s' "$inst" | grep -q '"compute"'; then cv_done skip "Azure IMDS is unreachable from this host, so this is not an Azure VM" "$1"; fi
  SUB=$(printf '%s' "$inst" | grep -o '"subscriptionId":"[^"]*"' | head -n1 | cut -d'"' -f4)
  RG=$(printf '%s' "$inst" | grep -o '"resourceGroupName":"[^"]*"' | head -n1 | cut -d'"' -f4)
  VMN=$(printf '%s' "$inst" | grep -o '"name":"[^"]*"' | head -n1 | cut -d'"' -f4)
}
cv_az_token() { # encoded-resource -> CV_TOKEN, CV_TCODE
  local out
  out=$(curl -s -m 5 -w '\n%{http_code}' -H 'Metadata: true' "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$1" 2>/dev/null)
  CV_TCODE=$(printf '%s' "$out" | tail -n1)
  CV_TOKEN=$(printf '%s' "$out" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' | head -n1)
}
cv_http() { # method uri token [body] [x-ms-version] -> CV_HCODE, CV_HBODY
  local args out
  args=(-s -m 15 -w '\n%{http_code}' -X "$1")
  [ -n "${5:-}" ] && args+=(-H "x-ms-version: $5")
  if [ -n "${4:-}" ]; then args+=(-H 'Content-Type: application/json' --data "$4"); fi
  # the bearer token is passed through a curl config on stdin, so it never appears in the process list
  out=$(printf 'header = "Authorization: Bearer %s"\n' "$3" | curl -K - "${args[@]}" "$2" 2>/dev/null)
  CV_HCODE=$(printf '%s' "$out" | tail -n1)
  CV_HBODY=$(printf '%s' "$out" | sed '$d')
}
cv_count() { # jq filter -> count, or "unknown" without jq
  if [ "$CV_HCODE" != 200 ]; then echo 0; return; fi
  if command -v jq >/dev/null 2>&1; then printf '%s' "$CV_HBODY" | jq -r "$1" 2>/dev/null; else echo unknown; fi
}
cv_classify_http() { # code what gate id
  local c="$1" what="$2" gate="${3:-BAS_CLOUD_EXPECT_ENUMERATION}" id="$4"
  case "$c" in
    2??)
      if cv_gate "$gate"; then cv_done skip "$what succeeded, which the operator documents as expected for this workload, so no control verdict is scored" "$id"; fi
      cv_done fail "$what succeeded for an identity the operator did not expect to have this access" "$id" ;;
    401|403) cv_done pass "$what was refused by the cloud control (HTTP $c)" "$id" ;;
    *) cv_done error "$what returned HTTP $c, which cannot be classified as a control result" "$id" ;;
  esac
}

cv_curl_auth() { # method url token [curl args...] -> prints the HTTP code only
  local m="$1" u="$2" t="$3"; shift 3
  printf 'header = "Authorization: Bearer %s"\n' "$t" | curl -s -m 30 -o /dev/null -w '%{http_code}' -X "$m" -K - "$@" "$u" 2>/dev/null
}
cv_have_aws() { command -v aws >/dev/null 2>&1; }
cv_aws() { CV_AOUT=$(aws "$@" --output json 2>&1); CV_ARC=$?; }
cv_classify_aws() { # what gate id
  local what="$1" gate="${2:-BAS_CLOUD_EXPECT_ENUMERATION}" id="$3"
  if [ "$CV_ARC" -eq 0 ]; then
    if cv_gate "$gate"; then cv_done skip "$what succeeded, which the operator documents as expected for this workload, so no control verdict is scored" "$id"; fi
    cv_done fail "$what succeeded for an identity the operator did not expect to have this access" "$id"
  fi
  if printf '%s' "$CV_AOUT" | grep -Eq 'Unable to locate credentials|NoCredentialProviders|NoCredentials'; then
    cv_done skip "no AWS identity is available to this host, so $what was not attempted" "$id"
  fi
  if printf '%s' "$CV_AOUT" | grep -Eq 'AccessDenied|UnauthorizedOperation|AuthFailure|not authorized|Forbidden'; then
    cv_done pass "$what was refused by the cloud control" "$id"
  fi
  cv_done error "$what failed without a classifiable control answer" "$id"
}
cv_aws_token() { curl -s -m 2 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 'http://169.254.169.254/latest/api/token' 2>/dev/null; }
cv_aws_meta() { # path -> body (empty when unavailable)
  local t
  t=$(cv_aws_token)
  [ -n "$t" ] || return 0
  curl -s -m 2 -H "X-aws-ec2-metadata-token: $t" "http://169.254.169.254/latest/meta-data/$1" 2>/dev/null
}
cv_set_region() {
  if [ -z "${AWS_DEFAULT_REGION:-}" ]; then
    local r; r=$(cv_aws_meta placement/region)
    [ -n "$r" ] && export AWS_DEFAULT_REGION="$r"
  fi
}

# Undo record helpers: baseline-based kill-safe undo for cloud steps.
cv_undo_path() { # id -> path
  local id="$1"
  printf '%s' "${TMPDIR:-/tmp}/bas-cv-undo/${id}.json"
}

cv_undo_new() { # id data_json -> creates record (exclusive), exits with error if already exists
  local id="$1" data="$2"
  local dir p
  dir=$(dirname "$(cv_undo_path "$id")")
  mkdir -p "$dir" 2>/dev/null || true
  p=$(cv_undo_path "$id")
  set -C  # noclobber: > fails if file exists
  printf '%s' "$data" > "$p" 2>/dev/null || { set +C; return 1; }
  set +C
  return 0
}

cv_undo_set() { # id data_json -> updates existing record
  local id="$1" data="$2"
  local p
  p=$(cv_undo_path "$id")
  printf '%s' "$data" > "$p" 2>/dev/null || return 1
  return 0
}

cv_undo_read() { # id -> prints JSON contents, or nothing if unreadable
  local id="$1"
  local p
  p=$(cv_undo_path "$id")
  [ -f "$p" ] || return 0
  cat "$p" 2>/dev/null || return 0
}

cv_undo_remove() { # id -> removes record
  local id="$1"
  local p
  p=$(cv_undo_path "$id")
  rm -f "$p" 2>/dev/null || true
  return 0
}
