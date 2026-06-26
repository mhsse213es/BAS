#!/bin/sh
# Inject API_KEY_RED / API_KEY_BLUE from env into conf/local.yml before
# Caldera starts. The stock Caldera image does not read these environment
# variables natively — without this step the API key in the running instance
# does not match CALDERA_API_KEY in the orchestrator stack and every REST
# call returns 401, requiring manual intervention.
#
# Caldera merges local.yml OVER default.yml at startup, so specifying only
# the two key fields is enough — all other settings come from default.yml.
set -e

if [ -n "$API_KEY_RED" ] || [ -n "$API_KEY_BLUE" ]; then
    red="${API_KEY_RED:-ADMIN123}"
    blue="${API_KEY_BLUE:-ADMIN123}"
    printf 'api_key_red: %s\napi_key_blue: %s\n' "$red" "$blue" > conf/local.yml
    echo "[entrypoint] Caldera API keys injected from environment."
fi

exec python3 server.py "$@"
