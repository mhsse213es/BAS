#!/bin/sh
# Inject API_KEY_RED / API_KEY_BLUE from env into conf/local.yml before
# Caldera starts. Uses Python to merge the keys into the full default config
# so fields like crypt_salt are never inadvertently wiped.
set -e

if [ -n "$API_KEY_RED" ] || [ -n "$API_KEY_BLUE" ]; then
    python3 - <<'PYEOF'
import yaml, os

# Seed from the existing local.yml if already populated, otherwise from
# default.yml. This preserves crypt_salt and every other field Caldera needs.
cfg = {}
for src in ['conf/local.yml', 'conf/default.yml']:
    try:
        with open(src) as f:
            loaded = yaml.safe_load(f) or {}
        if loaded:
            cfg = loaded
            break
    except OSError:
        pass

cfg['api_key_red']  = os.environ.get('API_KEY_RED',  'ADMIN123')
cfg['api_key_blue'] = os.environ.get('API_KEY_BLUE', 'ADMIN123')

with open('conf/local.yml', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)

print('[entrypoint] Caldera API keys injected from environment.')
PYEOF
fi

exec python3 server.py "$@"
