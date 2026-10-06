# Audspect dashboard (orchestrator/web)

Source for the dashboard served from `/wwwroot` in the orchestrator image.

- `index.html` — markup only; the build injects the hashed CSS/JS names.
- `styles/app.css` — all styles.
- `src/main.js` — entry: `installGlobals()`, then the load-time `__init_L*` functions in their original order.
- `src/globals.js` — the only place app names are defined on `window`. Every function called from an inline `on…=` handler must be listed in `HANDLER_FUNCTIONS`; CI (`scripts/g1c-check-globals.py`) fails on missing or stale entries. This list is the G1d (strict CSP) worklist: it shrinks as handlers move to event listeners.
- `src/core/` — escaper (`escape.js`), API helper (`api.js`), shared formatting (`util.js`), shared mutable state (`state.js`).
- `src/features/` — one module per dashboard area.

Build and test only inside the pinned images (Node is never installed on the host):

    tools/node.sh sh -c 'npm ci --ignore-scripts && npm test && npm run build'
    tools/smoke.sh dist           # Playwright smoke test of every tab (after a build)
    tools/dev-build.sh            # refreshes orchestrator/wwwroot for local runs
    scripts/g1-run-local.sh       # G1 XSS guard on the classifier view (repo root)

Integrity: the build writes `dist/MANIFEST.sha256`; the Docker build compiles its SHA-256 into the orchestrator, which refuses to start if any served file differs, is missing, or is unlisted.
