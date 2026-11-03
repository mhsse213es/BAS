#!/usr/bin/env python3
"""R-20a: load check of the cloud discovery gate and the account allow-list on a running server.

Prepared, not run. It is meant for staging and is run by the operator.

What it checks, with the server's expected answer for each case:
  - an account that is not on CLOUD_ALLOWED_ACCOUNTS gets 403 and never reaches a provider;
  - concurrent passes for one allow-listed account: one runs, the rest get 409 (busy);
  - more distinct allow-listed accounts than CLOUD_DISCOVERY_MAX_CONCURRENT + CLOUD_DISCOVERY_MAX_QUEUED:
    the overflow gets 503 (saturated), and nothing hangs longer than CLOUD_DISCOVERY_QUEUE_WAIT plus the run time.

It prints a count of each status code per case. It does not decide pass or fail on its own: compare the counts
with the expected column. Discovery of a real account calls the provider, so run it only against accounts the
owner has approved, and never against an account that is not on the allow-list except for the 403 case.

Credentials come from the environment, never from this file:
  BAS_URL          e.g. https://192.168.10.78:9543
  BAS_USER         console login
  BAS_PASS         console password
  LOAD_ALLOWED     comma-separated provider:accountId that is on the allow-list (for the concurrency cases)
  LOAD_UNLISTED    one provider:accountId that is NOT on the allow-list (for the 403 case)
  LOAD_TARGET      target string for the discovery run (for example an IAM role ARN)
Optional:
  LOAD_CONCURRENCY (default 12)
  LOAD_INSECURE=1  skip TLS verification for a self-signed staging certificate
"""

import concurrent.futures
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from collections import Counter


def env(name, default=None, required=False):
    v = os.environ.get(name, default)
    if required and not v:
        sys.exit(f"missing environment variable {name}")
    return v


BASE = env("BAS_URL", required=True).rstrip("/")
USER = env("BAS_USER", required=True)
PASSWORD = env("BAS_PASS", required=True)
ALLOWED = [a.strip() for a in env("LOAD_ALLOWED", required=True).split(",") if a.strip()]
UNLISTED = env("LOAD_UNLISTED", required=True).strip()
TARGET = env("LOAD_TARGET", required=True).strip()
CONCURRENCY = int(env("LOAD_CONCURRENCY", "12"))

ctx = ssl._create_unverified_context() if env("LOAD_INSECURE") == "1" else None


def call(method, path, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=900) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except json.JSONDecodeError:
            return e.code, {}


def split(pa):
    provider, account = pa.split(":", 1)
    return provider, account


def run_body(pa, label):
    provider, account = split(pa)
    return {"scenarioId": label, "account": {"provider": provider, "accountId": account},
            "discover": True, "target": TARGET, "held": []}


def login():
    status, body = call("POST", "/api/auth/login", body={"username": USER, "password": PASSWORD})
    if status != 200 or "token" not in body:
        sys.exit(f"login failed: HTTP {status}")
    return body["token"]


def case(name, expected, token, requests):
    """Send all requests at once and count the status codes."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(requests)) as ex:
        futures = [ex.submit(call, "POST", "/api/cloud-runs", token, body) for body in requests]
        statuses = Counter(f.result()[0] for f in futures)
    print(f"\n== {name}")
    print(f"   expected: {expected}")
    for code, n in sorted(statuses.items()):
        print(f"   HTTP {code}: {n}")


def main():
    token = login()

    # 1. Unlisted account: every request must be refused before any provider call.
    case("unlisted account refused", "all HTTP 403", token,
         [run_body(UNLISTED, "load-unlisted") for _ in range(4)])

    # 2. Same allow-listed account, many at once: one pass runs, the others see busy.
    first = ALLOWED[0]
    case("same account, concurrent passes", "one run then HTTP 409 for the rest (the first may still be running)",
         token, [run_body(first, "load-same-account") for _ in range(CONCURRENCY)])

    # 3. Distinct allow-listed accounts, more than the gate can hold: overflow gets 503.
    if len(ALLOWED) < 2:
        print("\n== distinct accounts: skipped (LOAD_ALLOWED lists fewer than two accounts)")
    else:
        case("distinct accounts past the limit", "some run, the overflow HTTP 503 (saturated)",
             token, [run_body(ALLOWED[i % len(ALLOWED)], f"load-distinct-{i}") for i in range(CONCURRENCY)])

    print("\nAfter the run, check on the server: cloud_request_refusals_total, cloud_discovery_failures_total"
          " and the audit rows with action '*.refused' (one per refused request).")


if __name__ == "__main__":
    main()
