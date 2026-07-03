# Audspect BAS — Monitoring and Logging Guide

**Classification:** Internal — Audspect Engineering / Confidential  
**Platform Version:** v1.7.3

---

## Overview

Audspect BAS produces logs at three levels: structured application logs from the orchestrator, PostgreSQL query logs, and Docker container-level logs. There is no built-in log shipping — export to your SIEM or log aggregator via Docker logging drivers.

---

## Orchestrator Log Format

The orchestrator logs to stdout (structured log lines):

```
2026-07-01T09:00:00Z [INFO] agent connected agent_id=agt-abc123 hostname=WIN-01 ip=192.168.1.100
2026-07-01T09:01:00Z [WARN] scenario signature invalid scenario_id=my-scenario
2026-07-01T09:02:00Z [ERROR] run dispatch failed run_id=run-xyz error="agent offline"
```

**Log levels:** DEBUG / INFO / WARN / ERROR

**Default level:** INFO. To enable debug logging, set `BAS_LOG_LEVEL=debug` in `.env`.

---

## Key Log Events

### Authentication

```
[INFO] user login success username=analyst@company.com ip=192.168.1.10
[WARN] user login failed username=unknown@company.com ip=192.168.1.50 reason=bad_credentials
[WARN] rate limit exceeded ip=192.168.1.50 endpoint=/api/auth/login
```

### Agent Lifecycle

```
[INFO] agent enrolled agent_id=agt-new hostname=WIN-NEW ip=192.168.1.200
[INFO] agent heartbeat agent_id=agt-abc123 binary_trust=trusted
[WARN] agent binary trust failed agent_id=agt-abc123 hash=abc123 expected=def456
[INFO] agent state changed agent_id=agt-abc123 old=active new=quarantined by=admin@company.com
```

### Scenario Execution

```
[INFO] run dispatched run_id=run-xyz scenario_id=safe-simulation agent_id=agt-abc123
[INFO] run step result run_id=run-xyz step_id=step-001 verdict=pass
[INFO] run completed run_id=run-xyz prevention_score=82 exposure_score=18
[ERROR] run delivery failed run_id=run-xyz agent_id=agt-abc123 error="agent disconnected"
```

### Integrity

```
[WARN] scenario signature verification failed scenario_id=my-scenario
[WARN] filesystem tamper detected scenario_id=my-scenario path=scenarios/my-scenario.yaml
[INFO] scenario loaded with valid signature scenario_id=safe-simulation
```

### Attack Path

```
[INFO] ap job created job_id=ap-job-xyz agent_id=agt-abc123
[INFO] ap job dispatched job_id=ap-job-xyz
[INFO] ap job stage updated job_id=ap-job-xyz stage=probing targets_done=12 targets_total=48
[INFO] ap job completed job_id=ap-job-xyz nodes=52 edges=120
[WARN] ap job delivery failed job_id=ap-job-xyz reason=ack_timeout
```

---

## Viewing Logs

### Docker Compose

```bash
# All services, real-time
docker compose logs -f

# Orchestrator only, last 200 lines
docker compose logs orchestrator --tail=200

# Filter for errors
docker compose logs orchestrator | grep "\[ERROR\]\|\[WARN\]"

# Filter for a specific agent
docker compose logs orchestrator | grep "agent_id=agt-abc123"
```

### Searching logs

```bash
# All signature failures today
docker compose logs orchestrator | grep "signature\|tamper"

# All failed logins
docker compose logs orchestrator | grep "login failed"

# All binary trust issues
docker compose logs orchestrator | grep "binary trust"
```

---

## Platform Health Monitoring

### Health endpoint

```bash
# Check platform health
curl -s http://localhost:9000/health

# Expected response
{"status":"ok","db":"ok","version":"1.7.3"}
```

Responses:
- `200 {"status":"ok"}` — healthy
- `503 {"status":"degraded","db":"unavailable"}` — database unreachable

### Container health

```bash
docker compose ps
```

Watch for containers in `Exit` or `Restarting` state.

### PostgreSQL metrics

```bash
# Active connections
docker compose exec postgres psql -U bas -d bas \
  -c "SELECT count(*) FROM pg_stat_activity WHERE state='active';"

# Table sizes
docker compose exec postgres psql -U bas -d bas \
  -c "SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size FROM pg_tables WHERE schemaname='public' ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC LIMIT 10;"

# Long-running queries
docker compose exec postgres psql -U bas -d bas \
  -c "SELECT pid, now() - pg_stat_activity.query_start AS duration, query FROM pg_stat_activity WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes';"
```

---

## Disk Usage Monitoring

```bash
# Docker volume usage
docker system df -v

# bas_pgdata volume specifically
docker run --rm -v bas_pgdata:/data alpine du -sh /data

# Orchestrator container disk (should be minimal — read-only filesystem)
docker compose exec orchestrator df -h /
```

Alert thresholds:
- PostgreSQL data directory > 80% full: schedule maintenance
- PostgreSQL data directory > 90% full: immediate action required (stop ingestion, archive old data)

---

## Audit Log API

The platform's audit log (user-facing) is accessible via API for security teams:

```
GET /api/events?category=auth&from=2026-07-01T00:00:00Z&limit=100
GET /api/events?category=agent&from=2026-07-01T00:00:00Z
GET /api/events?category=integrity
GET /api/events/export?format=csv&from=2026-07-01&to=2026-07-31
```

Event categories: `auth`, `user`, `agent`, `scenario`, `run`, `finding`, `integrity`, `config`

---

## Exporting Logs to a SIEM

### Docker syslog driver

```yaml
services:
  orchestrator:
    logging:
      driver: syslog
      options:
        syslog-address: "tcp://siem.company.com:514"
        tag: "audspect-orchestrator"
```

### Docker fluentd driver

```yaml
services:
  orchestrator:
    logging:
      driver: fluentd
      options:
        fluentd-address: "localhost:24224"
        tag: "audspect.orchestrator"
```

### JSON file driver (default) + Filebeat

Default Docker logging writes JSON to `/var/lib/docker/containers/<id>/<id>-json.log`. Configure Filebeat to ship these to Elasticsearch.

---

## Key Metrics for SOC Dashboards

| Metric | Query | Alert Threshold |
|---|---|---|
| Failed logins per hour | `grep "login failed" | count` | >10/hour |
| Agent binary trust failures | `grep "binary trust failed"` | Any |
| Scenario signature failures | `grep "signature verification failed"` | Any |
| Agent offline count | `GET /api/agents?state=offline` | >20% of fleet |
| Database connection errors | `grep "db.*error"` | Any |
| AP job delivery failures | `grep "ap job delivery failed"` | >3/day |

---

*© Audspect Engineering — Internal / Confidential*
