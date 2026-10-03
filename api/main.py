"""
BAS Platform — Python API Service
Handles reporting, AI analysis, scoring, and dashboard data.
The Go orchestrator handles real-time agent communication and scenario execution.
"""
from contextlib import asynccontextmanager
from typing import Any
import os

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, select, update
import httpx

from database import engine, Base, get_db
from models import Agent, Report, ScenarioRun
import scoring
from cors_config import allowed_origins


ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://orchestrator:9000")


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(
    title="BAS Platform API",
    version="1.0.0",
    lifespan=lifespan,
)

# F2 (groupF.txt): was allow_origins=["*"] with wildcard methods/headers --
# any origin could call this API from a browser. Real endpoints only ever
# use GET/POST and a JSON Content-Type (no Authorization header
# anywhere in this service); allow_origins is derived from PUBLIC_BASE_URL
# (plus optional CORS_ALLOWED_ORIGINS), the same concept the Go
# orchestrator's browser WebSocket origin check reads, so the two never
# drift apart as independently configured values. An unset PUBLIC_BASE_URL
# yields an empty origin list -- no cross-origin browser access at all --
# rather than falling back to a wildcard.
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins(),
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "bas-api"}


# ── Agents ─────────────────────────────────────────────────────────────────────

@app.get("/api/agents")
async def list_agents(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Agent).order_by(Agent.last_update.desc())
    )
    agents = result.scalars().all()
    return [_agent_to_dict(a) for a in agents]


@app.get("/api/agents/{agent_id}")
async def get_agent(agent_id: str, db: AsyncSession = Depends(get_db)):
    agent = await db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _agent_to_dict(agent)


# ── Reports ─────────────────────────────────────────────────────────────────────

@app.get("/api/report/{agent_id}")
async def get_report(agent_id: str, db: AsyncSession = Depends(get_db)):
    report = await db.get(Report, agent_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return _report_to_dict(report)


@app.get("/api/report/{agent_id}/score")
async def get_report_score(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Compute or return cached score for a report."""
    report = await db.get(Report, agent_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.score:
        return report.score

    # Compute score from categories
    categories = report.categories or []
    score = scoring.compute(categories)
    score_dict = score.to_dict()

    # Cache it
    await db.execute(
        update(Report).where(Report.agent_id == agent_id).values(score=score_dict)
    )
    await db.commit()
    return score_dict


# ── Scenario Runs ──────────────────────────────────────────────────────────────

@app.get("/api/scenarios/runs")
async def list_scenario_runs(
    agent_id: str | None = None,
    scenario_id: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(ScenarioRun).order_by(ScenarioRun.started_at.desc()).limit(100)
    if agent_id:
        query = query.where(ScenarioRun.agent_id == agent_id)
    if scenario_id:
        query = query.where(ScenarioRun.scenario_id == scenario_id)
    result = await db.execute(query)
    runs = result.scalars().all()
    return [_run_to_dict(r) for r in runs]


@app.get("/api/scenarios/runs/{run_id}")
async def get_scenario_run(run_id: str, db: AsyncSession = Depends(get_db)):
    run = await db.get(ScenarioRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return _run_to_dict(run)


# ── Proxy to Orchestrator (scenario dispatch) ──────────────────────────────────

@app.get("/api/scenarios")
async def list_scenarios():
    """Proxy to Go orchestrator for scenario list."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{ORCHESTRATOR_URL}/api/scenarios", timeout=10)
        resp.raise_for_status()
        return resp.json()


@app.post("/api/scenarios/{scenario_id}/run")
async def run_scenario(scenario_id: str, body: dict[str, Any]):
    """Proxy to Go orchestrator to dispatch scenario to agent."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{ORCHESTRATOR_URL}/api/scenarios/{scenario_id}/run",
            json=body,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _agent_to_dict(a: Agent) -> dict:
    return {
        "agentId":    a.agent_id,
        "hostname":   a.hostname,
        "ipAddress":  a.ip_address,
        "osVersion":  a.os_version,
        "username":   a.username,
        "status":     a.status,
        "envLabel":   a.env_label,
        "hasReport":  a.has_report,
        "lastUpdate": a.last_update.isoformat() if a.last_update else None,
    }


def _report_to_dict(r: Report) -> dict:
    return {
        "agentId":       r.agent_id,
        "hostname":      r.hostname,
        "ipAddress":     r.ip_address,
        "osVersion":     r.os_version,
        "username":      r.username,
        "status":        r.status,
        "envLabel":      r.env_label,
        "securityTools": r.security_tools or [],
        "categories":    r.categories or [],
        "score":         r.score,
        "startedAt":     r.started_at.isoformat() if r.started_at else None,
        "lastUpdate":    r.last_update.isoformat() if r.last_update else None,
    }


def _run_to_dict(r: ScenarioRun) -> dict:
    return {
        "id":          r.id,
        "scenarioId":  r.scenario_id,
        "agentId":     r.agent_id,
        "name":        r.name,
        "status":      r.status,
        "results":     r.results or [],
        "score":       r.score,
        "startedAt":   r.started_at.isoformat() if r.started_at else None,
        "completedAt": r.completed_at.isoformat() if r.completed_at else None,
    }


def _results_to_checks(results: list[dict]) -> list[dict]:
    """Convert SimulationResult list to SimCheck format for the scoring engine."""
    return [
        {
            "result":   r.get("result", "Skipped"),
            "severity": r.get("severity", "Medium"),
        }
        for r in results
    ]
