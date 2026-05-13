from sqlalchemy import Column, String, Boolean, DateTime, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from database import Base


class Agent(Base):
    __tablename__ = "agents"

    agent_id    = Column(String, primary_key=True)
    hostname    = Column(String, default="")
    ip_address  = Column(String, default="")
    os_version  = Column(String, default="")
    username    = Column(String, default="")
    status      = Column(String, default="idle")
    env_label   = Column(String, default="Production")
    has_report  = Column(Boolean, default=False)
    last_update = Column(DateTime(timezone=True), server_default=func.now())


class Report(Base):
    __tablename__ = "reports"

    agent_id       = Column(String, primary_key=True)
    hostname       = Column(String, default="")
    ip_address     = Column(String, default="")
    os_version     = Column(String, default="")
    username       = Column(String, default="")
    started_at     = Column(DateTime(timezone=True), server_default=func.now())
    status         = Column(String, default="Completed")
    env_label      = Column(String, default="Production")
    security_tools = Column(JSONB, default=list)
    categories     = Column(JSONB, default=list)
    score          = Column(JSONB, nullable=True)
    last_update    = Column(DateTime(timezone=True), server_default=func.now())


class ScenarioRun(Base):
    __tablename__ = "scenario_runs"

    id           = Column(String, primary_key=True)
    scenario_id  = Column(String, nullable=False)
    agent_id     = Column(String, nullable=False)
    name         = Column(String, default="")
    status       = Column(String, default="running")
    results      = Column(JSONB, default=list)
    score        = Column(JSONB, nullable=True)
    started_at   = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)


class User(Base):
    __tablename__ = "users"

    id            = Column(String, primary_key=True)
    username      = Column(String, unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    role          = Column(String, default="analyst")
    created_at    = Column(DateTime(timezone=True), server_default=func.now())
    last_login    = Column(DateTime(timezone=True), nullable=True)
