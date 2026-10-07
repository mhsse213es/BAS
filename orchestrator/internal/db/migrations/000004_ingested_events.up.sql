-- Idempotency ledger for the generic inbound security-event ingestion API
-- (internal/ingest): one row per (source, external_event_id) a customer's
-- SIEM/SOAR/ITSM tooling has submitted, so a retried delivery is recorded
-- once. ioc_id is nullable: an event with no IOC payload is still recorded
-- here so a retry is still rejected as a duplicate, even though it produced
-- no iocs row.
CREATE TABLE ingested_events (
    id                 BIGSERIAL PRIMARY KEY,
    source             TEXT NOT NULL,
    external_event_id  TEXT NOT NULL,
    ioc_id             TEXT REFERENCES iocs(id) ON DELETE SET NULL,
    received_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(source, external_event_id)
);
CREATE INDEX idx_ingested_events_received ON ingested_events(received_at);
