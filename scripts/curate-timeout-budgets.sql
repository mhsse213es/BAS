-- Step C of the Timeout Scored As PASS project (plan A -> C -> B).
-- Curates per-technique ExecuteSec from OBSERVED StepTermination data
-- (agent/executor.go's cappedBuffer + the termination marker, commit
-- 95937c5), not intuition. See memory: project_timeout_scored_as_pass.md.
--
-- Data source: scenario_runs.results is a JSONB array of models.SimulationResult.
-- Each element MAY carry a "termination" object (nil for a step that exited
-- on its own, or for pre-95937c5 agents) with: reason, elapsedMs,
-- outputBytes, silenceMs. Only rows where termination IS NOT NULL are steps
-- the agent itself killed -- i.e. every technique that has ever timed out.
--
-- Usage:
--   psql -U bas_user -d bas_platform -f curate-timeout-budgets.sql
-- or inside the container:
--   docker exec -it audspect-postgres psql -U bas_user -d bas_platform -f /path/curate-timeout-budgets.sql

-- ── Per-technique termination summary ───────────────────────────────────────
-- One row per technique that has AT LEAST ONE recorded termination. Empty
-- result set means: no technique has hit its execute deadline since 95937c5
-- was deployed -- not enough runs yet, not "nothing ever times out".
WITH terminated_steps AS (
    SELECT
        sr.id                                              AS run_id,
        sr.scenario_id,
        step ->> 'technique' AS technique_raw,                 -- {"id":"T1083","name":"..."}
        (step -> 'technique' ->> 'id')                    AS technique_id,
        (step -> 'termination' ->> 'reason')               AS term_reason,
        (step -> 'termination' ->> 'elapsedMs')::bigint    AS elapsed_ms,
        (step -> 'termination' ->> 'outputBytes')::bigint  AS output_bytes,
        (step -> 'termination' ->> 'silenceMs')::bigint    AS silence_ms
    FROM scenario_runs sr,
         LATERAL jsonb_array_elements(sr.results) AS step
    WHERE sr.results IS NOT NULL
      AND step -> 'termination' IS NOT NULL
)
SELECT
    technique_id,
    COUNT(*)                                          AS timeout_count,
    ROUND(AVG(elapsed_ms))                             AS avg_elapsed_ms,
    PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY elapsed_ms) AS p50_elapsed_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY elapsed_ms) AS p95_elapsed_ms,
    MAX(elapsed_ms)                                     AS max_elapsed_ms,
    ROUND(AVG(output_bytes))                            AS avg_output_bytes_at_timeout,
    ROUND(AVG(silence_ms))                              AS avg_silence_ms,
    -- A step silent for its whole run (silence_ms ~= elapsed_ms) was likely
    -- wedged, not slow-but-working -- see feedback in project memory: output
    -- is evidence of activity, not proof of progress, but zero output for
    -- the ENTIRE window is the strongest signal available that this
    -- technique's SIMULATION (not the real-world technique) may be
    -- misbehaved rather than merely needing more time (Hypothesis from the
    -- 2026-09-04 follow-up: "may reveal some 'hung' techniques are badly
    -- behaved simulations to fix rather than give more time").
    ROUND(100.0 * COUNT(*) FILTER (WHERE silence_ms >= elapsed_ms - 100) / COUNT(*), 1) AS pct_fully_silent
FROM terminated_steps
WHERE technique_id IS NOT NULL AND technique_id != ''
GROUP BY technique_id
ORDER BY timeout_count DESC, p95_elapsed_ms DESC;

-- ── Overall summary: how much data exists at all ────────────────────────────
-- Run this first if the query above returns zero rows, to confirm whether
-- that's "no timeouts yet" or "no runs on a post-95937c5 agent yet".
SELECT
    COUNT(*) FILTER (WHERE step -> 'termination' IS NOT NULL) AS total_terminations_recorded,
    COUNT(*)                                                   AS total_steps_recorded,
    COUNT(DISTINCT sr.id)                                      AS total_runs_scanned,
    MIN(sr.started_at)                                         AS earliest_run,
    MAX(sr.started_at)                                         AS latest_run
FROM scenario_runs sr,
     LATERAL jsonb_array_elements(sr.results) AS step
WHERE sr.results IS NOT NULL;
