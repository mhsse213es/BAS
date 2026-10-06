-- 000001 baseline, captured 2026-10-06 by tools/h1-capture-baseline from internal/db/legacy (frozen).
-- Never edit: schema changes are new migrations (README.md).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE action_connectors (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    name text NOT NULL,
    provider text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    tenant_id text DEFAULT ''::text NOT NULL,
    client_id text DEFAULT ''::text NOT NULL,
    client_secret text DEFAULT ''::text NOT NULL,
    base_url text DEFAULT ''::text NOT NULL,
    kill_process_script_name text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE action_requests (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    type text NOT NULL,
    target_type text NOT NULL,
    target_identifier text NOT NULL,
    parameters jsonb DEFAULT '{}'::jsonb NOT NULL,
    connector_id text NOT NULL,
    status text NOT NULL,
    resolved_device_id text DEFAULT ''::text NOT NULL,
    vendor_request_id text DEFAULT ''::text NOT NULL,
    error text DEFAULT ''::text NOT NULL,
    requested_by text DEFAULT ''::text NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    ticket_ref text DEFAULT ''::text NOT NULL,
    run_id text DEFAULT ''::text NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    dispatched_at timestamp with time zone,
    completed_at timestamp with time zone
);

CREATE TABLE agent_certificates (
    serial_number text NOT NULL,
    agent_id text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked boolean DEFAULT false NOT NULL,
    revoked_at timestamp with time zone,
    command_signing_key_id text
);

CREATE TABLE agent_groups (
    id bigint NOT NULL,
    name text NOT NULL,
    parent_id bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE agent_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE agent_groups_id_seq OWNED BY agent_groups.id;

CREATE TABLE agent_maintenance_freezes (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    agent_id text NOT NULL,
    from_at timestamp with time zone NOT NULL,
    to_at timestamp with time zone NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE agent_op_logs (
    id bigint NOT NULL,
    agent_id text NOT NULL,
    level text DEFAULT 'info'::text NOT NULL,
    category text DEFAULT 'lifecycle'::text NOT NULL,
    message text NOT NULL,
    seq bigint DEFAULT 0 NOT NULL,
    schema_ver integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE SEQUENCE agent_op_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE agent_op_logs_id_seq OWNED BY agent_op_logs.id;

CREATE TABLE agent_sec_logs (
    id bigint NOT NULL,
    agent_id text NOT NULL,
    level text DEFAULT 'info'::text NOT NULL,
    scenario_id text DEFAULT ''::text NOT NULL,
    run_id text DEFAULT ''::text NOT NULL,
    step_id text DEFAULT ''::text NOT NULL,
    technique_id text DEFAULT ''::text NOT NULL,
    category text DEFAULT 'scenario_step'::text NOT NULL,
    message text NOT NULL,
    seq bigint DEFAULT 0 NOT NULL,
    schema_ver integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE SEQUENCE agent_sec_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE agent_sec_logs_id_seq OWNED BY agent_sec_logs.id;

CREATE TABLE agent_telemetry (
    id bigint NOT NULL,
    agent_id text NOT NULL,
    metric text NOT NULL,
    value double precision NOT NULL,
    unit text DEFAULT ''::text NOT NULL,
    seq bigint DEFAULT 0 NOT NULL,
    schema_ver integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE SEQUENCE agent_telemetry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE agent_telemetry_id_seq OWNED BY agent_telemetry.id;

CREATE TABLE agents (
    agent_id text NOT NULL,
    hostname text DEFAULT ''::text NOT NULL,
    ip_address text DEFAULT ''::text NOT NULL,
    os_version text DEFAULT ''::text NOT NULL,
    username text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'idle'::text NOT NULL,
    env_label text DEFAULT 'Production'::text NOT NULL,
    has_report boolean DEFAULT false NOT NULL,
    binary_hash text DEFAULT ''::text NOT NULL,
    binary_trusted boolean DEFAULT false NOT NULL,
    last_update timestamp with time zone DEFAULT now() NOT NULL,
    state text DEFAULT 'active'::text NOT NULL,
    policy_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    enrolled_at timestamp with time zone,
    protocol_version integer DEFAULT 1 NOT NULL,
    security_products jsonb DEFAULT '[]'::jsonb NOT NULL,
    posture_catalog jsonb DEFAULT '{}'::jsonb NOT NULL,
    stopped_by text,
    stopped_at timestamp with time zone,
    stop_reason text,
    domain_joined boolean,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    transport text DEFAULT 'legacy'::text NOT NULL,
    group_id bigint,
    uninstall_requested_by text,
    uninstall_requested_at timestamp with time zone,
    uninstall_reason text,
    uninstall_prior_state text,
    uninstall_error text,
    uninstall_error_at timestamp with time zone
);

CREATE TABLE art_atomic_raw (
    technique_id text NOT NULL,
    yaml text NOT NULL,
    content_hash text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    import_version integer DEFAULT 1 NOT NULL
);

CREATE TABLE art_atomic_tests (
    id bigint NOT NULL,
    technique_id text NOT NULL,
    test_index integer NOT NULL,
    name text NOT NULL,
    executor text NOT NULL,
    command text NOT NULL,
    cleanup text DEFAULT ''::text NOT NULL,
    platform text DEFAULT 'windows'::text NOT NULL,
    timeout_sec integer DEFAULT 120 NOT NULL,
    required_payloads text[] DEFAULT '{}'::text[] NOT NULL,
    framework text DEFAULT 'art'::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    requires_priv text DEFAULT ''::text NOT NULL,
    original_elevation_required boolean DEFAULT false NOT NULL
);

CREATE SEQUENCE art_atomic_tests_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE art_atomic_tests_id_seq OWNED BY art_atomic_tests.id;

CREATE TABLE art_content_meta (
    id integer DEFAULT 1 NOT NULL,
    source_version text DEFAULT ''::text NOT NULL,
    technique_count integer DEFAULT 0 NOT NULL,
    payload_count integer DEFAULT 0 NOT NULL,
    source text DEFAULT ''::text NOT NULL,
    imported_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT art_content_meta_id_check CHECK ((id = 1))
);

CREATE TABLE art_payloads (
    basename text NOT NULL,
    sha256 text NOT NULL,
    size_bytes bigint NOT NULL,
    storage_path text NOT NULL,
    payload_type text DEFAULT ''::text NOT NULL,
    source text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE attackpath_asset_tags (
    host_key text NOT NULL,
    label text DEFAULT ''::text NOT NULL,
    crown_jewel text DEFAULT ''::text NOT NULL,
    segment text DEFAULT ''::text NOT NULL,
    high_value boolean DEFAULT false NOT NULL,
    criticality_tier text DEFAULT ''::text NOT NULL,
    internet_facing boolean DEFAULT false NOT NULL,
    identity_exposed boolean DEFAULT false NOT NULL,
    production boolean DEFAULT false NOT NULL,
    compliance_scope text[] DEFAULT '{}'::text[] NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE attackpath_collection_history (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    agent_id text NOT NULL,
    hostname text DEFAULT ''::text NOT NULL,
    source text DEFAULT 'agent'::text NOT NULL,
    collected_at timestamp with time zone NOT NULL,
    node_count integer DEFAULT 0 NOT NULL,
    edge_count integer DEFAULT 0 NOT NULL,
    sharphound boolean DEFAULT false NOT NULL,
    duration_ms bigint DEFAULT 0 NOT NULL,
    status text DEFAULT 'completed'::text NOT NULL,
    error_msg text DEFAULT ''::text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE attackpath_collection_requests (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    agent_id text NOT NULL,
    targets jsonb DEFAULT '[]'::jsonb NOT NULL,
    run_sharphound boolean DEFAULT false NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE attackpath_collections (
    agent_id text NOT NULL,
    hostname text DEFAULT ''::text NOT NULL,
    source text DEFAULT 'agent'::text NOT NULL,
    collected_at timestamp with time zone DEFAULT now() NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE attackpath_jobs (
    id text NOT NULL,
    agent_id text NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    dispatched_at timestamp with time zone,
    ack_at timestamp with time zone,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    last_heartbeat_at timestamp with time zone,
    attempts integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    error text DEFAULT ''::text NOT NULL,
    progress jsonb DEFAULT '{}'::jsonb NOT NULL,
    metrics jsonb DEFAULT '{}'::jsonb NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE attackpath_schedule (
    id integer DEFAULT 1 NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    interval_minutes integer DEFAULT 1440 NOT NULL,
    targets jsonb DEFAULT '[]'::jsonb NOT NULL,
    segment text DEFAULT ''::text NOT NULL,
    run_sharphound boolean DEFAULT false NOT NULL,
    last_run_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    CONSTRAINT attackpath_schedule_singleton CHECK ((id = 1))
);

CREATE TABLE audit_logs (
    id bigint NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    actor_id text DEFAULT ''::text NOT NULL,
    action text NOT NULL,
    resource text DEFAULT ''::text NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    ip text DEFAULT ''::text NOT NULL,
    outcome text DEFAULT 'ok'::text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE SEQUENCE audit_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE audit_logs_id_seq OWNED BY audit_logs.id;

CREATE TABLE backup_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    job_type text NOT NULL,
    trigger text NOT NULL,
    requested_by text,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    status text DEFAULT 'requested'::text NOT NULL,
    archive_filename text,
    archive_size_bytes bigint,
    sha256 text,
    local_path text,
    remote_path text,
    error_message text,
    restore_of_id uuid,
    manifest jsonb,
    CONSTRAINT backup_jobs_job_type_check CHECK ((job_type = ANY (ARRAY['backup'::text, 'restore_marker'::text]))),
    CONSTRAINT backup_jobs_status_check CHECK ((status = ANY (ARRAY['requested'::text, 'running'::text, 'protected'::text, 'local_success'::text, 'remote_failed'::text, 'failed'::text]))),
    CONSTRAINT backup_jobs_trigger_check CHECK ((trigger = ANY (ARRAY['console'::text, 'scheduled'::text, 'cli'::text, 'pre_restore'::text])))
);

CREATE TABLE campaign_variant_summary (
    campaign_id text NOT NULL,
    techniques_tested integer DEFAULT 0 NOT NULL,
    variants_executed integer DEFAULT 0 NOT NULL,
    blocked integer DEFAULT 0 NOT NULL,
    detected integer DEFAULT 0 NOT NULL,
    bypassed integer DEFAULT 0 NOT NULL,
    run_count integer DEFAULT 0 NOT NULL,
    prevention_score double precision DEFAULT 0 NOT NULL,
    detection_score double precision DEFAULT 0 NOT NULL,
    top_bypasses jsonb DEFAULT '[]'::jsonb NOT NULL,
    tactic_breakdown jsonb DEFAULT '[]'::jsonb NOT NULL,
    prev_bypassed integer,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE campaigns (
    id text NOT NULL,
    name text NOT NULL,
    scenario_id text NOT NULL,
    scenario_name text DEFAULT ''::text NOT NULL,
    mode text DEFAULT 'posture'::text NOT NULL,
    subset jsonb DEFAULT '{}'::jsonb NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    targets jsonb DEFAULT '[]'::jsonb NOT NULL,
    skips jsonb DEFAULT '[]'::jsonb NOT NULL,
    notes text DEFAULT ''::text NOT NULL,
    tags jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    stopped_at timestamp with time zone,
    target_type text DEFAULT 'agents'::text NOT NULL,
    target_group_id bigint,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE compliance_snapshots (
    agent_id text NOT NULL,
    framework_id text NOT NULL,
    snapshot_at timestamp with time zone DEFAULT now() NOT NULL,
    run_count integer DEFAULT 0 NOT NULL,
    compliance_pct numeric(5,2) DEFAULT 0 NOT NULL,
    coverage_pct numeric(5,2) DEFAULT 0 NOT NULL,
    total_controls integer DEFAULT 0 NOT NULL,
    testable_controls integer DEFAULT 0 NOT NULL,
    tested_controls integer DEFAULT 0 NOT NULL,
    passing_controls integer DEFAULT 0 NOT NULL,
    failing_controls integer DEFAULT 0 NOT NULL,
    manual_controls integer DEFAULT 0 NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE cve_epss (
    cve_id text NOT NULL,
    epss_score real DEFAULT 0 NOT NULL,
    percentile real DEFAULT 0 NOT NULL,
    score_date date,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE cves (
    cve_id text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    cvss real,
    published date,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    vendor text DEFAULT ''::text NOT NULL,
    product text DEFAULT ''::text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    date_added date,
    known_ransomware boolean DEFAULT false NOT NULL,
    source text DEFAULT ''::text NOT NULL
);

CREATE TABLE dashboard_snapshots (
    id bigint NOT NULL,
    snapshot_date date NOT NULL,
    avg_risk_score integer NOT NULL,
    exposure_score integer NOT NULL,
    detection_coverage integer NOT NULL,
    asset_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE SEQUENCE dashboard_snapshots_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE dashboard_snapshots_id_seq OWNED BY dashboard_snapshots.id;

CREATE TABLE detection_connectors (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    name text NOT NULL,
    provider text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    auto_verify boolean DEFAULT false NOT NULL,
    azure_tenant_id text DEFAULT ''::text NOT NULL,
    client_id text DEFAULT ''::text NOT NULL,
    client_secret text DEFAULT ''::text NOT NULL,
    workspace_id text DEFAULT ''::text NOT NULL,
    base_url text DEFAULT ''::text NOT NULL,
    api_token text DEFAULT ''::text NOT NULL,
    verify_delay_seconds integer DEFAULT 120 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    insecure_tls boolean DEFAULT false NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE dlp_sink_receipts (
    id bigint NOT NULL,
    token text NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    source_ip text DEFAULT ''::text NOT NULL,
    payload_hash text DEFAULT ''::text NOT NULL,
    payload_size integer DEFAULT 0 NOT NULL,
    channel text DEFAULT ''::text NOT NULL
);

CREATE SEQUENCE dlp_sink_receipts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE dlp_sink_receipts_id_seq OWNED BY dlp_sink_receipts.id;

CREATE TABLE dlp_sink_tokens (
    token text NOT NULL,
    run_id text NOT NULL,
    technique_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

CREATE TABLE em_sweeps (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    agent_id text NOT NULL,
    layers text[] NOT NULL,
    current_index integer DEFAULT 0 NOT NULL,
    current_scenario_run_id text DEFAULT ''::text NOT NULL,
    current_layer_started_at timestamp with time zone,
    completed_layers integer DEFAULT 0 NOT NULL,
    total_layers integer DEFAULT 0 NOT NULL,
    status text DEFAULT 'running'::text NOT NULL,
    error text DEFAULT ''::text NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    disconnected_at timestamp with time zone
);

CREATE TABLE execution_attempts (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    source text NOT NULL,
    granularity text NOT NULL,
    source_execution_id text NOT NULL,
    source_attempt_id text NOT NULL,
    technique_id text,
    status text NOT NULL,
    skip_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    dispatch_queued_at timestamp with time zone,
    dispatch_sent_at timestamp with time zone,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    decision_at timestamp with time zone,
    result jsonb,
    CONSTRAINT execution_attempts_decision_at_ck CHECK ((((status = 'skipped'::text) AND (decision_at IS NOT NULL)) OR ((status <> 'skipped'::text) AND (decision_at IS NULL)))),
    CONSTRAINT execution_attempts_granularity_check CHECK ((granularity = ANY (ARRAY['run'::text, 'step'::text]))),
    CONSTRAINT execution_attempts_skip_reason_ck CHECK ((((status = 'skipped'::text) AND (skip_reason IS NOT NULL)) OR ((status <> 'skipped'::text) AND (skip_reason IS NULL)))),
    CONSTRAINT execution_attempts_source_check CHECK ((source = ANY (ARRAY['art'::text, 'caldera'::text, 'exercise'::text]))),
    CONSTRAINT execution_attempts_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'dispatched'::text, 'running'::text, 'completed'::text, 'timed_out'::text, 'cancelled'::text, 'abandoned'::text, 'failed_to_dispatch'::text, 'skipped'::text])))
);

CREATE TABLE exercise_events (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    execution_id text NOT NULL,
    step_id text,
    event_type text NOT NULL,
    actor text DEFAULT ''::text NOT NULL,
    detail_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE exercise_evidence (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    execution_id text NOT NULL,
    step_execution_id text,
    seq bigint NOT NULL,
    evidence_type text NOT NULL,
    actor text DEFAULT ''::text NOT NULL,
    source text DEFAULT ''::text NOT NULL,
    payload_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    sha256 text NOT NULL,
    prev_hash text DEFAULT ''::text NOT NULL,
    signature text DEFAULT ''::text NOT NULL,
    retention_policy text DEFAULT '90d'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE exercise_executions (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    plan_id text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'draft'::text NOT NULL,
    initiated_by text DEFAULT ''::text NOT NULL,
    targets_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    metadata_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    variables_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    plan_version integer DEFAULT 1 NOT NULL,
    score_json jsonb,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    execution_policy_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE exercise_plans (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    steps_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    variables_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    template_id text,
    version integer DEFAULT 1 NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE exercise_step_executions (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    execution_id text NOT NULL,
    step_id text NOT NULL,
    step_type text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempt integer DEFAULT 0 NOT NULL,
    scheduled_at timestamp with time zone,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    result_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    error_msg text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE exercise_templates (
    id text NOT NULL,
    name text NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    category text DEFAULT ''::text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    variables_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    steps_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    built_in boolean DEFAULT false NOT NULL,
    author text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    metadata_json jsonb DEFAULT '{}'::jsonb NOT NULL
);

CREATE TABLE exercise_track_tokens (
    token text NOT NULL,
    execution_id text NOT NULL,
    step_exec_id text NOT NULL,
    target_id text DEFAULT ''::text NOT NULL,
    token_type text NOT NULL,
    payload_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    used_count integer DEFAULT 0 NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE exercise_webhook_calls (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    token text NOT NULL,
    execution_id text NOT NULL,
    step_exec_id text DEFAULT ''::text NOT NULL,
    body bytea,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE finding_slas (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    posture_finding_id text NOT NULL,
    severity_at_start text NOT NULL,
    started_at timestamp with time zone NOT NULL,
    deadline_at timestamp with time zone NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    breached_at timestamp with time zone,
    resolved_at timestamp with time zone
);

CREATE TABLE finding_tickets (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    finding_id text NOT NULL,
    config_id text NOT NULL,
    ticket_id text NOT NULL,
    ticket_url text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'open'::text NOT NULL,
    revalidation_required boolean DEFAULT false NOT NULL,
    last_synced_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revalidation_dispatched_at timestamp with time zone,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE findings (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    agent_id text NOT NULL,
    technique_id text NOT NULL,
    control_class text NOT NULL,
    technique_name text DEFAULT ''::text NOT NULL,
    tactic text DEFAULT ''::text NOT NULL,
    severity text DEFAULT 'Medium'::text NOT NULL,
    exposure_state text DEFAULT 'missed'::text NOT NULL,
    status text DEFAULT 'open'::text NOT NULL,
    source_type text DEFAULT ''::text NOT NULL,
    attack_data_source jsonb DEFAULT '[]'::jsonb NOT NULL,
    security_product_snapshot jsonb DEFAULT '[]'::jsonb NOT NULL,
    occurrence_count integer DEFAULT 1 NOT NULL,
    reopened_count integer DEFAULT 0 NOT NULL,
    last_run_id text,
    last_campaign_id text,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_observed_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by text,
    resolved_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE initiatives (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    state text DEFAULT 'active'::text NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    closed_at timestamp with time zone,
    archived_at timestamp with time zone
);

CREATE TABLE intelligence_campaigns (
    id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    actor_ids text[] DEFAULT '{}'::text[] NOT NULL,
    technique_ids text[] DEFAULT '{}'::text[] NOT NULL,
    source_provider text NOT NULL,
    source_external_id text DEFAULT ''::text NOT NULL,
    source_confidence text DEFAULT ''::text NOT NULL,
    last_updated timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    aliases text[] DEFAULT '{}'::text[] NOT NULL,
    search_key text[] DEFAULT '{}'::text[] NOT NULL
);

CREATE TABLE intelligence_entity_sources (
    id bigint NOT NULL,
    entity_type text NOT NULL,
    entity_id text NOT NULL,
    provider text NOT NULL,
    external_id text NOT NULL,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_sync timestamp with time zone NOT NULL,
    confidence text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE SEQUENCE intelligence_entity_sources_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE intelligence_entity_sources_id_seq OWNED BY intelligence_entity_sources.id;

CREATE TABLE intelligence_malware (
    id text NOT NULL,
    name text NOT NULL,
    aliases text[] DEFAULT '{}'::text[] NOT NULL,
    technique_ids text[] DEFAULT '{}'::text[] NOT NULL,
    actor_ids text[] DEFAULT '{}'::text[] NOT NULL,
    campaign_ids text[] DEFAULT '{}'::text[] NOT NULL,
    source_provider text NOT NULL,
    source_external_id text DEFAULT ''::text NOT NULL,
    source_confidence text DEFAULT ''::text NOT NULL,
    last_updated timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE intelligence_tools (
    id text NOT NULL,
    name text NOT NULL,
    aliases text[] DEFAULT '{}'::text[] NOT NULL,
    technique_ids text[] DEFAULT '{}'::text[] NOT NULL,
    actor_ids text[] DEFAULT '{}'::text[] NOT NULL,
    campaign_ids text[] DEFAULT '{}'::text[] NOT NULL,
    source_provider text NOT NULL,
    source_external_id text DEFAULT ''::text NOT NULL,
    source_confidence text DEFAULT ''::text NOT NULL,
    last_updated timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE ioc_enrichment (
    id bigint NOT NULL,
    indicator_type text NOT NULL,
    indicator_value text NOT NULL,
    provider text NOT NULL,
    provider_version text DEFAULT ''::text NOT NULL,
    schema_version smallint DEFAULT 1 NOT NULL,
    pulse_count integer DEFAULT 0 NOT NULL,
    pulse_names jsonb DEFAULT '[]'::jsonb NOT NULL,
    malware_families jsonb DEFAULT '[]'::jsonb NOT NULL,
    adversary_names jsonb DEFAULT '[]'::jsonb NOT NULL,
    industries jsonb DEFAULT '[]'::jsonb NOT NULL,
    tags jsonb DEFAULT '[]'::jsonb NOT NULL,
    raw_response jsonb,
    lookup_duration_ms integer,
    last_success_at timestamp with time zone,
    last_failure_at timestamp with time zone,
    last_error text,
    ttl_expires_at timestamp with time zone NOT NULL
);

CREATE SEQUENCE ioc_enrichment_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE ioc_enrichment_id_seq OWNED BY ioc_enrichment.id;

CREATE TABLE ioc_sightings (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    ioc_id text NOT NULL,
    scenario_id text DEFAULT ''::text NOT NULL,
    run_id text DEFAULT ''::text NOT NULL,
    agent_id text DEFAULT ''::text NOT NULL,
    observed_at timestamp with time zone DEFAULT now() NOT NULL,
    technique_id text DEFAULT ''::text NOT NULL,
    detection_verdict text DEFAULT ''::text NOT NULL
);

CREATE TABLE iocs (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    type text NOT NULL,
    value text NOT NULL,
    source text NOT NULL,
    origin text DEFAULT 'built-in'::text NOT NULL,
    status text DEFAULT 'observed'::text NOT NULL,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    sighting_count integer DEFAULT 1 NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    suppressed boolean DEFAULT false NOT NULL,
    suppression_reason text DEFAULT ''::text NOT NULL
);

CREATE TABLE job_schedules (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    type text NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    agent_ids jsonb NOT NULL,
    day_of_week integer NOT NULL,
    time_of_day text NOT NULL,
    timezone text DEFAULT 'UTC'::text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_occurrence_at timestamp with time zone,
    last_spawned_job_id text DEFAULT ''::text NOT NULL,
    recurrence_type text DEFAULT ''::text NOT NULL,
    run_at timestamp with time zone,
    day_of_month integer DEFAULT 0 NOT NULL,
    end_date timestamp with time zone,
    concurrency_limit integer DEFAULT 0 NOT NULL,
    group_ids jsonb DEFAULT '[]'::jsonb NOT NULL,
    mode text DEFAULT ''::text NOT NULL,
    approved_by text DEFAULT ''::text NOT NULL,
    approved_at timestamp with time zone,
    approval_version integer DEFAULT 0 NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    initiative_id text DEFAULT ''::text NOT NULL
);

CREATE TABLE job_targets (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    job_id text NOT NULL,
    agent_id text NOT NULL,
    state text NOT NULL,
    ref_id text DEFAULT ''::text NOT NULL,
    error text DEFAULT ''::text NOT NULL,
    retry_count integer DEFAULT 0 NOT NULL,
    max_retries integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    owner_id text DEFAULT ''::text NOT NULL,
    assigned_at timestamp with time zone
);

CREATE TABLE jobs (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    type text NOT NULL,
    state text NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    scheduled_at timestamp with time zone,
    concurrency_limit integer DEFAULT 0 NOT NULL,
    initiative_id text DEFAULT ''::text NOT NULL
);

CREATE TABLE legacy_transport_log (
    agent_id text NOT NULL,
    day date NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    endpoint text NOT NULL
);

CREATE TABLE legacy_transport_unattributed (
    day date NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    request_count integer DEFAULT 1 NOT NULL
);

CREATE TABLE notification_webhooks (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    name text NOT NULL,
    url text NOT NULL,
    secret text DEFAULT ''::text NOT NULL,
    min_severity text DEFAULT 'warning'::text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE notifications (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    type text NOT NULL,
    job_id text,
    target_id text DEFAULT ''::text NOT NULL,
    agent_id text DEFAULT ''::text NOT NULL,
    severity text NOT NULL,
    message text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE openaev_bundles (
    id text NOT NULL,
    openaev_scenario_id text NOT NULL,
    bundle jsonb NOT NULL,
    content_hash text NOT NULL,
    size_bytes integer DEFAULT 0 NOT NULL,
    source_version integer DEFAULT 1 NOT NULL,
    synced_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE openaev_config (
    id integer DEFAULT 1 NOT NULL,
    base_url text DEFAULT ''::text NOT NULL,
    bearer_token text DEFAULT ''::text NOT NULL,
    poll_interval_hours integer DEFAULT 24 NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    last_sync_at timestamp with time zone,
    last_sync_status text DEFAULT 'never'::text NOT NULL,
    last_error text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    last_sync_created integer DEFAULT 0 NOT NULL,
    last_sync_updated integer DEFAULT 0 NOT NULL,
    last_sync_skipped integer DEFAULT 0 NOT NULL,
    last_sync_errored integer DEFAULT 0 NOT NULL,
    CONSTRAINT openaev_config_id_check CHECK ((id = 1))
);

CREATE TABLE openaev_scenarios (
    openaev_scenario_id text NOT NULL,
    name text NOT NULL,
    category text DEFAULT ''::text NOT NULL,
    severity text DEFAULT ''::text NOT NULL,
    platforms text[] DEFAULT '{}'::text[] NOT NULL,
    technique_ids text[] DEFAULT '{}'::text[] NOT NULL,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    objectives_count integer DEFAULT 0 NOT NULL,
    injects_count integer DEFAULT 0 NOT NULL,
    source_updated_at timestamp with time zone NOT NULL,
    content_hash text DEFAULT ''::text NOT NULL,
    bundle_id text,
    sync_revision integer DEFAULT 1 NOT NULL,
    imported_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    source_type text DEFAULT 'scenario'::text NOT NULL
);

CREATE TABLE owasp_risks (
    risk_id text NOT NULL,
    version text DEFAULT ''::text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    display_order integer DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE payload_families (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    technique_id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    payload text NOT NULL,
    purpose text DEFAULT 'recon'::text NOT NULL,
    risk_level text DEFAULT 'SAFE'::text NOT NULL,
    platform text DEFAULT 'windows'::text NOT NULL,
    executor text DEFAULT 'powershell'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tactic text DEFAULT ''::text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE posture_findings (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    agent_id text NOT NULL,
    check_id text NOT NULL,
    category text DEFAULT ''::text NOT NULL,
    title text DEFAULT ''::text NOT NULL,
    severity text DEFAULT 'Medium'::text NOT NULL,
    exposure_state text DEFAULT 'missed'::text NOT NULL,
    status text DEFAULT 'open'::text NOT NULL,
    occurrence_count integer DEFAULT 1 NOT NULL,
    reopened_count integer DEFAULT 0 NOT NULL,
    last_run_id text,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_observed_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    resolved_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE relationship_evidence (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    relationship_id text NOT NULL,
    source text DEFAULT 'Analyst'::text NOT NULL,
    reference_type text DEFAULT 'URL'::text NOT NULL,
    reference_value text DEFAULT ''::text NOT NULL,
    note text DEFAULT ''::text NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    added_by text DEFAULT ''::text NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted boolean DEFAULT false NOT NULL,
    deleted_by text DEFAULT ''::text NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE remediation_requests (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    remediation_id text NOT NULL,
    agent_id text NOT NULL,
    check_id text NOT NULL,
    tier integer NOT NULL,
    status text NOT NULL,
    fix_run_id text DEFAULT ''::text NOT NULL,
    verify_run_id text DEFAULT ''::text NOT NULL,
    error text DEFAULT ''::text NOT NULL,
    requested_by text DEFAULT ''::text NOT NULL,
    approved_by text DEFAULT ''::text NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    rollback_available boolean DEFAULT false NOT NULL,
    rollback_status text DEFAULT ''::text NOT NULL,
    rollback_run_id text DEFAULT ''::text NOT NULL,
    rollback_verify_run_id text DEFAULT ''::text NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    dispatched_at timestamp with time zone,
    execution_completed_at timestamp with time zone,
    verification_completed_at timestamp with time zone,
    completed_at timestamp with time zone,
    continuous_validation boolean DEFAULT false NOT NULL
);

CREATE TABLE report_log (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    report_type text NOT NULL,
    format text DEFAULT ''::text NOT NULL,
    scope_label text DEFAULT ''::text NOT NULL,
    parameters jsonb DEFAULT '{}'::jsonb NOT NULL,
    source text DEFAULT 'reports_hub'::text NOT NULL,
    status text DEFAULT 'generated'::text NOT NULL,
    generated_by text,
    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE run_events (
    run_id text NOT NULL,
    seq bigint NOT NULL,
    type text NOT NULL,
    task_id text DEFAULT ''::text NOT NULL,
    technique_id text DEFAULT ''::text NOT NULL,
    ts timestamp with time zone NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    step_name text DEFAULT ''::text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE run_iocs (
    id bigint NOT NULL,
    run_id text NOT NULL,
    scenario_id text NOT NULL,
    indicator_type text NOT NULL,
    indicator_value text NOT NULL,
    hash_algorithm text,
    confidence smallint NOT NULL,
    indicator_source text NOT NULL,
    offset_start integer NOT NULL,
    offset_end integer NOT NULL,
    technique_ids jsonb DEFAULT '[]'::jsonb NOT NULL,
    simulation_ids jsonb DEFAULT '[]'::jsonb NOT NULL,
    extracted_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE run_iocs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE run_iocs_id_seq OWNED BY run_iocs.id;

CREATE TABLE scenario_runs (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    scenario_id text NOT NULL,
    agent_id text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'running'::text NOT NULL,
    results jsonb DEFAULT '[]'::jsonb NOT NULL,
    score jsonb,
    initiated_by text,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    step_meta jsonb DEFAULT '{}'::jsonb NOT NULL,
    reverted jsonb DEFAULT '[]'::jsonb NOT NULL,
    variant_depth text DEFAULT 'none'::text NOT NULL,
    mode text DEFAULT ''::text NOT NULL,
    max_privilege text DEFAULT ''::text NOT NULL,
    paused boolean DEFAULT false NOT NULL,
    steps_total integer DEFAULT 0 NOT NULL,
    steps_done integer DEFAULT 0 NOT NULL,
    steps_running integer DEFAULT 0 NOT NULL,
    steps_passed integer DEFAULT 0 NOT NULL,
    steps_failed integer DEFAULT 0 NOT NULL,
    steps_timeout integer DEFAULT 0 NOT NULL,
    detections_raw jsonb DEFAULT '[]'::jsonb NOT NULL,
    detection_summary jsonb,
    detection_rate integer,
    undetected_rate integer,
    mttd_ms bigint,
    campaign_id text,
    leaked_steps integer DEFAULT 0 NOT NULL,
    hygiene_score double precision DEFAULT 100.0 NOT NULL,
    alerts_total integer DEFAULT 0 NOT NULL,
    alerts_high_fidelity integer DEFAULT 0 NOT NULL,
    noise_score double precision DEFAULT 0.0 NOT NULL,
    perf_cpu_before double precision DEFAULT 0.0 NOT NULL,
    perf_cpu_after double precision DEFAULT 0.0 NOT NULL,
    perf_ram_before double precision DEFAULT 0.0 NOT NULL,
    perf_ram_after double precision DEFAULT 0.0 NOT NULL,
    perf_disk_before double precision DEFAULT 0.0 NOT NULL,
    perf_disk_after double precision DEFAULT 0.0 NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    steps_total_base integer DEFAULT 0 NOT NULL,
    steps_eligible_base integer DEFAULT 0 NOT NULL,
    policy_skipped_results jsonb DEFAULT '[]'::jsonb NOT NULL,
    auto_verified boolean DEFAULT false NOT NULL,
    sweep_id text,
    em_sweep_id text,
    dispatch_subset jsonb,
    fail_reason text
);

CREATE TABLE scenario_techniques (
    scenario_id text NOT NULL,
    technique_id text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE scenario_variant_results (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    run_id text NOT NULL,
    scenario_id text NOT NULL,
    step_id text NOT NULL,
    variant_id text NOT NULL,
    technique_id text NOT NULL,
    proxy_technique_id text,
    encoding text DEFAULT 'plain'::text NOT NULL,
    privilege text DEFAULT 'user'::text NOT NULL,
    execution_context text DEFAULT 'direct'::text NOT NULL,
    platform text DEFAULT 'windows'::text NOT NULL,
    requested_privilege text,
    actual_privilege text,
    verdict text NOT NULL,
    duration_ms bigint,
    executed_at timestamp with time zone,
    raw_result jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE scenario_variant_technique_summary (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    run_id text NOT NULL,
    technique_id text NOT NULL,
    technique_name text DEFAULT ''::text NOT NULL,
    tactic text DEFAULT ''::text NOT NULL,
    variants_executed integer DEFAULT 0 NOT NULL,
    blocked integer DEFAULT 0 NOT NULL,
    detected integer DEFAULT 0 NOT NULL,
    logged integer DEFAULT 0 NOT NULL,
    bypassed integer DEFAULT 0 NOT NULL,
    errors integer DEFAULT 0 NOT NULL,
    skipped integer DEFAULT 0 NOT NULL,
    best_bypass_variant_id text,
    encodings_tested text[] DEFAULT '{}'::text[] NOT NULL,
    privileges_tested text[] DEFAULT '{}'::text[] NOT NULL,
    contexts_tested text[] DEFAULT '{}'::text[] NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE scenarios (
    scenario_id text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    category text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE scim_configs (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    tenant_id text NOT NULL,
    token_hash text NOT NULL,
    default_role text DEFAULT 'viewer'::text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE search_documents (
    id bigint NOT NULL,
    doc_type text NOT NULL,
    source_id text NOT NULL,
    title text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    search_vector tsvector NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE SEQUENCE search_documents_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE search_documents_id_seq OWNED BY search_documents.id;

CREATE TABLE search_favorites (
    id bigint NOT NULL,
    user_id text NOT NULL,
    doc_type text NOT NULL,
    source_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE search_favorites_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE search_favorites_id_seq OWNED BY search_favorites.id;

CREATE TABLE search_selections (
    id bigint NOT NULL,
    user_id text NOT NULL,
    doc_type text NOT NULL,
    source_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE search_selections_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE search_selections_id_seq OWNED BY search_selections.id;

CREATE TABLE siem_configs (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    name text NOT NULL,
    provider text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    console_url text DEFAULT ''::text NOT NULL,
    token text DEFAULT ''::text NOT NULL,
    username text DEFAULT ''::text NOT NULL,
    password text DEFAULT ''::text NOT NULL,
    tenant_id text DEFAULT ''::text NOT NULL,
    workspace_id text DEFAULT ''::text NOT NULL,
    client_id text DEFAULT ''::text NOT NULL,
    client_secret text DEFAULT ''::text NOT NULL,
    insecure_skip_verify boolean DEFAULT false NOT NULL,
    auto_correlate boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE siem_correlations (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    run_id text NOT NULL,
    config_id text NOT NULL,
    agent_id text NOT NULL,
    agent_ip text DEFAULT ''::text NOT NULL,
    provider text NOT NULL,
    window_start timestamp with time zone NOT NULL,
    window_end timestamp with time zone NOT NULL,
    total_alerts integer DEFAULT 0 NOT NULL,
    detected integer DEFAULT 0 NOT NULL,
    undetected integer DEFAULT 0 NOT NULL,
    not_executed integer DEFAULT 0 NOT NULL,
    detection_rate integer DEFAULT 0 NOT NULL,
    undetected_rate integer DEFAULT 0 NOT NULL,
    report_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    correlated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE sla_policy (
    severity text NOT NULL,
    duration_hours integer NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by text DEFAULT ''::text NOT NULL,
    CONSTRAINT sla_policy_duration_hours_check CHECK (((duration_hours > 0) AND (duration_hours <= 8760)))
);

CREATE TABLE sso_configs (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    tenant_id text NOT NULL,
    issuer_url text NOT NULL,
    client_id text NOT NULL,
    client_secret text NOT NULL,
    default_role text DEFAULT 'viewer'::text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE tactics (
    tactic_id text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    attack_id text DEFAULT ''::text NOT NULL,
    kill_chain_order integer DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE tamper_events (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    detected_at timestamp with time zone DEFAULT now() NOT NULL,
    path text NOT NULL,
    event_type text NOT NULL,
    severity text NOT NULL,
    acknowledged boolean DEFAULT false NOT NULL,
    acked_by text,
    acked_at timestamp with time zone,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE taxii_connector_config (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    name text NOT NULL,
    server_url text NOT NULL,
    api_root text DEFAULT ''::text NOT NULL,
    collection_id text DEFAULT ''::text NOT NULL,
    auth_type text DEFAULT 'none'::text NOT NULL,
    username text DEFAULT ''::text NOT NULL,
    password text DEFAULT ''::text NOT NULL,
    client_cert text DEFAULT ''::text NOT NULL,
    client_key text DEFAULT ''::text NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    last_poll_at timestamp with time zone,
    last_poll_status text DEFAULT 'never'::text NOT NULL,
    last_poll_summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    last_error text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    insecure_tls boolean DEFAULT false NOT NULL
);

CREATE TABLE taxii_ingested_objects (
    connector_id text NOT NULL,
    stix_id text NOT NULL,
    modified timestamp with time zone NOT NULL,
    ioc_id text NOT NULL,
    ingested_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE technique_cve_relationships (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    technique_id text NOT NULL,
    cve_id text NOT NULL,
    relationship_type text NOT NULL,
    proposed_confidence text DEFAULT 'Medium'::text NOT NULL,
    effective_confidence text DEFAULT 'Medium'::text NOT NULL,
    primary_source text DEFAULT 'Analyst'::text NOT NULL,
    rationale text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'Active'::text NOT NULL,
    status_changed_by text DEFAULT ''::text NOT NULL,
    status_changed_at timestamp with time zone,
    status_reason text DEFAULT ''::text NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    reviewed_by text DEFAULT ''::text NOT NULL,
    last_reviewed_at timestamp with time zone,
    review_due_at timestamp with time zone
);

CREATE TABLE technique_cves (
    technique_id text NOT NULL,
    cve_id text NOT NULL
);

CREATE TABLE technique_evidence (
    actor_name text NOT NULL,
    technique_id text NOT NULL,
    via text DEFAULT ''::text NOT NULL,
    via_name text DEFAULT ''::text NOT NULL,
    source text NOT NULL,
    confidence integer DEFAULT 0 NOT NULL,
    start_time timestamp with time zone,
    stop_time timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE technique_owasp (
    technique_id text NOT NULL,
    risk_id text NOT NULL
);

CREATE TABLE technique_verification_runs (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    request_id text NOT NULL,
    agent_id text NOT NULL,
    check_id text NOT NULL,
    technique_id text NOT NULL,
    engine text DEFAULT 'art'::text NOT NULL,
    run_id text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'requested'::text NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    requested_by text DEFAULT ''::text NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    dispatched_at timestamp with time zone,
    completed_at timestamp with time zone
);

CREATE TABLE techniques (
    technique_id text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    tactic text DEFAULT ''::text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE tenants (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE threat_actor_activity (
    actor_name text NOT NULL,
    source text NOT NULL,
    pulse_count integer DEFAULT 0 NOT NULL,
    first_observed timestamp with time zone,
    last_observed timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE threat_actor_profiles (
    name text NOT NULL,
    aliases text[] DEFAULT '{}'::text[] NOT NULL,
    sectors text[] DEFAULT '{}'::text[] NOT NULL,
    regions text[] DEFAULT '{}'::text[] NOT NULL,
    source text DEFAULT ''::text NOT NULL,
    last_seen timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    confidence text DEFAULT ''::text NOT NULL,
    canonical_group_id text DEFAULT ''::text NOT NULL,
    techniques text[] DEFAULT '{}'::text[] NOT NULL
);

CREATE TABLE threat_actor_sources (
    actor_name text NOT NULL,
    source text NOT NULL,
    source_id text DEFAULT ''::text NOT NULL,
    name text NOT NULL,
    aliases text[] DEFAULT '{}'::text[] NOT NULL,
    sectors text[] DEFAULT '{}'::text[] NOT NULL,
    regions text[] DEFAULT '{}'::text[] NOT NULL,
    confidence text DEFAULT ''::text NOT NULL,
    technique_count integer DEFAULT 0 NOT NULL,
    last_seen timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE threat_intel_config (
    connector text NOT NULL,
    base_url text DEFAULT ''::text NOT NULL,
    api_key text DEFAULT ''::text NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    last_sync_at timestamp with time zone,
    last_sync_status text DEFAULT 'never'::text NOT NULL,
    last_error text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    insecure_tls boolean DEFAULT false NOT NULL
);

CREATE TABLE threat_priority_history (
    id bigint NOT NULL,
    actor_name text NOT NULL,
    score integer NOT NULL,
    tier text DEFAULT ''::text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE threat_priority_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE threat_priority_history_id_seq OWNED BY threat_priority_history.id;

CREATE TABLE threat_readiness_history (
    id bigint NOT NULL,
    run_id text NOT NULL,
    agent_id text NOT NULL,
    actor_name text NOT NULL,
    prevention real DEFAULT 0 NOT NULL,
    detection real DEFAULT 0 NOT NULL,
    tested integer DEFAULT 0 NOT NULL,
    total integer DEFAULT 0 NOT NULL,
    confidence text DEFAULT ''::text NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE SEQUENCE threat_readiness_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE threat_readiness_history_id_seq OWNED BY threat_readiness_history.id;

CREATE TABLE ticketing_configs (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    name text NOT NULL,
    provider text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    auto_create text DEFAULT 'off'::text NOT NULL,
    auto_update boolean DEFAULT true NOT NULL,
    auto_close boolean DEFAULT true NOT NULL,
    settings jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_test_ok boolean,
    last_test_at timestamp with time zone,
    last_test_error text DEFAULT ''::text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE users (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    username text NOT NULL,
    password_hash text NOT NULL,
    role text DEFAULT 'analyst'::text NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    must_change_pw boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login timestamp with time zone,
    tenant_id text DEFAULT 'default'::text,
    auth_source text DEFAULT 'local'::text NOT NULL
);

CREATE TABLE variant_findings (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    variant_run_id text NOT NULL,
    task_id text NOT NULL,
    technique_id text NOT NULL,
    encoding text NOT NULL,
    exec_context text NOT NULL,
    evasion text NOT NULL,
    risk_level text DEFAULT 'SAFE'::text NOT NULL,
    gap_summary text DEFAULT ''::text NOT NULL,
    recommendation text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE variant_run_steps (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    variant_run_id text NOT NULL,
    task_id text NOT NULL,
    technique_id text NOT NULL,
    encoding text NOT NULL,
    exec_context text NOT NULL,
    evasion text NOT NULL,
    executor text NOT NULL,
    cmd_preview text DEFAULT ''::text NOT NULL,
    risk_level text DEFAULT 'SAFE'::text NOT NULL,
    variant_hash text DEFAULT ''::text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE variant_runs (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    agent_id text NOT NULL,
    technique_id text NOT NULL,
    base_type text DEFAULT 'art'::text NOT NULL,
    base_id text DEFAULT ''::text NOT NULL,
    scenario_run_id text NOT NULL,
    total_variants integer DEFAULT 0 NOT NULL,
    status text DEFAULT 'running'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    execution_mode text DEFAULT 'sequential'::text NOT NULL,
    generator_version text DEFAULT ''::text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE verification_evidence (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    verification_id text NOT NULL,
    storage_type text DEFAULT 'database'::text NOT NULL,
    storage_key text DEFAULT ''::text NOT NULL,
    hash_algorithm text DEFAULT 'SHA-256'::text NOT NULL,
    content_hash text DEFAULT ''::text NOT NULL,
    original_filename text DEFAULT ''::text NOT NULL,
    display_filename text DEFAULT ''::text NOT NULL,
    mime text DEFAULT ''::text NOT NULL,
    size bigint DEFAULT 0 NOT NULL,
    uploaded_by text DEFAULT ''::text NOT NULL,
    uploaded_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted boolean DEFAULT false NOT NULL,
    deleted_by text DEFAULT ''::text NOT NULL,
    deleted_at timestamp with time zone,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE verification_evidence_blob (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    bytes bytea NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE TABLE verification_history (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    run_id text NOT NULL,
    expectation_id text NOT NULL,
    profile_name text DEFAULT ''::text NOT NULL,
    profile_version integer DEFAULT 0 NOT NULL,
    technique_id text DEFAULT ''::text NOT NULL,
    domain text DEFAULT ''::text NOT NULL,
    provider text DEFAULT ''::text NOT NULL,
    result text DEFAULT ''::text NOT NULL,
    workflow_state text DEFAULT 'Pending'::text NOT NULL,
    verification_source text DEFAULT 'manual'::text NOT NULL,
    note text DEFAULT ''::text NOT NULL,
    alert_id text DEFAULT ''::text NOT NULL,
    verified_by text DEFAULT ''::text NOT NULL,
    verified_at timestamp with time zone DEFAULT now() NOT NULL,
    supersedes_id text DEFAULT ''::text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    rule_ids text[] DEFAULT '{}'::text[] NOT NULL
);

CREATE TABLE vex_sweeps (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    agent_id text NOT NULL,
    mode text DEFAULT 'sequential'::text NOT NULL,
    include_advanced boolean DEFAULT false NOT NULL,
    techniques text[] NOT NULL,
    technique_variant_counts integer[] NOT NULL,
    base_types text[] DEFAULT '{}'::text[] NOT NULL,
    base_ids text[] DEFAULT '{}'::text[] NOT NULL,
    current_index integer DEFAULT 0 NOT NULL,
    current_variant_run_id text DEFAULT ''::text NOT NULL,
    current_scenario_run_id text DEFAULT ''::text NOT NULL,
    current_technique_started_at timestamp with time zone,
    completed_variants integer DEFAULT 0 NOT NULL,
    total_variants integer DEFAULT 0 NOT NULL,
    status text DEFAULT 'running'::text NOT NULL,
    error text DEFAULT ''::text NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    disconnected_at timestamp with time zone
);

ALTER TABLE ONLY agent_groups ALTER COLUMN id SET DEFAULT nextval('agent_groups_id_seq'::regclass);

ALTER TABLE ONLY agent_op_logs ALTER COLUMN id SET DEFAULT nextval('agent_op_logs_id_seq'::regclass);

ALTER TABLE ONLY agent_sec_logs ALTER COLUMN id SET DEFAULT nextval('agent_sec_logs_id_seq'::regclass);

ALTER TABLE ONLY agent_telemetry ALTER COLUMN id SET DEFAULT nextval('agent_telemetry_id_seq'::regclass);

ALTER TABLE ONLY art_atomic_tests ALTER COLUMN id SET DEFAULT nextval('art_atomic_tests_id_seq'::regclass);

ALTER TABLE ONLY audit_logs ALTER COLUMN id SET DEFAULT nextval('audit_logs_id_seq'::regclass);

ALTER TABLE ONLY dashboard_snapshots ALTER COLUMN id SET DEFAULT nextval('dashboard_snapshots_id_seq'::regclass);

ALTER TABLE ONLY dlp_sink_receipts ALTER COLUMN id SET DEFAULT nextval('dlp_sink_receipts_id_seq'::regclass);

ALTER TABLE ONLY intelligence_entity_sources ALTER COLUMN id SET DEFAULT nextval('intelligence_entity_sources_id_seq'::regclass);

ALTER TABLE ONLY ioc_enrichment ALTER COLUMN id SET DEFAULT nextval('ioc_enrichment_id_seq'::regclass);

ALTER TABLE ONLY run_iocs ALTER COLUMN id SET DEFAULT nextval('run_iocs_id_seq'::regclass);

ALTER TABLE ONLY search_documents ALTER COLUMN id SET DEFAULT nextval('search_documents_id_seq'::regclass);

ALTER TABLE ONLY search_favorites ALTER COLUMN id SET DEFAULT nextval('search_favorites_id_seq'::regclass);

ALTER TABLE ONLY search_selections ALTER COLUMN id SET DEFAULT nextval('search_selections_id_seq'::regclass);

ALTER TABLE ONLY threat_priority_history ALTER COLUMN id SET DEFAULT nextval('threat_priority_history_id_seq'::regclass);

ALTER TABLE ONLY threat_readiness_history ALTER COLUMN id SET DEFAULT nextval('threat_readiness_history_id_seq'::regclass);

ALTER TABLE ONLY action_connectors
    ADD CONSTRAINT action_connectors_pkey PRIMARY KEY (id);

ALTER TABLE ONLY action_requests
    ADD CONSTRAINT action_requests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY agent_certificates
    ADD CONSTRAINT agent_certificates_pkey PRIMARY KEY (serial_number);

ALTER TABLE ONLY agent_groups
    ADD CONSTRAINT agent_groups_pkey PRIMARY KEY (id);

ALTER TABLE ONLY agent_maintenance_freezes
    ADD CONSTRAINT agent_maintenance_freezes_pkey PRIMARY KEY (id);

ALTER TABLE ONLY agent_op_logs
    ADD CONSTRAINT agent_op_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY agent_sec_logs
    ADD CONSTRAINT agent_sec_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY agent_telemetry
    ADD CONSTRAINT agent_telemetry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY agents
    ADD CONSTRAINT agents_pkey PRIMARY KEY (agent_id);

ALTER TABLE ONLY art_atomic_raw
    ADD CONSTRAINT art_atomic_raw_pkey PRIMARY KEY (technique_id);

ALTER TABLE ONLY art_atomic_tests
    ADD CONSTRAINT art_atomic_tests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY art_atomic_tests
    ADD CONSTRAINT art_atomic_tests_technique_id_test_index_key UNIQUE (technique_id, test_index);

ALTER TABLE ONLY art_content_meta
    ADD CONSTRAINT art_content_meta_pkey PRIMARY KEY (id);

ALTER TABLE ONLY art_payloads
    ADD CONSTRAINT art_payloads_pkey PRIMARY KEY (basename);

ALTER TABLE ONLY attackpath_asset_tags
    ADD CONSTRAINT attackpath_asset_tags_pkey PRIMARY KEY (host_key);

ALTER TABLE ONLY attackpath_collection_history
    ADD CONSTRAINT attackpath_collection_history_pkey PRIMARY KEY (id);

ALTER TABLE ONLY attackpath_collection_requests
    ADD CONSTRAINT attackpath_collection_requests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY attackpath_collections
    ADD CONSTRAINT attackpath_collections_pkey PRIMARY KEY (agent_id, source);

ALTER TABLE ONLY attackpath_jobs
    ADD CONSTRAINT attackpath_jobs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY attackpath_schedule
    ADD CONSTRAINT attackpath_schedule_pkey PRIMARY KEY (id);

ALTER TABLE ONLY audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY backup_jobs
    ADD CONSTRAINT backup_jobs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY campaign_variant_summary
    ADD CONSTRAINT campaign_variant_summary_pkey PRIMARY KEY (campaign_id);

ALTER TABLE ONLY campaigns
    ADD CONSTRAINT campaigns_pkey PRIMARY KEY (id);

ALTER TABLE ONLY compliance_snapshots
    ADD CONSTRAINT compliance_snapshots_pkey PRIMARY KEY (agent_id, framework_id);

ALTER TABLE ONLY cve_epss
    ADD CONSTRAINT cve_epss_pkey PRIMARY KEY (cve_id);

ALTER TABLE ONLY cves
    ADD CONSTRAINT cves_pkey PRIMARY KEY (cve_id);

ALTER TABLE ONLY dashboard_snapshots
    ADD CONSTRAINT dashboard_snapshots_pkey PRIMARY KEY (id);

ALTER TABLE ONLY dashboard_snapshots
    ADD CONSTRAINT dashboard_snapshots_snapshot_date_key UNIQUE (snapshot_date);

ALTER TABLE ONLY detection_connectors
    ADD CONSTRAINT detection_connectors_pkey PRIMARY KEY (id);

ALTER TABLE ONLY dlp_sink_receipts
    ADD CONSTRAINT dlp_sink_receipts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY dlp_sink_tokens
    ADD CONSTRAINT dlp_sink_tokens_pkey PRIMARY KEY (token);

ALTER TABLE ONLY em_sweeps
    ADD CONSTRAINT em_sweeps_pkey PRIMARY KEY (id);

ALTER TABLE ONLY execution_attempts
    ADD CONSTRAINT execution_attempts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY execution_attempts
    ADD CONSTRAINT execution_attempts_source_source_attempt_id_key UNIQUE (source, source_attempt_id);

ALTER TABLE ONLY exercise_events
    ADD CONSTRAINT exercise_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY exercise_evidence
    ADD CONSTRAINT exercise_evidence_execution_id_seq_key UNIQUE (execution_id, seq);

ALTER TABLE ONLY exercise_evidence
    ADD CONSTRAINT exercise_evidence_pkey PRIMARY KEY (id);

ALTER TABLE ONLY exercise_executions
    ADD CONSTRAINT exercise_executions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY exercise_plans
    ADD CONSTRAINT exercise_plans_pkey PRIMARY KEY (id);

ALTER TABLE ONLY exercise_step_executions
    ADD CONSTRAINT exercise_step_executions_execution_id_step_id_key UNIQUE (execution_id, step_id);

ALTER TABLE ONLY exercise_step_executions
    ADD CONSTRAINT exercise_step_executions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY exercise_templates
    ADD CONSTRAINT exercise_templates_pkey PRIMARY KEY (id);

ALTER TABLE ONLY exercise_track_tokens
    ADD CONSTRAINT exercise_track_tokens_pkey PRIMARY KEY (token);

ALTER TABLE ONLY exercise_webhook_calls
    ADD CONSTRAINT exercise_webhook_calls_pkey PRIMARY KEY (id);

ALTER TABLE ONLY finding_slas
    ADD CONSTRAINT finding_slas_pkey PRIMARY KEY (id);

ALTER TABLE ONLY finding_tickets
    ADD CONSTRAINT finding_tickets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY initiatives
    ADD CONSTRAINT initiatives_pkey PRIMARY KEY (id);

ALTER TABLE ONLY intelligence_campaigns
    ADD CONSTRAINT intelligence_campaigns_pkey PRIMARY KEY (id);

ALTER TABLE ONLY intelligence_entity_sources
    ADD CONSTRAINT intelligence_entity_sources_entity_type_entity_id_provider_key UNIQUE (entity_type, entity_id, provider);

ALTER TABLE ONLY intelligence_entity_sources
    ADD CONSTRAINT intelligence_entity_sources_pkey PRIMARY KEY (id);

ALTER TABLE ONLY intelligence_malware
    ADD CONSTRAINT intelligence_malware_pkey PRIMARY KEY (id);

ALTER TABLE ONLY intelligence_tools
    ADD CONSTRAINT intelligence_tools_pkey PRIMARY KEY (id);

ALTER TABLE ONLY ioc_enrichment
    ADD CONSTRAINT ioc_enrichment_indicator_type_indicator_value_provider_key UNIQUE (indicator_type, indicator_value, provider);

ALTER TABLE ONLY ioc_enrichment
    ADD CONSTRAINT ioc_enrichment_pkey PRIMARY KEY (id);

ALTER TABLE ONLY ioc_sightings
    ADD CONSTRAINT ioc_sightings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY iocs
    ADD CONSTRAINT iocs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY job_schedules
    ADD CONSTRAINT job_schedules_pkey PRIMARY KEY (id);

ALTER TABLE ONLY job_targets
    ADD CONSTRAINT job_targets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY jobs
    ADD CONSTRAINT jobs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY legacy_transport_log
    ADD CONSTRAINT legacy_transport_log_agent_id_day_key UNIQUE (agent_id, day);

ALTER TABLE ONLY legacy_transport_unattributed
    ADD CONSTRAINT legacy_transport_unattributed_pkey PRIMARY KEY (day);

ALTER TABLE ONLY notification_webhooks
    ADD CONSTRAINT notification_webhooks_pkey PRIMARY KEY (id);

ALTER TABLE ONLY notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);

ALTER TABLE ONLY openaev_bundles
    ADD CONSTRAINT openaev_bundles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY openaev_config
    ADD CONSTRAINT openaev_config_pkey PRIMARY KEY (id);

ALTER TABLE ONLY openaev_scenarios
    ADD CONSTRAINT openaev_scenarios_pkey PRIMARY KEY (openaev_scenario_id);

ALTER TABLE ONLY owasp_risks
    ADD CONSTRAINT owasp_risks_pkey PRIMARY KEY (risk_id);

ALTER TABLE ONLY payload_families
    ADD CONSTRAINT payload_families_pkey PRIMARY KEY (id);

ALTER TABLE ONLY posture_findings
    ADD CONSTRAINT posture_findings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY relationship_evidence
    ADD CONSTRAINT relationship_evidence_pkey PRIMARY KEY (id);

ALTER TABLE ONLY remediation_requests
    ADD CONSTRAINT remediation_requests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY report_log
    ADD CONSTRAINT report_log_pkey PRIMARY KEY (id);

ALTER TABLE ONLY run_events
    ADD CONSTRAINT run_events_pkey PRIMARY KEY (run_id, seq);

ALTER TABLE ONLY run_iocs
    ADD CONSTRAINT run_iocs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY run_iocs
    ADD CONSTRAINT run_iocs_run_id_indicator_type_indicator_value_key UNIQUE (run_id, indicator_type, indicator_value);

ALTER TABLE ONLY scenario_runs
    ADD CONSTRAINT scenario_runs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY scenario_techniques
    ADD CONSTRAINT scenario_techniques_pkey PRIMARY KEY (scenario_id, technique_id);

ALTER TABLE ONLY scenario_variant_results
    ADD CONSTRAINT scenario_variant_results_pkey PRIMARY KEY (id);

ALTER TABLE ONLY scenario_variant_results
    ADD CONSTRAINT scenario_variant_results_run_id_step_id_variant_id_key UNIQUE (run_id, step_id, variant_id);

ALTER TABLE ONLY scenario_variant_technique_summary
    ADD CONSTRAINT scenario_variant_technique_summary_pkey PRIMARY KEY (id);

ALTER TABLE ONLY scenario_variant_technique_summary
    ADD CONSTRAINT scenario_variant_technique_summary_run_id_technique_id_key UNIQUE (run_id, technique_id);

ALTER TABLE ONLY scenarios
    ADD CONSTRAINT scenarios_pkey PRIMARY KEY (scenario_id);

ALTER TABLE ONLY scim_configs
    ADD CONSTRAINT scim_configs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY scim_configs
    ADD CONSTRAINT scim_configs_tenant_id_key UNIQUE (tenant_id);

ALTER TABLE ONLY search_documents
    ADD CONSTRAINT search_documents_doc_type_source_id_key UNIQUE (doc_type, source_id);

ALTER TABLE ONLY search_documents
    ADD CONSTRAINT search_documents_pkey PRIMARY KEY (id);

ALTER TABLE ONLY search_favorites
    ADD CONSTRAINT search_favorites_pkey PRIMARY KEY (id);

ALTER TABLE ONLY search_favorites
    ADD CONSTRAINT search_favorites_user_id_doc_type_source_id_key UNIQUE (user_id, doc_type, source_id);

ALTER TABLE ONLY search_selections
    ADD CONSTRAINT search_selections_pkey PRIMARY KEY (id);

ALTER TABLE ONLY siem_configs
    ADD CONSTRAINT siem_configs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY siem_correlations
    ADD CONSTRAINT siem_correlations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY siem_correlations
    ADD CONSTRAINT siem_correlations_run_id_config_id_key UNIQUE (run_id, config_id);

ALTER TABLE ONLY sla_policy
    ADD CONSTRAINT sla_policy_pkey PRIMARY KEY (severity);

ALTER TABLE ONLY sso_configs
    ADD CONSTRAINT sso_configs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sso_configs
    ADD CONSTRAINT sso_configs_tenant_id_key UNIQUE (tenant_id);

ALTER TABLE ONLY tactics
    ADD CONSTRAINT tactics_pkey PRIMARY KEY (tactic_id);

ALTER TABLE ONLY tamper_events
    ADD CONSTRAINT tamper_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY taxii_connector_config
    ADD CONSTRAINT taxii_connector_config_pkey PRIMARY KEY (id);

ALTER TABLE ONLY taxii_ingested_objects
    ADD CONSTRAINT taxii_ingested_objects_pkey PRIMARY KEY (connector_id, stix_id, modified);

ALTER TABLE ONLY technique_cve_relationships
    ADD CONSTRAINT technique_cve_relationships_pkey PRIMARY KEY (id);

ALTER TABLE ONLY technique_cve_relationships
    ADD CONSTRAINT technique_cve_relationships_technique_id_cve_id_relationshi_key UNIQUE (technique_id, cve_id, relationship_type);

ALTER TABLE ONLY technique_cves
    ADD CONSTRAINT technique_cves_pkey PRIMARY KEY (technique_id, cve_id);

ALTER TABLE ONLY technique_evidence
    ADD CONSTRAINT technique_evidence_pkey PRIMARY KEY (actor_name, technique_id, via, via_name, source);

ALTER TABLE ONLY technique_owasp
    ADD CONSTRAINT technique_owasp_pkey PRIMARY KEY (technique_id, risk_id);

ALTER TABLE ONLY technique_verification_runs
    ADD CONSTRAINT technique_verification_runs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY techniques
    ADD CONSTRAINT techniques_pkey PRIMARY KEY (technique_id);

ALTER TABLE ONLY tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY tenants
    ADD CONSTRAINT tenants_slug_key UNIQUE (slug);

ALTER TABLE ONLY threat_actor_activity
    ADD CONSTRAINT threat_actor_activity_pkey PRIMARY KEY (actor_name, source);

ALTER TABLE ONLY threat_actor_profiles
    ADD CONSTRAINT threat_actor_profiles_pkey PRIMARY KEY (name);

ALTER TABLE ONLY threat_actor_sources
    ADD CONSTRAINT threat_actor_sources_pkey PRIMARY KEY (actor_name, source);

ALTER TABLE ONLY threat_intel_config
    ADD CONSTRAINT threat_intel_config_pkey PRIMARY KEY (connector);

ALTER TABLE ONLY threat_priority_history
    ADD CONSTRAINT threat_priority_history_pkey PRIMARY KEY (id);

ALTER TABLE ONLY threat_readiness_history
    ADD CONSTRAINT threat_readiness_history_pkey PRIMARY KEY (id);

ALTER TABLE ONLY ticketing_configs
    ADD CONSTRAINT ticketing_configs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY findings
    ADD CONSTRAINT uq_finding UNIQUE (agent_id, technique_id, control_class);

ALTER TABLE ONLY finding_tickets
    ADD CONSTRAINT uq_finding_ticket UNIQUE (finding_id, config_id);

ALTER TABLE ONLY payload_families
    ADD CONSTRAINT uq_payload_family UNIQUE (technique_id, name);

ALTER TABLE ONLY posture_findings
    ADD CONSTRAINT uq_posture_finding UNIQUE (agent_id, check_id);

ALTER TABLE ONLY users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY users
    ADD CONSTRAINT users_username_key UNIQUE (username);

ALTER TABLE ONLY variant_findings
    ADD CONSTRAINT variant_findings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY variant_run_steps
    ADD CONSTRAINT variant_run_steps_pkey PRIMARY KEY (id);

ALTER TABLE ONLY variant_runs
    ADD CONSTRAINT variant_runs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY verification_evidence_blob
    ADD CONSTRAINT verification_evidence_blob_pkey PRIMARY KEY (id);

ALTER TABLE ONLY verification_evidence
    ADD CONSTRAINT verification_evidence_pkey PRIMARY KEY (id);

ALTER TABLE ONLY verification_history
    ADD CONSTRAINT verification_history_pkey PRIMARY KEY (id);

ALTER TABLE ONLY vex_sweeps
    ADD CONSTRAINT vex_sweeps_pkey PRIMARY KEY (id);

CREATE INDEX compliance_snapshots_agent ON compliance_snapshots USING btree (agent_id);

CREATE INDEX idx_action_requests_run_id ON action_requests USING btree (run_id) WHERE (run_id <> ''::text);

CREATE INDEX idx_agent_certificates_agent_id ON agent_certificates USING btree (agent_id);

CREATE INDEX idx_agent_groups_parent_id ON agent_groups USING btree (parent_id);

CREATE INDEX idx_agent_maintenance_freezes_agent_id ON agent_maintenance_freezes USING btree (agent_id);

CREATE INDEX idx_agents_group_id ON agents USING btree (group_id);

CREATE INDEX idx_aph_agent_time ON attackpath_collection_history USING btree (agent_id, collected_at DESC);

CREATE INDEX idx_atomic_tests_technique ON art_atomic_tests USING btree (technique_id);

CREATE INDEX idx_attackpath_collection_requests_agent ON attackpath_collection_requests USING btree (agent_id, requested_at DESC);

CREATE INDEX idx_attackpath_jobs_active ON attackpath_jobs USING btree (expires_at) WHERE (status <> ALL (ARRAY['completed'::text, 'failed'::text, 'timed_out'::text, 'delivery_failed'::text, 'cancelled'::text]));

CREATE INDEX idx_attackpath_jobs_agent ON attackpath_jobs USING btree (agent_id, status);

CREATE INDEX idx_audit_logs_action ON audit_logs USING btree (action, ts DESC);

CREATE INDEX idx_audit_logs_actor ON audit_logs USING btree (actor_id, ts DESC);

CREATE INDEX idx_audit_logs_ts ON audit_logs USING btree (ts DESC);

CREATE INDEX idx_backup_jobs_requested_at ON backup_jobs USING btree (requested_at DESC);

CREATE INDEX idx_backup_jobs_status ON backup_jobs USING btree (status);

CREATE INDEX idx_dashboard_snapshots_date ON dashboard_snapshots USING btree (snapshot_date DESC);

CREATE INDEX idx_dlp_sink_receipts_token ON dlp_sink_receipts USING btree (token);

CREATE INDEX idx_dlp_sink_tokens_run_id ON dlp_sink_tokens USING btree (run_id);

CREATE INDEX idx_em_sweeps_agent ON em_sweeps USING btree (agent_id);

CREATE UNIQUE INDEX idx_em_sweeps_one_running_per_agent ON em_sweeps USING btree (agent_id) WHERE (status = ANY (ARRAY['running'::text, 'agent_disconnected'::text]));

CREATE INDEX idx_ex_events_exec ON exercise_events USING btree (execution_id);

CREATE INDEX idx_ex_events_ts ON exercise_events USING btree (execution_id, ts DESC);

CREATE INDEX idx_ex_evidence_exec ON exercise_evidence USING btree (execution_id);

CREATE INDEX idx_ex_evidence_type ON exercise_evidence USING btree (execution_id, evidence_type);

CREATE INDEX idx_ex_exec_plan ON exercise_executions USING btree (plan_id);

CREATE INDEX idx_ex_exec_status ON exercise_executions USING btree (status);

CREATE INDEX idx_ex_hook_token ON exercise_webhook_calls USING btree (token);

CREATE INDEX idx_ex_stepex_exec ON exercise_step_executions USING btree (execution_id);

CREATE INDEX idx_ex_stepex_status ON exercise_step_executions USING btree (execution_id, status);

CREATE INDEX idx_ex_tmpl_category ON exercise_templates USING btree (category);

CREATE INDEX idx_ex_token_exec ON exercise_track_tokens USING btree (execution_id);

CREATE INDEX idx_ex_token_step ON exercise_track_tokens USING btree (step_exec_id);

CREATE INDEX idx_execution_attempts_execution ON execution_attempts USING btree (source_execution_id);

CREATE INDEX idx_execution_attempts_status ON execution_attempts USING btree (status);

CREATE INDEX idx_execution_attempts_technique ON execution_attempts USING btree (technique_id) WHERE (technique_id IS NOT NULL);

CREATE INDEX idx_finding_slas_active_deadline ON finding_slas USING btree (status, deadline_at) WHERE (status = 'active'::text);

CREATE INDEX idx_finding_slas_posture_finding ON finding_slas USING btree (posture_finding_id);

CREATE INDEX idx_finding_tickets_finding ON finding_tickets USING btree (finding_id);

CREATE INDEX idx_finding_tickets_reval ON finding_tickets USING btree (revalidation_required, revalidation_dispatched_at) WHERE (revalidation_required = true);

CREATE INDEX idx_finding_tickets_status ON finding_tickets USING btree (status);

CREATE INDEX idx_findings_campaign ON findings USING btree (last_campaign_id);

CREATE INDEX idx_findings_status_sev ON findings USING btree (status, severity);

CREATE INDEX idx_ioc_enrichment_ttl ON ioc_enrichment USING btree (ttl_expires_at);

CREATE INDEX idx_ioc_sightings_agent ON ioc_sightings USING btree (agent_id);

CREATE INDEX idx_ioc_sightings_ioc ON ioc_sightings USING btree (ioc_id);

CREATE INDEX idx_ioc_sightings_run ON ioc_sightings USING btree (run_id);

CREATE INDEX idx_ioc_sightings_technique ON ioc_sightings USING btree (technique_id);

CREATE INDEX idx_iocs_status ON iocs USING btree (status);

CREATE INDEX idx_iocs_suppressed ON iocs USING btree (suppressed) WHERE (suppressed = true);

CREATE UNIQUE INDEX idx_iocs_type_value ON iocs USING btree (type, value);

CREATE INDEX idx_job_schedules_enabled ON job_schedules USING btree (enabled) WHERE (enabled = true);

CREATE INDEX idx_job_schedules_initiative_id ON job_schedules USING btree (initiative_id) WHERE (initiative_id <> ''::text);

CREATE INDEX idx_job_targets_job_id ON job_targets USING btree (job_id);

CREATE INDEX idx_job_targets_owner_id ON job_targets USING btree (owner_id) WHERE (owner_id <> ''::text);

CREATE INDEX idx_job_targets_state ON job_targets USING btree (state) WHERE (state = 'pending'::text);

CREATE INDEX idx_jobs_initiative_id ON jobs USING btree (initiative_id) WHERE (initiative_id <> ''::text);

CREATE INDEX idx_jobs_state ON jobs USING btree (state);

CREATE INDEX idx_legacy_transport_log_day ON legacy_transport_log USING btree (day);

CREATE INDEX idx_notifications_created_at ON notifications USING btree (created_at DESC);

CREATE INDEX idx_notifications_job_id ON notifications USING btree (job_id);

CREATE INDEX idx_op_logs_agent_time ON agent_op_logs USING btree (agent_id, created_at DESC);

CREATE INDEX idx_payload_families_tech ON payload_families USING btree (technique_id);

CREATE INDEX idx_posture_findings_agent ON posture_findings USING btree (agent_id);

CREATE INDEX idx_posture_findings_status ON posture_findings USING btree (status);

CREATE INDEX idx_remediation_requests_agent_id ON remediation_requests USING btree (agent_id);

CREATE INDEX idx_remediation_requests_fix_run_id ON remediation_requests USING btree (fix_run_id) WHERE (fix_run_id <> ''::text);

CREATE INDEX idx_remediation_requests_verify_run_id ON remediation_requests USING btree (verify_run_id) WHERE (verify_run_id <> ''::text);

CREATE INDEX idx_report_log_time ON report_log USING btree (generated_at DESC);

CREATE INDEX idx_reve_relationship ON relationship_evidence USING btree (relationship_id) WHERE (NOT deleted);

CREATE INDEX idx_run_iocs_run_id ON run_iocs USING btree (run_id);

CREATE INDEX idx_run_iocs_value ON run_iocs USING btree (indicator_type, indicator_value);

CREATE INDEX idx_scenario_runs_agent ON scenario_runs USING btree (agent_id);

CREATE UNIQUE INDEX idx_scenario_runs_agent_running ON scenario_runs USING btree (agent_id) WHERE (status = 'running'::text);

CREATE INDEX idx_scenario_runs_campaign ON scenario_runs USING btree (campaign_id);

CREATE INDEX idx_scenario_runs_em_sweep_id ON scenario_runs USING btree (em_sweep_id);

CREATE INDEX idx_scenario_runs_scenario ON scenario_runs USING btree (scenario_id);

CREATE INDEX idx_scenario_runs_sweep_id ON scenario_runs USING btree (sweep_id);

CREATE INDEX idx_search_documents_vector ON search_documents USING gin (search_vector);

CREATE INDEX idx_search_favorites_user ON search_favorites USING btree (user_id);

CREATE INDEX idx_search_selections_entity ON search_selections USING btree (doc_type, source_id, created_at DESC);

CREATE INDEX idx_search_selections_user ON search_selections USING btree (user_id, created_at DESC);

CREATE INDEX idx_sec_logs_agent_time ON agent_sec_logs USING btree (agent_id, created_at DESC);

CREATE INDEX idx_sec_logs_run ON agent_sec_logs USING btree (run_id);

CREATE INDEX idx_siem_corr_agent ON siem_correlations USING btree (agent_id, correlated_at DESC);

CREATE INDEX idx_siem_corr_run ON siem_correlations USING btree (run_id);

CREATE INDEX idx_svr_run_id ON scenario_variant_results USING btree (run_id);

CREATE INDEX idx_svr_tech_verdict ON scenario_variant_results USING btree (technique_id, verdict);

CREATE INDEX idx_svr_variant_id ON scenario_variant_results USING btree (variant_id);

CREATE INDEX idx_svts_bypassed ON scenario_variant_technique_summary USING btree (run_id, bypassed DESC);

CREATE INDEX idx_svts_run_id ON scenario_variant_technique_summary USING btree (run_id);

CREATE INDEX idx_tamper_events_ack ON tamper_events USING btree (acknowledged, detected_at DESC);

CREATE INDEX idx_tcr_active_scored ON technique_cve_relationships USING btree (technique_id) WHERE ((status = 'Active'::text) AND (effective_confidence = ANY (ARRAY['High'::text, 'Medium'::text])));

CREATE INDEX idx_tcr_cve ON technique_cve_relationships USING btree (cve_id);

CREATE INDEX idx_tcr_technique ON technique_cve_relationships USING btree (technique_id);

CREATE INDEX idx_technique_verification_runs_agent_id ON technique_verification_runs USING btree (agent_id);

CREATE INDEX idx_technique_verification_runs_request_id ON technique_verification_runs USING btree (request_id);

CREATE INDEX idx_technique_verification_runs_run_id ON technique_verification_runs USING btree (run_id) WHERE (run_id <> ''::text);

CREATE INDEX idx_telemetry_agent_time ON agent_telemetry USING btree (agent_id, created_at DESC);

CREATE INDEX idx_telemetry_metric ON agent_telemetry USING btree (agent_id, metric, created_at DESC);

CREATE INDEX idx_variant_findings_run ON variant_findings USING btree (variant_run_id);

CREATE UNIQUE INDEX idx_variant_findings_run_task ON variant_findings USING btree (variant_run_id, task_id);

CREATE INDEX idx_variant_findings_tech ON variant_findings USING btree (technique_id);

CREATE INDEX idx_variant_run_steps_run ON variant_run_steps USING btree (variant_run_id);

CREATE INDEX idx_variant_run_steps_task ON variant_run_steps USING btree (task_id);

CREATE INDEX idx_variant_runs_agent ON variant_runs USING btree (agent_id);

CREATE INDEX idx_variant_runs_run ON variant_runs USING btree (scenario_run_id);

CREATE INDEX idx_variant_runs_technique ON variant_runs USING btree (technique_id);

CREATE UNIQUE INDEX idx_verif_active_one ON verification_history USING btree (run_id, expectation_id) WHERE active;

CREATE INDEX idx_verif_evidence_vid ON verification_evidence USING btree (verification_id) WHERE (NOT deleted);

CREATE INDEX idx_verif_lookup ON verification_history USING btree (run_id, expectation_id, verified_at DESC);

CREATE INDEX idx_verif_run ON verification_history USING btree (run_id);

CREATE INDEX idx_vex_sweeps_agent ON vex_sweeps USING btree (agent_id);

CREATE UNIQUE INDEX idx_vex_sweeps_one_running_per_agent ON vex_sweeps USING btree (agent_id) WHERE (status = ANY (ARRAY['running'::text, 'agent_disconnected'::text]));

CREATE INDEX tph_actor_time ON threat_priority_history USING btree (actor_name, recorded_at DESC);

CREATE INDEX trh_agent_actor_time ON threat_readiness_history USING btree (agent_id, actor_name, recorded_at DESC);

CREATE UNIQUE INDEX trh_run_actor ON threat_readiness_history USING btree (run_id, actor_name);

ALTER TABLE ONLY art_atomic_raw
    ADD CONSTRAINT art_atomic_raw_technique_id_fkey FOREIGN KEY (technique_id) REFERENCES techniques(technique_id) ON DELETE CASCADE;

ALTER TABLE ONLY art_atomic_tests
    ADD CONSTRAINT art_atomic_tests_technique_id_fkey FOREIGN KEY (technique_id) REFERENCES techniques(technique_id) ON DELETE CASCADE;

ALTER TABLE ONLY backup_jobs
    ADD CONSTRAINT backup_jobs_restore_of_id_fkey FOREIGN KEY (restore_of_id) REFERENCES backup_jobs(id);

ALTER TABLE ONLY exercise_events
    ADD CONSTRAINT exercise_events_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES exercise_executions(id) ON DELETE CASCADE;

ALTER TABLE ONLY exercise_evidence
    ADD CONSTRAINT exercise_evidence_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES exercise_executions(id) ON DELETE CASCADE;

ALTER TABLE ONLY exercise_executions
    ADD CONSTRAINT exercise_executions_plan_id_fkey FOREIGN KEY (plan_id) REFERENCES exercise_plans(id) ON DELETE RESTRICT;

ALTER TABLE ONLY exercise_step_executions
    ADD CONSTRAINT exercise_step_executions_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES exercise_executions(id) ON DELETE CASCADE;

ALTER TABLE ONLY finding_slas
    ADD CONSTRAINT finding_slas_posture_finding_id_fkey FOREIGN KEY (posture_finding_id) REFERENCES posture_findings(id);

ALTER TABLE ONLY finding_tickets
    ADD CONSTRAINT finding_tickets_config_id_fkey FOREIGN KEY (config_id) REFERENCES ticketing_configs(id) ON DELETE CASCADE;

ALTER TABLE ONLY finding_tickets
    ADD CONSTRAINT finding_tickets_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE;

ALTER TABLE ONLY scenario_runs
    ADD CONSTRAINT fk_agent FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE;

ALTER TABLE ONLY ioc_sightings
    ADD CONSTRAINT ioc_sightings_ioc_id_fkey FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE;

ALTER TABLE ONLY job_targets
    ADD CONSTRAINT job_targets_job_id_fkey FOREIGN KEY (job_id) REFERENCES jobs(id);

ALTER TABLE ONLY notifications
    ADD CONSTRAINT notifications_job_id_fkey FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE;

ALTER TABLE ONLY openaev_scenarios
    ADD CONSTRAINT openaev_scenarios_bundle_id_fkey FOREIGN KEY (bundle_id) REFERENCES openaev_bundles(id);

ALTER TABLE ONLY relationship_evidence
    ADD CONSTRAINT relationship_evidence_relationship_id_fkey FOREIGN KEY (relationship_id) REFERENCES technique_cve_relationships(id) ON DELETE CASCADE;

ALTER TABLE ONLY scenario_runs
    ADD CONSTRAINT scenario_runs_em_sweep_id_fkey FOREIGN KEY (em_sweep_id) REFERENCES em_sweeps(id);

ALTER TABLE ONLY scenario_runs
    ADD CONSTRAINT scenario_runs_sweep_id_fkey FOREIGN KEY (sweep_id) REFERENCES vex_sweeps(id);

ALTER TABLE ONLY scenario_techniques
    ADD CONSTRAINT scenario_techniques_scenario_id_fkey FOREIGN KEY (scenario_id) REFERENCES scenarios(scenario_id) ON DELETE CASCADE;

ALTER TABLE ONLY scenario_techniques
    ADD CONSTRAINT scenario_techniques_technique_id_fkey FOREIGN KEY (technique_id) REFERENCES techniques(technique_id) ON DELETE CASCADE;

ALTER TABLE ONLY scim_configs
    ADD CONSTRAINT scim_configs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE ONLY search_favorites
    ADD CONSTRAINT search_favorites_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id);

ALTER TABLE ONLY search_selections
    ADD CONSTRAINT search_selections_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id);

ALTER TABLE ONLY sso_configs
    ADD CONSTRAINT sso_configs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE ONLY tamper_events
    ADD CONSTRAINT tamper_events_acked_by_fkey FOREIGN KEY (acked_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE ONLY taxii_ingested_objects
    ADD CONSTRAINT taxii_ingested_objects_connector_id_fkey FOREIGN KEY (connector_id) REFERENCES taxii_connector_config(id) ON DELETE CASCADE;

ALTER TABLE ONLY taxii_ingested_objects
    ADD CONSTRAINT taxii_ingested_objects_ioc_id_fkey FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE;

ALTER TABLE ONLY technique_cve_relationships
    ADD CONSTRAINT technique_cve_relationships_cve_id_fkey FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE;

ALTER TABLE ONLY technique_cve_relationships
    ADD CONSTRAINT technique_cve_relationships_technique_id_fkey FOREIGN KEY (technique_id) REFERENCES techniques(technique_id) ON DELETE CASCADE;

ALTER TABLE ONLY technique_cves
    ADD CONSTRAINT technique_cves_cve_id_fkey FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE;

ALTER TABLE ONLY technique_cves
    ADD CONSTRAINT technique_cves_technique_id_fkey FOREIGN KEY (technique_id) REFERENCES techniques(technique_id) ON DELETE CASCADE;

ALTER TABLE ONLY technique_evidence
    ADD CONSTRAINT technique_evidence_actor_name_fkey FOREIGN KEY (actor_name) REFERENCES threat_actor_profiles(name) ON DELETE CASCADE;

ALTER TABLE ONLY technique_owasp
    ADD CONSTRAINT technique_owasp_risk_id_fkey FOREIGN KEY (risk_id) REFERENCES owasp_risks(risk_id) ON DELETE CASCADE;

ALTER TABLE ONLY technique_owasp
    ADD CONSTRAINT technique_owasp_technique_id_fkey FOREIGN KEY (technique_id) REFERENCES techniques(technique_id) ON DELETE CASCADE;

ALTER TABLE ONLY technique_verification_runs
    ADD CONSTRAINT technique_verification_runs_request_id_fkey FOREIGN KEY (request_id) REFERENCES remediation_requests(id);

ALTER TABLE ONLY threat_actor_activity
    ADD CONSTRAINT threat_actor_activity_actor_name_fkey FOREIGN KEY (actor_name) REFERENCES threat_actor_profiles(name) ON DELETE CASCADE;

ALTER TABLE ONLY threat_actor_sources
    ADD CONSTRAINT threat_actor_sources_actor_name_fkey FOREIGN KEY (actor_name) REFERENCES threat_actor_profiles(name) ON DELETE CASCADE;

ALTER TABLE ONLY users
    ADD CONSTRAINT users_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE POLICY tenant_isolation ON users USING (((tenant_id = current_setting('app.tenant_id'::text, true)) OR (current_setting('app.is_platform_admin'::text, true))::boolean));

