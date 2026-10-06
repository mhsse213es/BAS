-- A real v1.7.0 (2026-06-17) database: built by that tag's own
-- db.EnsureSchema + db.EnsureContentSchema, one agent row added, then
-- pg_dump --inserts --no-owner --no-privileges, minus its psql-only
-- restrict/unrestrict lines. Regression fixture for adopting installs
-- older than the tenants table (H1 final review I1). Do not edit.
--
-- PostgreSQL database dump
--


-- Dumped from database version 16.15
-- Dumped by pg_dump version 16.15

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: agent_op_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_op_logs (
    id bigint NOT NULL,
    agent_id text NOT NULL,
    level text DEFAULT 'info'::text NOT NULL,
    category text DEFAULT 'lifecycle'::text NOT NULL,
    message text NOT NULL,
    seq bigint DEFAULT 0 NOT NULL,
    schema_ver integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agent_op_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_op_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_op_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_op_logs_id_seq OWNED BY public.agent_op_logs.id;


--
-- Name: agent_sec_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_sec_logs (
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
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agent_sec_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_sec_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_sec_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_sec_logs_id_seq OWNED BY public.agent_sec_logs.id;


--
-- Name: agent_telemetry; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_telemetry (
    id bigint NOT NULL,
    agent_id text NOT NULL,
    metric text NOT NULL,
    value double precision NOT NULL,
    unit text DEFAULT ''::text NOT NULL,
    seq bigint DEFAULT 0 NOT NULL,
    schema_ver integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agent_telemetry_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_telemetry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_telemetry_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_telemetry_id_seq OWNED BY public.agent_telemetry.id;


--
-- Name: agents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agents (
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
    posture_catalog jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: art_atomic_raw; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.art_atomic_raw (
    technique_id text NOT NULL,
    yaml text NOT NULL,
    content_hash text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: art_atomic_tests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.art_atomic_tests (
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
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: art_atomic_tests_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.art_atomic_tests_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: art_atomic_tests_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.art_atomic_tests_id_seq OWNED BY public.art_atomic_tests.id;


--
-- Name: art_content_meta; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.art_content_meta (
    id integer DEFAULT 1 NOT NULL,
    source_version text DEFAULT ''::text NOT NULL,
    technique_count integer DEFAULT 0 NOT NULL,
    payload_count integer DEFAULT 0 NOT NULL,
    source text DEFAULT ''::text NOT NULL,
    imported_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT art_content_meta_id_check CHECK ((id = 1))
);


--
-- Name: art_payloads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.art_payloads (
    basename text NOT NULL,
    sha256 text NOT NULL,
    size_bytes bigint NOT NULL,
    storage_path text NOT NULL,
    payload_type text DEFAULT ''::text NOT NULL,
    source text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: campaigns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campaigns (
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
    stopped_at timestamp with time zone
);


--
-- Name: cves; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cves (
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


--
-- Name: owasp_risks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.owasp_risks (
    risk_id text NOT NULL,
    version text DEFAULT ''::text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    display_order integer DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: run_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.run_events (
    run_id text NOT NULL,
    seq bigint NOT NULL,
    type text NOT NULL,
    task_id text DEFAULT ''::text NOT NULL,
    technique_id text DEFAULT ''::text NOT NULL,
    ts timestamp with time zone NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: scenario_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scenario_runs (
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
    campaign_id text
);


--
-- Name: scenario_techniques; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scenario_techniques (
    scenario_id text NOT NULL,
    technique_id text NOT NULL
);


--
-- Name: scenarios; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scenarios (
    scenario_id text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    category text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: tactics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tactics (
    tactic_id text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    attack_id text DEFAULT ''::text NOT NULL,
    kill_chain_order integer DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: technique_cves; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.technique_cves (
    technique_id text NOT NULL,
    cve_id text NOT NULL
);


--
-- Name: technique_owasp; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.technique_owasp (
    technique_id text NOT NULL,
    risk_id text NOT NULL
);


--
-- Name: techniques; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.techniques (
    technique_id text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    tactic text DEFAULT ''::text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    username text NOT NULL,
    password_hash text NOT NULL,
    role text DEFAULT 'analyst'::text NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    must_change_pw boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login timestamp with time zone
);


--
-- Name: agent_op_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_op_logs ALTER COLUMN id SET DEFAULT nextval('public.agent_op_logs_id_seq'::regclass);


--
-- Name: agent_sec_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_sec_logs ALTER COLUMN id SET DEFAULT nextval('public.agent_sec_logs_id_seq'::regclass);


--
-- Name: agent_telemetry id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_telemetry ALTER COLUMN id SET DEFAULT nextval('public.agent_telemetry_id_seq'::regclass);


--
-- Name: art_atomic_tests id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.art_atomic_tests ALTER COLUMN id SET DEFAULT nextval('public.art_atomic_tests_id_seq'::regclass);


--
-- Data for Name: agent_op_logs; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: agent_sec_logs; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: agent_telemetry; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: agents; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.agents VALUES ('a-v170', 'host-v170', '', '', '', 'idle', 'Production', false, '', false, '2026-10-06 08:50:21.974587+00', 'active', '{}', NULL, 1, '[]', '{}');


--
-- Data for Name: art_atomic_raw; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: art_atomic_tests; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: art_content_meta; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: art_payloads; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: campaigns; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: cves; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: owasp_risks; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: run_events; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: scenario_runs; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: scenario_techniques; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: scenarios; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: tactics; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: technique_cves; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: technique_owasp; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: techniques; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Name: agent_op_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.agent_op_logs_id_seq', 1, false);


--
-- Name: agent_sec_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.agent_sec_logs_id_seq', 1, false);


--
-- Name: agent_telemetry_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.agent_telemetry_id_seq', 1, false);


--
-- Name: art_atomic_tests_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.art_atomic_tests_id_seq', 1, false);


--
-- Name: agent_op_logs agent_op_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_op_logs
    ADD CONSTRAINT agent_op_logs_pkey PRIMARY KEY (id);


--
-- Name: agent_sec_logs agent_sec_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_sec_logs
    ADD CONSTRAINT agent_sec_logs_pkey PRIMARY KEY (id);


--
-- Name: agent_telemetry agent_telemetry_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_telemetry
    ADD CONSTRAINT agent_telemetry_pkey PRIMARY KEY (id);


--
-- Name: agents agents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_pkey PRIMARY KEY (agent_id);


--
-- Name: art_atomic_raw art_atomic_raw_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.art_atomic_raw
    ADD CONSTRAINT art_atomic_raw_pkey PRIMARY KEY (technique_id);


--
-- Name: art_atomic_tests art_atomic_tests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.art_atomic_tests
    ADD CONSTRAINT art_atomic_tests_pkey PRIMARY KEY (id);


--
-- Name: art_atomic_tests art_atomic_tests_technique_id_test_index_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.art_atomic_tests
    ADD CONSTRAINT art_atomic_tests_technique_id_test_index_key UNIQUE (technique_id, test_index);


--
-- Name: art_content_meta art_content_meta_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.art_content_meta
    ADD CONSTRAINT art_content_meta_pkey PRIMARY KEY (id);


--
-- Name: art_payloads art_payloads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.art_payloads
    ADD CONSTRAINT art_payloads_pkey PRIMARY KEY (basename);


--
-- Name: campaigns campaigns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaigns
    ADD CONSTRAINT campaigns_pkey PRIMARY KEY (id);


--
-- Name: cves cves_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cves
    ADD CONSTRAINT cves_pkey PRIMARY KEY (cve_id);


--
-- Name: owasp_risks owasp_risks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.owasp_risks
    ADD CONSTRAINT owasp_risks_pkey PRIMARY KEY (risk_id);


--
-- Name: run_events run_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.run_events
    ADD CONSTRAINT run_events_pkey PRIMARY KEY (run_id, seq);


--
-- Name: scenario_runs scenario_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scenario_runs
    ADD CONSTRAINT scenario_runs_pkey PRIMARY KEY (id);


--
-- Name: scenario_techniques scenario_techniques_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scenario_techniques
    ADD CONSTRAINT scenario_techniques_pkey PRIMARY KEY (scenario_id, technique_id);


--
-- Name: scenarios scenarios_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scenarios
    ADD CONSTRAINT scenarios_pkey PRIMARY KEY (scenario_id);


--
-- Name: tactics tactics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tactics
    ADD CONSTRAINT tactics_pkey PRIMARY KEY (tactic_id);


--
-- Name: technique_cves technique_cves_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.technique_cves
    ADD CONSTRAINT technique_cves_pkey PRIMARY KEY (technique_id, cve_id);


--
-- Name: technique_owasp technique_owasp_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.technique_owasp
    ADD CONSTRAINT technique_owasp_pkey PRIMARY KEY (technique_id, risk_id);


--
-- Name: techniques techniques_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.techniques
    ADD CONSTRAINT techniques_pkey PRIMARY KEY (technique_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: idx_atomic_tests_technique; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_atomic_tests_technique ON public.art_atomic_tests USING btree (technique_id);


--
-- Name: idx_op_logs_agent_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_op_logs_agent_time ON public.agent_op_logs USING btree (agent_id, created_at DESC);


--
-- Name: idx_scenario_runs_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scenario_runs_agent ON public.scenario_runs USING btree (agent_id);


--
-- Name: idx_scenario_runs_campaign; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scenario_runs_campaign ON public.scenario_runs USING btree (campaign_id);


--
-- Name: idx_scenario_runs_scenario; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scenario_runs_scenario ON public.scenario_runs USING btree (scenario_id);


--
-- Name: idx_sec_logs_agent_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sec_logs_agent_time ON public.agent_sec_logs USING btree (agent_id, created_at DESC);


--
-- Name: idx_sec_logs_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sec_logs_run ON public.agent_sec_logs USING btree (run_id);


--
-- Name: idx_telemetry_agent_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_telemetry_agent_time ON public.agent_telemetry USING btree (agent_id, created_at DESC);


--
-- Name: idx_telemetry_metric; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_telemetry_metric ON public.agent_telemetry USING btree (agent_id, metric, created_at DESC);


--
-- Name: art_atomic_raw art_atomic_raw_technique_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.art_atomic_raw
    ADD CONSTRAINT art_atomic_raw_technique_id_fkey FOREIGN KEY (technique_id) REFERENCES public.techniques(technique_id) ON DELETE CASCADE;


--
-- Name: art_atomic_tests art_atomic_tests_technique_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.art_atomic_tests
    ADD CONSTRAINT art_atomic_tests_technique_id_fkey FOREIGN KEY (technique_id) REFERENCES public.techniques(technique_id) ON DELETE CASCADE;


--
-- Name: scenario_runs fk_agent; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scenario_runs
    ADD CONSTRAINT fk_agent FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE CASCADE;


--
-- Name: scenario_techniques scenario_techniques_scenario_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scenario_techniques
    ADD CONSTRAINT scenario_techniques_scenario_id_fkey FOREIGN KEY (scenario_id) REFERENCES public.scenarios(scenario_id) ON DELETE CASCADE;


--
-- Name: scenario_techniques scenario_techniques_technique_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scenario_techniques
    ADD CONSTRAINT scenario_techniques_technique_id_fkey FOREIGN KEY (technique_id) REFERENCES public.techniques(technique_id) ON DELETE CASCADE;


--
-- Name: technique_cves technique_cves_cve_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.technique_cves
    ADD CONSTRAINT technique_cves_cve_id_fkey FOREIGN KEY (cve_id) REFERENCES public.cves(cve_id) ON DELETE CASCADE;


--
-- Name: technique_cves technique_cves_technique_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.technique_cves
    ADD CONSTRAINT technique_cves_technique_id_fkey FOREIGN KEY (technique_id) REFERENCES public.techniques(technique_id) ON DELETE CASCADE;


--
-- Name: technique_owasp technique_owasp_risk_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.technique_owasp
    ADD CONSTRAINT technique_owasp_risk_id_fkey FOREIGN KEY (risk_id) REFERENCES public.owasp_risks(risk_id) ON DELETE CASCADE;


--
-- Name: technique_owasp technique_owasp_technique_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.technique_owasp
    ADD CONSTRAINT technique_owasp_technique_id_fkey FOREIGN KEY (technique_id) REFERENCES public.techniques(technique_id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


