-- dbsim lab: PostgreSQL seed. Run ONCE by postgres/10-seed.sh as the bootstrap
-- superuser against database "dbsim", with psql variables :test_pw and :lab_pw
-- (from DBSIM_TEST_PASSWORD / DBSIM_LAB_PASSWORD; never committed).
-- Synthetic data only. NOT executed by the author (no Docker on the dev host).

-- Keep the seed (and its passwords) out of the server log and pgaudit.
SET log_statement = 'none';
SET pgaudit.log = 'none';

-- ---------------------------------------------------------------- accounts --
-- Least-privilege, client-style account: login only, read-only by default.
CREATE ROLE dbsim_test LOGIN PASSWORD :'test_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
ALTER ROLE dbsim_test SET default_transaction_read_only = on;

-- Lab-admin-style account for lab mode: fixture Seed/Cleanup creates and drops
-- schemas (needs CREATE on the database) and roles (needs CREATEROLE).
CREATE ROLE dbsim_lab LOGIN PASSWORD :'lab_pw'
  NOSUPERUSER NOCREATEDB CREATEROLE;
GRANT CREATE ON DATABASE dbsim TO dbsim_lab;

-- The application role the DB-02 scenario reads grants for.
CREATE ROLE bas_dbsim_app NOLOGIN;

-- pg_control_system() backs the system_identifier target identity (R6).
-- Execute rights on it are UNVERIFIED as a default, so grant explicitly.
GRANT EXECUTE ON FUNCTION pg_control_system() TO dbsim_test, dbsim_lab;

-- ----------------------------------------------------------- lab objects ----
CREATE SCHEMA bas_dbsim;

CREATE TABLE bas_dbsim.app_data (id int PRIMARY KEY, label text NOT NULL);
INSERT INTO bas_dbsim.app_data VALUES
  (1, 'BAS-SIM-APP-001'), (2, 'BAS-SIM-APP-002'), (3, 'BAS-SIM-APP-003');

CREATE TABLE bas_dbsim.restricted (id int PRIMARY KEY, label text NOT NULL, note text);
INSERT INTO bas_dbsim.restricted VALUES
  (1, 'BAS-SIM-RESTRICTED-001', 'synthetic'),
  (2, 'BAS-SIM-RESTRICTED-002', 'synthetic'),
  (3, 'BAS-SIM-RESTRICTED-003', 'synthetic');

-- bas_dbsim_app may read app_data only. NOBODY but the owner may touch
-- bas_dbsim.restricted: DB-03 expects the test account to be DENIED.
GRANT USAGE ON SCHEMA bas_dbsim TO bas_dbsim_app;
GRANT SELECT ON bas_dbsim.app_data TO bas_dbsim_app;
REVOKE ALL ON SCHEMA bas_dbsim FROM PUBLIC;
REVOKE ALL ON bas_dbsim.restricted FROM PUBLIC;

-- ------------------------------------------------------- audit view (fdw) ---
-- The agent reads dbsim_audit.pg_log(log_time, user_name, database_name,
-- command_tag, message). It is a view over the server's csvlog through
-- file_fdw. The csvlog path is FIXED: docker-compose sets log_filename =
-- 'dbsim-pg.log', log_rotation_age = 0 and log_rotation_size = 0, so the
-- collector writes one never-rotated /var/log/postgresql/dbsim-pg.csv (the
-- .log suffix is replaced by .csv). The file only grows; truncate it by
-- recreating the pg-log volume. The foreign table has to list EVERY csvlog
-- column of the server major version; this is the PostgreSQL 16 layout (26).
CREATE EXTENSION IF NOT EXISTS file_fdw;
CREATE SERVER dbsim_logsrv FOREIGN DATA WRAPPER file_fdw;
CREATE SCHEMA dbsim_audit;
CREATE FOREIGN TABLE dbsim_audit.pg_log_raw (
  log_time timestamp(3) with time zone,
  user_name text,
  database_name text,
  process_id integer,
  connection_from text,
  session_id text,
  session_line_num bigint,
  command_tag text,
  session_start_time timestamp with time zone,
  virtual_transaction_id text,
  transaction_id bigint,
  error_severity text,
  sql_state_code text,
  message text,
  detail text,
  hint text,
  internal_query text,
  internal_query_pos integer,
  context text,
  query text,
  query_pos integer,
  location text,
  application_name text,
  backend_type text,
  leader_pid integer,
  query_id bigint
) SERVER dbsim_logsrv
  OPTIONS (filename '/var/log/postgresql/dbsim-pg.csv', format 'csv');

CREATE VIEW dbsim_audit.pg_log AS
  SELECT log_time, user_name, database_name, command_tag, message
  FROM dbsim_audit.pg_log_raw;

REVOKE ALL ON SCHEMA dbsim_audit FROM PUBLIC;
REVOKE ALL ON dbsim_audit.pg_log, dbsim_audit.pg_log_raw FROM PUBLIC;
GRANT USAGE ON SCHEMA dbsim_audit TO dbsim_test, dbsim_lab;
-- The view runs with its owner's (superuser) rights; only the view is granted.
GRANT SELECT ON dbsim_audit.pg_log TO dbsim_test, dbsim_lab;
