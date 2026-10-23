-- dbsim lab: MySQL 8.0 seed. Run ONCE by mysql/10-seed.sh as root. The
-- @@TEST_PW@@ / @@LAB_PW@@ placeholders are substituted from the environment
-- ([A-Za-z0-9] only; never committed). Synthetic data only.
-- NOT executed by the author (no Docker on the dev host).

-- Keep the seed out of the general log (session scope).
SET SESSION sql_log_off = 1;

CREATE DATABASE IF NOT EXISTS dbsim;
CREATE DATABASE bas_dbsim CHARACTER SET utf8mb4;

CREATE TABLE bas_dbsim.app_data (id INT PRIMARY KEY, label VARCHAR(64) NOT NULL);
INSERT INTO bas_dbsim.app_data VALUES
  (1, 'BAS-SIM-APP-001'), (2, 'BAS-SIM-APP-002'), (3, 'BAS-SIM-APP-003');

CREATE TABLE bas_dbsim.restricted (id INT PRIMARY KEY, label VARCHAR(64) NOT NULL, note VARCHAR(64));
INSERT INTO bas_dbsim.restricted VALUES
  (1, 'BAS-SIM-RESTRICTED-001', 'synthetic'),
  (2, 'BAS-SIM-RESTRICTED-002', 'synthetic'),
  (3, 'BAS-SIM-RESTRICTED-003', 'synthetic');

-- Application "role" for DB-02 (MySQL has no login-less roles that show in
-- TABLE_PRIVILEGES the same way; a locked account is what the fixtures use too).
CREATE USER 'bas_dbsim_app'@'%' ACCOUNT LOCK;
GRANT SELECT ON bas_dbsim.app_data TO 'bas_dbsim_app'@'%';

-- Least-privilege client-style account. NO privilege on bas_dbsim: DB-03
-- expects the read of bas_dbsim.restricted to be DENIED.
CREATE USER 'dbsim_test'@'%' IDENTIFIED WITH mysql_native_password BY '@@TEST_PW@@';
GRANT SELECT ON dbsim.* TO 'dbsim_test'@'%';
-- Audit sources the adapter reads (mysql.general_log TABLE and
-- performance_schema), plus column-level access to the account list.
GRANT SELECT ON mysql.general_log TO 'dbsim_test'@'%';
GRANT SELECT ON performance_schema.events_statements_history_long TO 'dbsim_test'@'%';
GRANT SELECT ON performance_schema.threads TO 'dbsim_test'@'%';
GRANT SELECT ON performance_schema.global_status TO 'dbsim_test'@'%';
GRANT SELECT ON performance_schema.setup_consumers TO 'dbsim_test'@'%';
GRANT SELECT (`User`, `Host`, `account_locked`, `Super_priv`) ON mysql.user TO 'dbsim_test'@'%';

-- Lab-admin-style account for lab mode: fixtures CREATE/DROP schemas and
-- users and GRANT SELECT on what they created (needs SELECT ... WITH GRANT
-- OPTION globally, since MySQL does not give a schema's creator privileges
-- on it). Lab only.
CREATE USER 'dbsim_lab'@'%' IDENTIFIED WITH mysql_native_password BY '@@LAB_PW@@';
GRANT CREATE, DROP, SELECT, INSERT, CREATE USER ON *.* TO 'dbsim_lab'@'%' WITH GRANT OPTION;

FLUSH PRIVILEGES;
