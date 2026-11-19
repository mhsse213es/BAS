-- DB-02-06 inheritance chain (lab only). Run as the lab superuser against database dbsim.
-- Adds a NOLOGIN parent role that holds SELECT on bas_dbsim.restricted and is granted to
-- dbsim_lab. dbsim_lab inherits that privilege through the membership. Idempotent.
-- Teardown: lab/dbsim/teardown-inherit-chain.sql

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bas_dbsim_parent') THEN
    CREATE ROLE bas_dbsim_parent NOLOGIN;
  END IF;
END
$$;

GRANT USAGE ON SCHEMA bas_dbsim TO bas_dbsim_parent;
GRANT SELECT ON bas_dbsim.restricted TO bas_dbsim_parent;
GRANT bas_dbsim_parent TO dbsim_lab;
