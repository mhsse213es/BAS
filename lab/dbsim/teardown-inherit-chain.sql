-- Removes the DB-02-06 inheritance chain seeded by seed-inherit-chain.sql. Lab only.
REVOKE bas_dbsim_parent FROM dbsim_lab;
REVOKE SELECT ON bas_dbsim.restricted FROM bas_dbsim_parent;
DROP ROLE IF EXISTS bas_dbsim_parent;
