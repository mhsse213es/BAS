#!/bin/sh
# Runs once, on first init of an EMPTY data directory (docker-entrypoint-initdb.d).
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v test_pw="$DBSIM_TEST_PASSWORD" -v lab_pw="$DBSIM_LAB_PASSWORD" \
  -f /seed/seed-postgres.sql
