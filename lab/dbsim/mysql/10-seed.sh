#!/bin/sh
# Runs once on first init. Passwords are substituted into the SQL, so they must
# be [A-Za-z0-9] only (enforced here).
set -eu
for v in DBSIM_TEST_PASSWORD DBSIM_LAB_PASSWORD; do
  eval "val=\${$v:-}"
  case $val in ''|*[!A-Za-z0-9]*) echo "$v must be non-empty [A-Za-z0-9] only" >&2; exit 1;; esac
done
sed -e "s/@@TEST_PW@@/$DBSIM_TEST_PASSWORD/g" -e "s/@@LAB_PW@@/$DBSIM_LAB_PASSWORD/g" \
  /seed/seed-mysql.sql | mysql -uroot -p"$MYSQL_ROOT_PASSWORD"
