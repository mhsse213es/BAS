#!/usr/bin/env bash
# Install and configure external PostgreSQL 16 on Ubuntu 24.04
# Runs on the Ubuntu host — PostgreSQL is NOT inside k3s.

set -euo pipefail
readonly DB_NAME="bas_platform"
readonly DB_USER="bas_user"
readonly LOG="/var/log/bas-postgres-setup.log"
exec > >(tee -a "$LOG") 2>&1

[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }

DB_PASSWORD="${1:-}"
if [[ -z "$DB_PASSWORD" ]]; then
    echo "Usage: $0 <db_password>"
    echo "       The password will be set for the '$DB_USER' PostgreSQL role."
    exit 1
fi

info() { echo "[INFO] $*"; }

# ── Install PostgreSQL 16 ──────────────────────────────────────────────────────
info "Installing PostgreSQL 16"
apt-get install -y -qq curl ca-certificates
install -d /usr/share/postgresql-common/pgdg
curl -fsSL "https://www.postgresql.org/media/keys/ACCC4CF8.asc" \
    -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] \
https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
    > /etc/apt/sources.list.d/pgdg.list
apt-get update -qq
apt-get install -y -qq postgresql-16
info "PostgreSQL 16 installed"

# ── Create database and user ───────────────────────────────────────────────────
info "Creating database and user"
sudo -u postgres psql <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$DB_USER') THEN
    CREATE ROLE $DB_USER LOGIN PASSWORD '$DB_PASSWORD';
  ELSE
    ALTER ROLE $DB_USER WITH PASSWORD '$DB_PASSWORD';
  END IF;
END
\$\$;

CREATE DATABASE $DB_NAME OWNER $DB_USER ENCODING 'UTF8' LC_COLLATE 'en_US.UTF-8' TEMPLATE template0;
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
SQL
info "Database '$DB_NAME' and user '$DB_USER' created"

# ── Secure pg_hba.conf ────────────────────────────────────────────────────────
info "Hardening pg_hba.conf (scram-sha-256 only)"
PG_HBA="/etc/postgresql/16/main/pg_hba.conf"
cat > "$PG_HBA" << 'EOF'
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
local   all             all                                     peer
host    bas_platform    bas_user        127.0.0.1/32            scram-sha-256
host    bas_platform    bas_user        ::1/128                 scram-sha-256
# Allow k3s pod network (adjust CIDR to your k3s pod CIDR — default 10.42.0.0/16)
host    bas_platform    bas_user        10.42.0.0/16            scram-sha-256
EOF

# ── Bind to localhost only ─────────────────────────────────────────────────────
info "Configuring PostgreSQL to listen on localhost only"
PG_CONF="/etc/postgresql/16/main/postgresql.conf"
sed -i "s/#listen_addresses = 'localhost'/listen_addresses = 'localhost'/" "$PG_CONF"

systemctl restart postgresql
systemctl enable postgresql
info "PostgreSQL restarted and enabled"

# ── Verify connection ──────────────────────────────────────────────────────────
info "Verifying connection"
PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -c "SELECT version();" \
    && info "Connection verified" \
    || { echo "[ERROR] Connection failed — check pg_hba.conf and credentials"; exit 1; }

info ""
info "=== PostgreSQL setup complete ==="
info "  Host:     localhost:5432"
info "  Database: $DB_NAME"
info "  User:     $DB_USER"
info "  DSN:      postgres://$DB_USER:<password>@localhost:5432/$DB_NAME"
info ""
info "NEXT STEP: Run ./scripts/install-k3s.sh"
