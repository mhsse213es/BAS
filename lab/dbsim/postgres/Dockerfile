FROM postgres:16.4-bookworm
# pgaudit comes from the PGDG apt repo already configured in the official image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-16-pgaudit \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/log/postgresql \
 && chown postgres:postgres /var/log/postgresql
