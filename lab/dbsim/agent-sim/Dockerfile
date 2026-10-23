# Stand-in for the probing agent's network position: a DIFFERENT container
# from the databases, with the clients smoke.sh needs. The real agent binary is
# built separately and mounted at /opt/agent (see README).
FROM postgres:16.4-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends default-mysql-client curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["sleep", "infinity"]
CMD []
