# Package lifecycle test. Build from the repository root:
#   docker build -f packaging/linux-deb/test/Dockerfile -t audspect-deb-test . && docker run --rm audspect-deb-test
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends systemd openssl curl ca-certificates dpkg-dev \
    && rm -rf /var/lib/apt/lists/*
COPY packaging/linux-deb /src/linux-deb
COPY orchestrator/internal/api/agentinstall/install-agent-linux.sh /src/install-agent-linux.sh
COPY packaging/linux-deb/test/fake-agent.sh /test/fake-agent.sh
COPY packaging/linux-deb/test/fake-systemctl.sh /usr/bin/systemctl
RUN chmod +x /usr/bin/systemctl /src/install-agent-linux.sh /src/linux-deb/build-deb.sh /test/fake-agent.sh \
    && mkdir -p /etc/systemd/system
CMD ["bash", "/src/linux-deb/test/lifecycle.sh"]
