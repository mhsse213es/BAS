OpenCTI and OpenAEV compose files used by build/build-deb.sh.

opencti/docker-compose.yml, opencti/rabbitmq.conf
  upstream: https://github.com/OpenCTI-Platform/docker.git
  commit:   d3aa93833fe16f06bfd272e76b2876f0a6a81e90

openaev/docker-compose.yml, openaev/rabbitmq.conf
  upstream: https://github.com/OpenAEV-Platform/docker.git
  commit:   44e1cc17e0ba4235b4a0120e9e0ce5893dfc3469

Copied unchanged. The build removes MinIO's host port 9000 mapping from both files.
Checksums: SHA256SUMS.compose
