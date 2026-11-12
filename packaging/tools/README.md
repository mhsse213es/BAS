# Offline build prerequisites (not committed; binaries are too large for git)

Fetch these on the build machine before a release build. Each file is checked against a SHA-256 pin:

- `docker/docker-*.tgz`, `docker/docker-compose-linux-*`: `packaging\fetch-docker-static.ps1`, pins in `packaging/docker-static.pin`.
- `cosign-linux-amd64`: `packaging/appliance/fetch-cosign.sh`, pin `COSIGN_SHA256_LINUX_AMD64` in `packaging/appliance/cosign.pin`.
- `cosign-linux-arm64`: no fetch script yet. Download `cosign-linux-arm64` for the version in `packaging/appliance/cosign.pin` from the sigstore release and check its SHA-256 against `COSIGN_SHA256_LINUX_ARM64`. The release build refuses a file that does not match.
