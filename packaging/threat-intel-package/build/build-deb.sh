#!/bin/bash
# build-deb.sh: builds "Threat Intelligence Package.deb", the offline installer
# for MISP, OpenCTI and OpenAEV.
#
# Run on a Linux host with Docker and dpkg-deb (Ubuntu 22.04/24.04 recommended).
# Needs internet access to pull images. Expect 30+ GB of disk and a long run.
#
#   sudo ./build-deb.sh [output-dir]
#
# Output: <output-dir>/Threat Intelligence Package.deb  (default: ./dist)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PKG_ROOT="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$PKG_ROOT/../.." && pwd)"
OUT_DIR="${1:-$PKG_ROOT/dist}"
VERSION="$(tr -d '[:space:]' < "$PKG_ROOT/VERSION")"
STAGE="$PKG_ROOT/build/stage"
DEB_NAME="Threat Intelligence Package.deb"

die()  { echo "build-deb: error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

# SKIP_IMAGES=1 builds the package layout without pulling images (dry run).
SKIP_IMAGES="${SKIP_IMAGES:-0}"
command -v dpkg-deb >/dev/null || die "dpkg-deb is required (apt install dpkg)"
if [ "$SKIP_IMAGES" != "1" ]; then
  command -v docker >/dev/null || die "docker is required"
  docker info >/dev/null 2>&1 || die "docker daemon is not reachable"
fi

[ -f "$PKG_ROOT/vendor/opencti/docker-compose.yml" ] || die "opencti compose not found in vendor/"
[ -f "$PKG_ROOT/vendor/openaev/docker-compose.yml" ] || die "openaev compose not found in vendor/"

rm -rf "$STAGE"
PAYLOAD="$STAGE/usr/share/threat-intelligence-package"
install -d "$STAGE/DEBIAN" "$STAGE/usr/bin" "$PAYLOAD/images" "$PAYLOAD/stacks/misp" \
           "$PAYLOAD/stacks/opencti" "$PAYLOAD/stacks/openaev" "$STAGE/usr/share/doc/threat-intelligence-package"

# ---- stacks -----------------------------------------------------------------
info "Staging compose stacks"
cp "$PKG_ROOT/vendor/misp-docker/docker-compose.yml" "$PAYLOAD/stacks/misp/docker-compose.yml"
cp "$PKG_ROOT/vendor/misp-docker/template.env" "$PAYLOAD/stacks/misp/template.env"

for s in opencti openaev; do
  src="$PKG_ROOT/vendor/$s/docker-compose.yml"
  dst="$PAYLOAD/stacks/$s/docker-compose.yml"
  # MinIO publishes host port 9000 in both vendor stacks. Both stacks cannot run
  # on one host while that mapping exists, so remove it. MinIO stays reachable
  # on the internal compose network.
  n=$(tr -d '\r' < "$src" | grep -c '"9000:9000"' || true)
  [ "$n" -eq 1 ] || die "expected exactly one 9000:9000 mapping in $src, found $n"
  # Also drop the 'ports:' key when the mapping was its only entry: an empty ports key is invalid.
  tr -d '\r' < "$src" | awk '
    BEGIN { held = "" }
    {
      if (held != "") {
        if ($0 ~ /^[[:space:]]*- "9000:9000"[[:space:]]*$/) { held = ""; next }
        print held; held = ""
      }
      if ($0 ~ /^[[:space:]]*ports:[[:space:]]*$/) { held = $0; next }
      print
    }
    END { if (held != "") print held }' > "$dst"
  cp "$PKG_ROOT/vendor/$s/rabbitmq.conf" "$PAYLOAD/stacks/$s/rabbitmq.conf"
done

MANIFEST="$PAYLOAD/MANIFEST.txt"
{
  echo "Threat Intelligence Package ${VERSION}"
  echo "Built: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Image digests (reference | digest | file):"
} > "$MANIFEST"

if [ "$SKIP_IMAGES" = "1" ]; then
  info "SKIP_IMAGES=1: dry run, no compose check and no images bundled"
  echo "(dry run: no images bundled)" >> "$MANIFEST"
else
  # Check the staged compose files parse with the variables the installer sets.
  # Placeholder values, so this checks syntax and references only.
  info "Checking compose syntax"
  CHECK_ENV="$STAGE/check.env"
  {
    for v in $(cat "$PAYLOAD"/stacks/*/docker-compose.yml | grep -o '\${[A-Z_][A-Z0-9_]*' | tr -d '${' | sort -u); do
      # Port variables must be numbers: compose rejects "x" as a host port.
      case "$v" in *PORT*) echo "$v=18080" ;; *) echo "$v=x" ;; esac
    done
  } > "$CHECK_ENV"
  for s in misp opencti openaev; do
    (cd "$PAYLOAD/stacks/$s" && docker compose --env-file "$CHECK_ENV" -f docker-compose.yml config >/dev/null) \
      || die "compose config failed for $s"
  done

  # ---- images ---------------------------------------------------------------
  info "Pulling and saving images"
  mapfile -t IMAGES < <(grep -v '^\s*#' "$HERE/images.list" | sed '/^\s*$/d' | sort -u)
  i=0
  for ref in "${IMAGES[@]}"; do
    i=$((i+1))
    file=$(printf 'img-%03d.tar.gz' "$i")
    info "[$i/${#IMAGES[@]}] $ref"
    docker pull --quiet "$ref" >/dev/null
    digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$ref" 2>/dev/null || echo "no-repo-digest")
    docker save "$ref" | gzip -6 > "$PAYLOAD/images/$file"
    echo "$ref | $digest | $file" >> "$MANIFEST"
  done
fi

# ---- control, scripts, docs -------------------------------------------------
cat > "$STAGE/DEBIAN/control" <<EOF
Package: threat-intelligence-package
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Audspect <admin@audspect.local>
Depends: docker.io | docker-ce, docker-compose-v2 | docker-compose-plugin, openssl, curl, iproute2, gzip, coreutils
Installed-Size: $(du -sk "$STAGE/usr" | cut -f1)
Description: Offline installer for MISP, OpenCTI and OpenAEV
 Installs all three threat-intelligence and exercise platforms from bundled
 images, with no internet access needed at install time. Requires only a host
 address and a base port. Generates every secret on the host, starts the
 stacks, and writes the admin logins and API keys to a root-only file.
 Run: sudo tip-install --host <ip> --port <base-port>
EOF

install -m 0755 "$PKG_ROOT/bin/tip-install" "$STAGE/usr/bin/tip-install"
install -m 0755 "$PKG_ROOT/bin/tip-show-credentials" "$STAGE/usr/bin/tip-show-credentials"
install -m 0644 "$PKG_ROOT/README.md" "$STAGE/usr/share/doc/threat-intelligence-package/README.md"
install -m 0644 "$PKG_ROOT/vendor/misp-docker/SHA256SUMS" "$PAYLOAD/stacks/misp/SHA256SUMS"

# ---- build the .deb ----------------------------------------------------------
install -d "$OUT_DIR"
info "Building $OUT_DIR/$DEB_NAME"
dpkg-deb --root-owner-group -Zgzip --build "$STAGE" "$OUT_DIR/$DEB_NAME"
rm -f "$STAGE/check.env"
info "Done: $OUT_DIR/$DEB_NAME ($(du -h "$OUT_DIR/$DEB_NAME" | cut -f1))"
