#!/usr/bin/env bash
# Shared by packaging/build.sh and packaging/airgap/pack.sh (sourced; needs log()
# and err() from the caller). Builds/pulls the pinned runtime images that compose
# starts with no profile, saves each as an UNCOMPRESSED tar and cosign-signs it
# with the same helper and key as the orchestrator. Every step is fatal: there is
# no warn-and-continue, because a bundle missing any runtime image cannot start.
#
# Runtime image set: orchestrator, postgres, bas-caldera, chromedp/headless-shell
# (postgres and chrome pulled by the digests in packaging/images.pin).
# (golang is build/dev-only -- compose profile "audit" -- and is never shipped.)

# rel_sign_tar <tar> <cosign.sh>: sign, then verify what was just produced.
rel_sign_tar() {
  local tar="$1" cs="$2"
  bash "$cs" --sign "$tar"   || { err "cosign signing failed for ${tar} -- aborting."; exit 1; }
  bash "$cs" --verify "$tar" || { err "cosign verification FAILED immediately after signing ${tar} -- investigate before shipping."; exit 1; }
}

# rel_verify_all_images <images dir> <cosign.pub>: packaging-time gate, run on the
# final images/ just before the tarball. Every file must be a .tar with a
# non-empty .bundle (or that .bundle), and EVERY tar is re-verified with the exact
# verify-blob key/flags install.sh's _verify_all_images uses, against the
# cosign.pub that ships in the bundle. A corrupted .bundle or a tar modified
# after signing is fatal: it is never packaged.
rel_verify_all_images() {
  local dir="$1" pub="$2" tar n=0
  [[ -f "$pub" ]] || { err "cosign public key not found at ${pub} -- refusing to package."; exit 1; }
  for tar in "$dir"/*; do
    [[ -f "$tar" ]] || continue
    case "$tar" in
      *.tar.bundle) ;;
      *.tar)
        [[ -s "${tar}.bundle" ]] || { err "$(basename "$tar") has no cosign .bundle -- refusing to package."; exit 1; }
        cosign verify-blob --key "$pub" --bundle "${tar}.bundle" --insecure-ignore-tlog "$tar" \
          || { err "cosign verification FAILED for $(basename "$tar") at packaging time -- refusing to package."; exit 1; }
        n=$((n + 1)) ;;
      *) err "Unexpected file in images/: $(basename "$tar") -- refusing to package."; exit 1 ;;
    esac
  done
  [[ "$n" -gt 0 ]] || { err "No image tars in ${dir} -- refusing to package."; exit 1; }
  log "  Packaging gate: all ${n} image tar(s) re-verified with cosign verify-blob."
}

# rel_save_sign <image> <out.tar> <cosign.sh>
rel_save_sign() {
  local img="$1" tar="$2" cs="$3"
  docker save "$img" -o "$tar" || { err "docker save ${img} failed -- aborting."; exit 1; }
  log "  Saved: $(basename "$tar") ($(du -sh "$tar" | cut -f1))"
  rel_sign_tar "$tar" "$cs"
}

# rel_build_caldera <version> <repo root>: bas-caldera:<version> with the emu library baked in.
rel_build_caldera() {
  local ver="$1" root="$2"
  log "Building bas-caldera:${ver} (pinned base + emu library)..."
  docker build -t "bas-caldera:${ver}" "${root}/packaging/caldera" || { err "Failed to build bas-caldera:${ver} -- aborting."; exit 1; }
}

# rel_read_pin <images.pin>: PARSE (never source) the pin file. Accepts only
# comments, blank lines and KEY=value lines for the known keys, each exactly
# once; an unknown or duplicate key, a malformed line/value or any CR (CRLF
# checkout) is fatal. Sets CHROME_VERSION CHROME_DIGEST POSTGRES_TAG POSTGRES_DIGEST.
rel_read_pin() {
  local file="$1" line key val n=0 seen=" "
  CHROME_VERSION=""; CHROME_DIGEST=""; POSTGRES_TAG=""; POSTGRES_DIGEST=""
  [[ -f "$file" ]] || { err "${file} not found -- aborting."; exit 1; }
  if grep -q $'\r' "$file"; then err "${file} contains CR characters (CRLF checkout?) -- aborting."; exit 1; fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n + 1))
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" =~ ^([A-Z_]+)=([^[:space:]]+)$ ]] || { err "${file}:${n}: malformed line (expected KEY=value) -- aborting."; exit 1; }
    key="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
    case "$key" in
      CHROME_VERSION)  [[ "$val" =~ ^[0-9]+(\.[0-9]+)+$ ]] ;;
      CHROME_DIGEST|POSTGRES_DIGEST) [[ "$val" =~ ^sha256:[0-9a-f]{64}$ ]] ;;
      POSTGRES_TAG)    [[ "$val" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ;;
      *) err "${file}:${n}: unknown key ${key} -- aborting."; exit 1 ;;
    esac || { err "${file}:${n}: invalid value for ${key} -- aborting."; exit 1; }
    [[ "$seen" == *" ${key} "* ]] && { err "${file}:${n}: duplicate key ${key} -- aborting."; exit 1; }
    seen="${seen}${key} "
    printf -v "$key" '%s' "$val"
  done < "$file"
  for key in CHROME_VERSION CHROME_DIGEST POSTGRES_TAG POSTGRES_DIGEST; do
    [[ -n "${!key}" ]] || { err "${file}: missing ${key} -- aborting."; exit 1; }
  done
}

# rel_pull_pinned <repo> <tag> <digest>: pull <repo>@<digest>, confirm the
# pulled image carries that digest, then tag it <repo>:<tag> (the tag compose runs).
rel_pull_pinned() {
  local repo="$1" tag="$2" digest="$3"
  log "Pulling ${repo}@${digest} (${tag})..."
  docker pull "${repo}@${digest}" || { err "Failed to pull ${repo}@${digest} -- aborting."; exit 1; }
  docker image inspect --format '{{json .RepoDigests}}' "${repo}@${digest}" 2>/dev/null | grep -q "${digest}"     || { err "Pulled ${repo} image does not carry the pinned digest ${digest} -- aborting."; exit 1; }
  docker tag "${repo}@${digest}" "${repo}:${tag}" || { err "docker tag ${repo}:${tag} failed -- aborting."; exit 1; }
}

# rel_pull_chrome <repo root>: chromedp/headless-shell BY DIGEST (packaging/images.pin),
# tagged CHROME_VERSION. Sets CHROME_IMAGE.
rel_pull_chrome() {
  rel_read_pin "$1/packaging/images.pin"
  CHROME_IMAGE="chromedp/headless-shell:${CHROME_VERSION}"
  rel_pull_pinned chromedp/headless-shell "$CHROME_VERSION" "$CHROME_DIGEST"
}

# rel_ship_postgres <repo root> <images dir> <cosign.sh>: postgres BY DIGEST
# (packaging/images.pin), tagged postgres:POSTGRES_TAG, saved + signed.
rel_ship_postgres() {
  local root="$1" dir="$2" cs="$3"
  rel_read_pin "${root}/packaging/images.pin"
  [[ "$POSTGRES_TAG" == "16-alpine" ]] || { err "POSTGRES_TAG=${POSTGRES_TAG}: the installers expect postgres:16-alpine (postgres-16-alpine.tar) -- update them together. Aborting."; exit 1; }
  rel_pull_pinned postgres "$POSTGRES_TAG" "$POSTGRES_DIGEST"
  rel_save_sign "postgres:${POSTGRES_TAG}" "${dir}/postgres-${POSTGRES_TAG}.tar" "$cs"
}

# rel_ship_caldera_chrome <version> <repo root> <images dir> <cosign.sh>
rel_ship_caldera_chrome() {
  local ver="$1" root="$2" dir="$3" cs="$4"
  rel_build_caldera "$ver" "$root"
  rel_save_sign "bas-caldera:${ver}" "${dir}/bas-caldera-${ver}.tar" "$cs"
  rel_pull_chrome "$root"
  rel_save_sign "$CHROME_IMAGE" "${dir}/headless-shell.tar" "$cs"
}
