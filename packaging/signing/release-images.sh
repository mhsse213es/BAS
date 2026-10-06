#!/usr/bin/env bash
# Shared by packaging/build.sh and packaging/airgap/pack.sh (sourced; needs log()
# and err() from the caller). Builds/pulls the pinned runtime images that compose
# starts with no profile, saves each as an UNCOMPRESSED tar and cosign-signs it
# with the same helper and key as the orchestrator. Every step is fatal: there is
# no warn-and-continue, because a bundle missing any runtime image cannot start.
#
# Runtime image set: orchestrator, postgres, bas-caldera, chromedp/headless-shell.
# (golang is build/dev-only -- compose profile "audit" -- and is never shipped.)

# rel_sign_tar <tar> <cosign.sh>: sign, then verify what was just produced.
rel_sign_tar() {
  local tar="$1" cs="$2"
  bash "$cs" --sign "$tar"   || { err "cosign signing failed for ${tar} -- aborting."; exit 1; }
  bash "$cs" --verify "$tar" || { err "cosign verification FAILED immediately after signing ${tar} -- investigate before shipping."; exit 1; }
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

# rel_pull_chrome <repo root>: pull chromedp/headless-shell BY DIGEST (packaging/images.pin),
# confirm the digest, and tag it CHROME_VERSION (the tag compose runs). Sets CHROME_IMAGE.
rel_pull_chrome() {
  local root="$1" CHROME_VERSION="" CHROME_DIGEST=""
  # shellcheck disable=SC1090,SC1091
  source "${root}/packaging/images.pin"
  [[ -n "$CHROME_VERSION" && "$CHROME_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || { err "packaging/images.pin is missing a valid CHROME_VERSION/CHROME_DIGEST."; exit 1; }
  CHROME_IMAGE="chromedp/headless-shell:${CHROME_VERSION}"
  log "Pulling chromedp/headless-shell@${CHROME_DIGEST} (${CHROME_VERSION})..."
  docker pull "chromedp/headless-shell@${CHROME_DIGEST}" || { err "Failed to pull chromedp/headless-shell@${CHROME_DIGEST} -- aborting."; exit 1; }
  docker image inspect --format '{{json .RepoDigests}}' "chromedp/headless-shell@${CHROME_DIGEST}" 2>/dev/null | grep -q "${CHROME_DIGEST}" \
    || { err "Pulled chrome image does not carry the pinned digest ${CHROME_DIGEST} -- aborting."; exit 1; }
  docker tag "chromedp/headless-shell@${CHROME_DIGEST}" "$CHROME_IMAGE" || { err "docker tag ${CHROME_IMAGE} failed -- aborting."; exit 1; }
}

# rel_ship_caldera_chrome <version> <repo root> <images dir> <cosign.sh>
rel_ship_caldera_chrome() {
  local ver="$1" root="$2" dir="$3" cs="$4"
  rel_build_caldera "$ver" "$root"
  rel_save_sign "bas-caldera:${ver}" "${dir}/bas-caldera-${ver}.tar" "$cs"
  rel_pull_chrome "$root"
  rel_save_sign "$CHROME_IMAGE" "${dir}/headless-shell.tar" "$cs"
}
